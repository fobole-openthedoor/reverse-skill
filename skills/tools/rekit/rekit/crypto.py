"""crypto: entropy mapping and repeating-key XOR recovery for firmware triage."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

import numpy as np
from numpy.lib.stride_tricks import sliding_window_view

DEFAULT_WINDOW = 4096
DEFAULT_STEP = 1024
DEFAULT_THRESHOLD = 7.2
KEYLEN_MIN = 1
KEYLEN_MAX = 40
MAX_GUESS_BLOCKS = 12
CRIB_SLIDE_MAX = 1 << 20
TOP_K = 5


class CryptoError(Exception):
    pass


def _printable_mask(arr: np.ndarray) -> np.ndarray:
    return (arr == 0x09) | (arr == 0x0A) | (arr == 0x0D) | ((arr >= 0x20) & (arr <= 0x7E))


def _printable_ratio(arr: np.ndarray) -> float:
    return float(_printable_mask(arr).mean()) if arr.size else 0.0


def _ioc(arr: np.ndarray) -> float:
    if arr.size == 0:
        return 0.0
    p = np.bincount(arr, minlength=256).astype(np.float64) / arr.size
    return float((p * p).sum())


def _xor_crypt(arr: np.ndarray, key: bytes) -> np.ndarray:
    k = np.frombuffer(key, dtype=np.uint8)
    reps = (arr.size + k.size - 1) // k.size
    return arr ^ np.tile(k, reps)[: arr.size]


def _shannon(arr: np.ndarray) -> float:
    if arr.size == 0:
        return 0.0
    counts = np.bincount(arr, minlength=256).astype(np.float64)
    p = counts[counts > 0] / arr.size
    return float(-(p * np.log2(p)).sum())


def entropy_regions(
    data: bytes, window: int = DEFAULT_WINDOW, step: int = DEFAULT_STEP, threshold: float = DEFAULT_THRESHOLD
) -> tuple[list[tuple[int, int, float]], float]:
    arr = np.frombuffer(data, dtype=np.uint8)
    n = arr.size
    mean_h = _shannon(arr)
    if n == 0:
        return [], mean_h
    if n < window:
        window = n
    marked: list[tuple[int, int, float]] = []
    stops = list(range(0, n - window + 1, step))
    if stops[-1] + window < n:
        stops.append(n - window)
    for pos in stops:
        h = _shannon(arr[pos : pos + window])
        if h >= threshold:
            marked.append((pos, pos + window, h))
    regions: list[tuple[int, int, float]] = []
    for s, e, h in marked:
        if regions and s <= regions[-1][1]:
            ps, pe, ph = regions[-1]
            regions[-1] = (ps, max(pe, e), max(ph, h))
        else:
            regions.append((s, e, h))
    return regions, mean_h


def guess_keylen(data: bytes, kmin: int = KEYLEN_MIN, kmax: int = KEYLEN_MAX) -> list[tuple[int, float]]:
    arr = np.frombuffer(data, dtype=np.uint8)
    out: list[tuple[int, float]] = []
    for keylen in range(max(1, kmin), max(1, kmax) + 1):
        nblocks = min(MAX_GUESS_BLOCKS, arr.size // keylen)
        if nblocks < 2:
            continue
        bits = np.unpackbits(arr[: nblocks * keylen].reshape(nblocks, keylen), axis=1)
        total = 0.0
        pairs = 0
        for i in range(nblocks - 1):
            d = np.count_nonzero(bits[i] != bits[i + 1 :], axis=1)
            total += float(d.sum())
            pairs += int(d.size)
        out.append((keylen, total / pairs / keylen))
    out.sort(key=lambda t: t[1])
    return out


def _min_period(key: bytes) -> bytes:
    for p in range(1, len(key) + 1):
        if len(key) % p == 0 and key == key[:p] * (len(key) // p):
            return key[:p]
    return key


def column_key_attack(data: bytes, keylen: int) -> tuple[bytes, float]:
    arr = np.frombuffer(data, dtype=np.uint8)
    if arr.size == 0 or keylen < 1:
        return b"", 0.0
    cands = np.arange(256, dtype=np.uint8)
    key = bytearray()
    for c in range(keylen):
        col = arr[c::keylen]
        scores = np.zeros(256, dtype=np.float64)
        for s in range(0, col.size, 65536):
            dec = col[s : s + 65536, None] ^ cands[None, :]
            good = _printable_mask(dec)
            zero = dec == 0
            scores += good.sum(axis=0) + 0.8 * zero.sum(axis=0) - np.logical_not(good | zero).sum(axis=0)
        key.append(int(np.argmax(scores)))
    key_b = bytes(key)
    return key_b, _printable_ratio(_xor_crypt(arr, key_b))


def crib_attack(
    data: bytes,
    crib: bytes,
    offset: int | None = None,
    kmin: int = KEYLEN_MIN,
    kmax: int = KEYLEN_MAX,
) -> list[tuple[int, int, bytes, float]]:
    arr = np.frombuffer(data, dtype=np.uint8)
    c = np.frombuffer(crib, dtype=np.uint8)
    if c.size == 0:
        raise CryptoError("empty crib")
    if c.size > arr.size:
        raise CryptoError(f"crib ({c.size} bytes) longer than region ({arr.size} bytes)")
    results: list[tuple[int, int, bytes, float]] = []
    if offset is not None:
        if offset < 0 or offset >= arr.size:
            raise CryptoError(f"crib offset {offset:#x} out of region ({arr.size} bytes)")
        for keylen in range(max(1, kmin), min(kmax, c.size) + 1):
            key = bytes((arr[offset : offset + keylen] ^ c[:keylen]).tolist())
            results.append((offset, keylen, key, _ioc(_xor_crypt(arr, key))))
    else:
        limit = min(arr.size, CRIB_SLIDE_MAX)
        kmin_e = max(1, kmin)
        kmax_e = min(kmax, c.size)
        n_kl = kmax_e - kmin_e + 1
        n_pos = limit - c.size + 1
        s_len = max(1024, min(arr.size, 4096, (1 << 33) // max(1, n_pos * n_kl)))
        score_view = arr[:s_len]
        prelim: list[tuple[int, int, bytes, float]] = []
        for keylen in range(kmin_e, kmax_e + 1):
            win = sliding_window_view(arr[:limit], keylen)
            keys = win[:n_pos] ^ c[:keylen]
            reps = (score_view.size + keylen - 1) // keylen
            step = max(1, (1 << 22) // max(1, reps * keylen))
            scores_all = np.empty(n_pos, dtype=np.float64)
            for p0 in range(0, n_pos, step):
                kchunk = keys[p0 : p0 + step]
                rows = kchunk.shape[0]
                tiled = np.tile(kchunk, (1, reps))[:, : score_view.size]
                dec = tiled ^ score_view[None, :]
                flat = dec.astype(np.uint32)
                flat += (np.arange(rows, dtype=np.uint32) * 256)[:, None]
                counts = np.bincount(flat.ravel(), minlength=rows * 256).reshape(rows, 256)
                scores_all[p0 : p0 + rows] = ((counts / score_view.size) ** 2).sum(axis=1)
            take = min(TOP_K, n_pos)
            idx = np.argpartition(-scores_all, take - 1)[:take]
            for i in idx[np.argsort(-scores_all[idx])]:
                prelim.append((int(i), keylen, bytes(keys[i].tolist()), float(scores_all[i])))
        prelim.sort(key=lambda t: -t[3])
        for pos, keylen, key, _r in prelim[:TOP_K]:
            results.append((pos, keylen, key, _ioc(_xor_crypt(arr, key))))
    results.sort(key=lambda t: -t[3])
    return results[:TOP_K]


def _va(text: str) -> int:
    try:
        return int(text, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid number: {text!r}") from None


def _read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _region(args: argparse.Namespace, data: bytes) -> bytes:
    offset = args.offset
    if offset < 0 or offset >= len(data):
        raise CryptoError(f"offset {offset:#x} out of file ({len(data)} bytes)")
    size = args.size if args.size is not None else len(data) - offset
    if size <= 0:
        raise CryptoError(f"invalid size {size}")
    return data[offset : offset + size]


def _preview(dec: bytes, limit: int = 64) -> str:
    return "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in dec[:limit])


def _check_keylen_bounds(args: argparse.Namespace) -> None:
    if args.keylen_min < 1 or args.keylen_max < args.keylen_min:
        raise CryptoError(f"bad keylen range {args.keylen_min}..{args.keylen_max}")


def _emit_result(args: argparse.Namespace, result: dict) -> None:
    human = result.pop("_human", [])
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for line in human:
            print(line)


def _cmd_entropy(args: argparse.Namespace) -> int:
    data = _read_file(args.file)
    regions, mean_h = entropy_regions(data, args.window, args.step, args.threshold)
    result = {
        "file": args.file,
        "size": len(data),
        "window": args.window,
        "step": args.step,
        "threshold": args.threshold,
        "mean_entropy": round(mean_h, 4),
        "regions": [{"start": s, "end": e, "peak": round(p, 4)} for s, e, p in regions],
        "_human": [
            f"file: {args.file} ({len(data)} bytes)",
            f"mean entropy: {mean_h:.4f} bits/byte",
            f"regions >= {args.threshold} (window={args.window} step={args.step}): {len(regions)}",
        ]
        + [f"  {s:#010x}-{e:#010x}  peak {p:.4f}  ({e - s} bytes)" for s, e, p in regions],
    }
    _emit_result(args, result)
    return 0


def _crib_from_args(args: argparse.Namespace) -> bytes | None:
    if args.magic is not None:
        try:
            return bytes.fromhex(args.magic)
        except ValueError:
            raise CryptoError(f"bad --magic hex: {args.magic!r}") from None
    if args.magic_str is not None:
        return args.magic_str.encode("utf-8")
    if args.crib is not None:
        return args.crib.encode("utf-8")
    return None


def _write_out(out_path: str, region: bytes, key: bytes) -> str:
    dec = _xor_crypt(np.frombuffer(region, dtype=np.uint8), key).tobytes()
    with open(out_path, "wb") as f:
        f.write(dec)
    return hashlib.sha256(dec).hexdigest()


def _cmd_xor(args: argparse.Namespace) -> int:
    data = _read_file(args.file)
    region = _region(args, data)
    _check_keylen_bounds(args)
    crib = _crib_from_args(args)
    base = {
        "file": args.file,
        "region": {"offset": args.offset, "size": len(region)},
        "keylen_range": [args.keylen_min, args.keylen_max],
    }
    if crib is not None:
        hits = crib_attack(region, crib, None, args.keylen_min, args.keylen_max)
        arr_region = np.frombuffer(region, dtype=np.uint8)
        candidates = [
            {
                "offset": pos,
                "keylen": klen,
                "key_hex": key.hex(),
                "ioc": round(score, 4),
                "printable_ratio": round(_printable_ratio(_xor_crypt(arr_region, key)), 4),
            }
            for pos, klen, key, score in hits
        ]
        best_key = hits[0][2] if hits else None
        result = dict(base)
        result["mode"] = "crib"
        result["crib_len"] = len(crib)
        result["candidates"] = candidates
        result["_human"] = [f"crib mode: {len(crib)}-byte crib over {len(region)}-byte region"] + [
            f"  #{i} offset={c['offset']:#x} keylen={c['keylen']} ioc={c['ioc']:.4f} key={c['key_hex']}"
            for i, c in enumerate(candidates, 1)
        ]
    else:
        keylens = guess_keylen(region, args.keylen_min, args.keylen_max)[:3]
        ranked = []
        seen_keys: set[bytes] = set()
        for keylen, dist in keylens:
            key, ratio = column_key_attack(region, keylen)
            key = _min_period(key)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            dec = _xor_crypt(np.frombuffer(region, dtype=np.uint8), key).tobytes()
            ranked.append((len(key), dist, key, ratio, _preview(dec)))
        ranked.sort(key=lambda t: -t[3])
        candidates = [
            {
                "keylen": klen,
                "hamming": round(dist, 4),
                "key_hex": key.hex(),
                "printable_ratio": round(ratio, 4),
                "preview": preview,
            }
            for klen, dist, key, ratio, preview in ranked
        ]
        best_key = ranked[0][2] if ranked else None
        result = dict(base)
        result["mode"] = "auto"
        result["keylens"] = [[klen, round(dist, 4)] for klen, dist in keylens]
        result["candidates"] = candidates
        result["_human"] = [
            f"region: {args.offset:#x}..{args.offset + len(region):#x} ({len(region)} bytes)",
            "keylen candidates: " + ", ".join(f"{klen} ({dist:.2f})" for klen, dist in keylens),
        ] + [
            f"  #{i} keylen={c['keylen']} score={c['printable_ratio']:.4f} key={c['key_hex']}\n      {c['preview']}"
            for i, c in enumerate(candidates, 1)
        ]
    if args.out:
        if best_key is None:
            raise CryptoError("no key candidate; nothing to write")
        digest = _write_out(args.out, region, best_key)
        result["out"] = {"path": args.out, "sha256": digest}
        result["_human"].append(f"wrote {args.out} (sha256 {digest})")
    _emit_result(args, result)
    return 0


def _dispatch(args: argparse.Namespace) -> int:
    try:
        return args.handler(args)
    except CryptoError as e:
        print(f"rekit: error: {e}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 3


def _add_subcommands(parser: argparse.ArgumentParser) -> None:
    parser.set_defaults(func=_dispatch)
    sub = parser.add_subparsers(dest="crypto_command", metavar="<command>", required=True)

    p = sub.add_parser("entropy", help="sliding-window Shannon entropy map")
    p.add_argument("file")
    p.add_argument("--window", type=_va, default=DEFAULT_WINDOW)
    p.add_argument("--step", type=_va, default=DEFAULT_STEP)
    p.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    p.add_argument("--json", action="store_true")
    p.set_defaults(handler=_cmd_entropy)

    p = sub.add_parser("xor", help="repeating-key XOR recovery (keylen guess / column attack / crib)")
    p.add_argument("file")
    p.add_argument("--offset", type=_va, default=0)
    p.add_argument("--size", type=_va, default=None)
    p.add_argument("--keylen-min", type=int, default=KEYLEN_MIN)
    p.add_argument("--keylen-max", type=int, default=KEYLEN_MAX)
    g = p.add_mutually_exclusive_group()
    g.add_argument("--magic", default=None, help="known plaintext as hex")
    g.add_argument("--magic-str", default=None, help="known plaintext as string")
    g.add_argument("--crib", default=None, help="known plaintext fragment as string")
    p.add_argument("--out", default=None, help="write decrypted region to PATH")
    p.add_argument("--json", action="store_true")
    p.set_defaults(handler=_cmd_xor)


def register(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("crypto", help="crypto mini-suite (entropy map, XOR key recovery)")
    _add_subcommands(parser)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rekit crypto", description=__doc__)
    _add_subcommands(parser)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
