from __future__ import annotations

import hashlib
import json
import os
import sys
from bisect import bisect_left, bisect_right

import lief
import lief.ELF as LE
import numpy as np
from numpy.lib.stride_tricks import as_strided, sliding_window_view

from .disasmx import linear_disasm

CACHE_VERSION = 1
FUNC_SIZE_CAP = 0x10000
MIN_STRING_LEN = 4
_SHF_EXECINSTR = LE.Section.FLAGS.EXECINSTR.value


class RekitError(Exception):
    pass


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _arch_bits(b: LE.Binary) -> tuple[str, int]:
    mt = b.header.machine_type
    bits = 64 if b.header.identity_class == LE.Header.CLASS.ELF64 else 32
    if mt == LE.ARCH.X86_64:
        return "x86-64", 64
    if mt == LE.ARCH.AARCH64:
        return "arm64", 64
    if mt == LE.ARCH.ARM:
        return "arm32", 32
    return "unknown", bits


def _image_base(b: LE.Binary) -> int:
    try:
        return int(b.imagebase)
    except Exception:
        vas = [s.virtual_address for s in b.segments if s.type == LE.Segment.TYPE.LOAD]
        return min(vas) if vas else 0


def _load_map(b: LE.Binary) -> list[tuple[int, int, int]]:
    out = []
    for s in b.segments:
        if s.type == LE.Segment.TYPE.LOAD and s.physical_size > 0:
            va = int(s.virtual_address)
            out.append((va, va + int(s.physical_size), int(s.file_offset)))
    return out


def _exec_ranges(b: LE.Binary) -> list[tuple[int, int]]:
    return [
        (int(s.virtual_address), int(s.virtual_address) + int(s.size))
        for s in b.sections
        if s.flags & _SHF_EXECINSTR and s.size > 0
    ]


def _text_sections(b: LE.Binary) -> list[LE.Section]:
    secs = [s for s in b.sections if s.name == ".text"]
    if not secs:
        secs = [s for s in b.sections if s.flags & _SHF_EXECINSTR and s.size > 0]
    return secs


def _scan_ascii_runs(buf: np.ndarray, base_va: int, out: dict[int, str]) -> None:
    if buf.size == 0:
        return
    mask = (buf >= 0x20) & (buf <= 0x7E)
    ext = np.zeros(buf.size + 2, dtype=np.int8)
    ext[1:-1] = mask
    d = np.diff(ext)
    starts = np.flatnonzero(d == 1)
    ends = np.flatnonzero(d == -1)
    keep = (ends - starts) >= MIN_STRING_LEN
    for s, e in zip(starts[keep].tolist(), ends[keep].tolist()):
        out[base_va + s] = bytes(buf[s:e]).decode("ascii")


def _seg_readable_nonexec(seg: LE.Segment) -> bool:
    try:
        return bool(seg.has(LE.Segment.FLAGS.R)) and not bool(seg.has(LE.Segment.FLAGS.X))
    except Exception:
        fl = int(getattr(seg, "raw_flags", 0))
        return bool(fl & 0x4) and not bool(fl & 0x1)


def _extract_strings(b: LE.Binary) -> dict[int, str]:
    out: dict[int, str] = {}
    rodatas = [s for s in b.sections if s.name == ".rodata" or s.name.startswith(".rodata.")]
    if rodatas:
        for sec in rodatas:
            _scan_ascii_runs(np.frombuffer(bytes(sec.content), dtype=np.uint8), int(sec.virtual_address), out)
    else:
        for seg in b.segments:
            if seg.type == LE.Segment.TYPE.LOAD and seg.physical_size > 0 and _seg_readable_nonexec(seg):
                _scan_ascii_runs(np.frombuffer(bytes(seg.content), dtype=np.uint8), int(seg.virtual_address), out)
    return out


def _got_map(b: LE.Binary) -> dict[int, str]:
    got: dict[int, str] = {}
    for r in b.pltgot_relocations:
        if r.has_symbol and r.symbol.name:
            got[int(r.address)] = r.symbol.name
    return got


def _plt_stubs_x64(b: LE.Binary, got: dict[int, str]) -> dict[str, int]:
    plt: dict[str, int] = {}
    for sec in b.sections:
        if not sec.name.startswith(".plt"):
            continue
        data = bytes(sec.content)
        arr = np.frombuffer(data, dtype=np.uint8)
        if arr.size < 6:
            continue
        va = int(sec.virtual_address)
        hits = np.flatnonzero((arr[:-1] == 0xFF) & (arr[1:] == 0x25))
        for pos in hits.tolist():
            if pos + 6 > arr.size:
                continue
            disp = int.from_bytes(data[pos + 2 : pos + 6], "little", signed=True)
            name = got.get(va + pos + 6 + disp)
            if name:
                plt[name] = va + (pos & ~0xF)
    return plt


def _plt_stubs_arm64(b: LE.Binary, got: dict[int, str]) -> dict[str, int]:
    plt: dict[str, int] = {}
    for sec in b.sections:
        if not sec.name.startswith(".plt"):
            continue
        data = bytes(sec.content)
        n = len(data) // 4
        if n < 3:
            continue
        w = np.frombuffer(data[: n * 4], dtype="<u4")
        va = int(sec.virtual_address)
        is_adrp16 = ((w & 0x9F000000) == 0x90000000) & ((w & 31) == 16)
        is_ldr = (w & 0xFFC00000) == 0xF9400000
        is_br17 = w == 0xD61F0220
        for i in range(n - 2):
            if not (is_adrp16[i] and is_ldr[i + 1] and is_br17[i + 2]):
                continue
            wl = int(w[i + 1])
            if ((wl >> 5) & 31) != 16 or (wl & 31) != 17:
                continue
            wa = int(w[i])
            imm = ((wa >> 3) & 0x1FFFFC) | ((wa >> 29) & 3)
            if imm & (1 << 20):
                imm -= 1 << 21
            pc = va + 4 * i
            got_va = (pc & ~0xFFF) + (imm << 12) + ((wl >> 10) & 0xFFF) * 8
            name = got.get(got_va)
            if name:
                plt[name] = pc
    return plt


def _pattern_hits(arr: np.ndarray, pat: bytes) -> np.ndarray:
    if arr.size < len(pat):
        return np.empty(0, dtype=np.int64)
    win = sliding_window_view(arr, len(pat))
    return np.flatnonzero((win == np.frombuffer(pat, dtype=np.uint8)).all(axis=1))


def _func_starts(b: LE.Binary, arch: str, plt: dict[str, int]) -> tuple[list[int], dict[int, str]]:
    starts: set[int] = set()
    names: dict[int, str] = {}
    for sym in b.dynamic_symbols:
        if sym.value and sym.type == LE.Symbol.TYPE.FUNC:
            starts.add(int(sym.value))
            if sym.name:
                names[int(sym.value)] = sym.name
    for sym in b.exported_symbols:
        if sym.value:
            starts.add(int(sym.value))
            if sym.name:
                names.setdefault(int(sym.value), sym.name)
    for sym in b.symtab_symbols:
        if sym.value and sym.type == LE.Symbol.TYPE.FUNC:
            starts.add(int(sym.value))
            if sym.name:
                names[int(sym.value)] = sym.name
    for name, va in plt.items():
        starts.add(va)
        names[va] = name
    if arch == "x86-64":
        for sec in _text_sections(b):
            arr = np.frombuffer(bytes(sec.content), dtype=np.uint8)
            va = int(sec.virtual_address)
            for pat in (b"\xf3\x0f\x1e\xfa", b"\x55\x48\x89\xe5"):
                for off in _pattern_hits(arr, pat).tolist():
                    starts.add(va + off)
    starts.discard(0)
    return sorted(starts), names


def _exports(b: LE.Binary) -> dict[str, int]:
    out: dict[str, int] = {}
    for sym in b.dynamic_symbols:
        if sym.name and sym.exported and sym.value:
            out[sym.name] = int(sym.value)
    return out


def _call_sites_x64(arr: np.ndarray, va: int) -> tuple[np.ndarray, np.ndarray]:
    if arr.size < 5:
        return np.empty(0, dtype=np.int64), np.empty(0, dtype=np.int64)
    win = sliding_window_view(arr, 5)
    pos = np.flatnonzero(win[:, 0] == 0xE8)
    disp = win[pos][:, 1:].copy().view("<i4").ravel().astype(np.int64)
    sites = va + pos
    return sites, sites + 5 + disp


def _call_sites_arm64(arr: np.ndarray, va: int) -> tuple[np.ndarray, np.ndarray]:
    n = arr.size // 4
    if n == 0:
        return np.empty(0, dtype=np.int64), np.empty(0, dtype=np.int64)
    w = arr[: n * 4].view("<u4")
    pos = np.flatnonzero((w & 0xFC000000) == 0x94000000)
    imm = (w[pos] & 0x03FFFFFF).astype(np.int64)
    imm = np.where(imm & 0x02000000, imm - (1 << 26), imm)
    sites = va + 4 * pos
    return sites, sites + (imm << 2)


def _call_edges(b: LE.Binary, arch: str, func_starts: list[int], valid: set[int]) -> list[tuple[int, int, int]]:
    fs = np.asarray(func_starts, dtype=np.int64)
    vv = np.asarray(sorted(valid), dtype=np.int64)
    edges: list[tuple[int, int, int]] = []
    if fs.size == 0 or vv.size == 0:
        return edges
    for sec in _text_sections(b):
        arr = np.frombuffer(bytes(sec.content), dtype=np.uint8)
        va = int(sec.virtual_address)
        if arch == "x86-64":
            sites, targets = _call_sites_x64(arr, va)
        elif arch == "arm64":
            sites, targets = _call_sites_arm64(arr, va)
        else:
            continue
        if sites.size == 0:
            continue
        idx = np.searchsorted(vv, targets)
        hit = np.flatnonzero((idx < vv.size) & (vv[np.minimum(idx, vv.size - 1)] == targets))
        sites, targets = sites[hit], targets[hit]
        ci = np.searchsorted(fs, sites, side="right") - 1
        keep = ci >= 0
        callers = fs[ci[keep]]
        edges.extend(zip(callers.tolist(), targets[keep].tolist(), sites[keep].tolist()))
    return edges


def _string_xrefs(b: LE.Binary, arch: str, strings: dict[int, str]) -> list[tuple[int, int]]:
    if arch != "x86-64" or not strings:
        return []
    sva = np.asarray(sorted(strings), dtype=np.int64)
    out: list[tuple[int, int]] = []
    for sec in _text_sections(b):
        arr = np.frombuffer(bytes(sec.content), dtype=np.uint8)
        n = arr.size - 3
        if n <= 0:
            continue
        win = as_strided(arr, shape=(n, 4), strides=(arr.strides[0], arr.strides[0]))
        disp = win.copy().view("<i4").ravel().astype(np.int64)
        va = int(sec.virtual_address)
        cand = va + np.arange(n, dtype=np.int64) + 4 + disp
        idx = np.searchsorted(sva, cand)
        hits = np.flatnonzero((idx < sva.size) & (sva[np.minimum(idx, sva.size - 1)] == cand))
        out.extend(zip((va + hits).tolist(), sva[idx[hits]].tolist()))
    return out


def _extract(path: str, digest: str) -> dict:
    try:
        b = lief.parse(path)
    except Exception as e:
        raise RekitError(f"lief failed to parse {path}: {e}") from e
    if b is None or not isinstance(b, LE.Binary):
        raise RekitError(f"{path}: not an ELF binary")
    arch, bits = _arch_bits(b)
    got = _got_map(b)
    if arch == "x86-64":
        plt = _plt_stubs_x64(b, got)
    elif arch == "arm64":
        plt = _plt_stubs_arm64(b, got)
    else:
        plt = {}
    func_starts, names = _func_starts(b, arch, plt)
    exports = _exports(b)
    strings = _extract_strings(b)
    valid = set(func_starts) | set(plt.values()) | set(exports.values())
    call_edges = _call_edges(b, arch, func_starts, valid)
    string_xrefs = _string_xrefs(b, arch, strings)
    return {
        "version": CACHE_VERSION,
        "sha256": digest,
        "arch": arch,
        "bits": bits,
        "image_base": _image_base(b),
        "entry": int(b.entrypoint),
        "plt": plt,
        "exports": exports,
        "strings": {str(k): v for k, v in sorted(strings.items())},
        "func_starts": func_starts,
        "names": {str(k): v for k, v in names.items()},
        "call_edges": call_edges,
        "string_xrefs": string_xrefs,
        "load_map": _load_map(b),
        "exec_ranges": _exec_ranges(b),
    }


class BinaryContext:
    def __init__(self, path: str, data: dict) -> None:
        self.path = path
        self.sha256 = data["sha256"]
        self.key = self.sha256[:16]
        self.arch = data["arch"]
        self.bits = data["bits"]
        self.image_base = data["image_base"]
        self.entry = data["entry"]
        self.plt = {k: int(v) for k, v in data["plt"].items()}
        self.exports = {k: int(v) for k, v in data["exports"].items()}
        self.strings = {int(k): v for k, v in data["strings"].items()}
        self.func_starts = [int(v) for v in data["func_starts"]]
        self.call_edges = [tuple(int(x) for x in e) for e in data["call_edges"]]
        self.string_xrefs = [tuple(int(x) for x in e) for e in data["string_xrefs"]]
        self.names = {int(k): v for k, v in data.get("names", {}).items()}
        self._load_map = [tuple(int(x) for x in s) for s in data["load_map"]]
        self._exec_ranges = [tuple(int(x) for x in s) for s in data["exec_ranges"]]
        with open(path, "rb") as f:
            self._blob = f.read()
        self._plt_by_va = {v: k for k, v in self.plt.items()}
        by_caller: dict[int, list[tuple[int, int]]] = {}
        by_target: dict[int, list[int]] = {}
        for caller, target, _site in self.call_edges:
            by_caller.setdefault(caller, []).append((target, _site))
            by_target.setdefault(target, []).append(caller)
        self._by_caller = by_caller
        self._by_target = by_target
        xs = sorted(self.string_xrefs)
        self._xs_sites = [s for s, _ in xs]
        self._xs_svas = [v for _, v in xs]

    @classmethod
    def load_or_build(cls, path: str) -> "BinaryContext":
        if not os.path.isfile(path):
            raise RekitError(f"{path}: no such file")
        path = os.path.abspath(path)
        digest = _sha256_file(path)
        home = os.environ.get("REKIT_HOME") or os.path.join(os.path.expanduser("~"), ".cache", "rekit")
        os.makedirs(home, exist_ok=True)
        key = digest[:16]
        cache_path = os.path.join(home, f"{key}_{os.path.basename(path)}.json")
        data = None
        try:
            with open(cache_path, encoding="utf-8") as f:
                cand = json.load(f)
            if cand.get("sha256") == digest and cand.get("version") == CACHE_VERSION:
                data = cand
        except (OSError, ValueError, KeyError):
            data = None
        if data is None:
            data = _extract(path, digest)
            tmp = cache_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, separators=(",", ":"))
            os.replace(tmp, cache_path)
            print(f"rekit: built {cache_path}", file=sys.stderr)
        else:
            print(f"rekit: loaded from cache {cache_path}", file=sys.stderr)
        return cls(path, data)

    def func_containing(self, va: int) -> int | None:
        i = bisect_right(self.func_starts, va) - 1
        return self.func_starts[i] if i >= 0 else None

    def funcs_calling(self, target: int) -> list[int]:
        return sorted(set(self._by_target.get(target, ())))

    def plt_name_at(self, va: int) -> str | None:
        return self._plt_by_va.get(va)

    def read_at_va(self, va: int, size: int) -> bytes:
        for vs, ve, off in self._load_map:
            if vs <= va < ve:
                fo = off + (va - vs)
                return self._blob[fo : fo + size]
        return b""

    def disasm(self, va: int, max_insns: int = 40) -> list[tuple[int, str, str]]:
        code = self.read_at_va(va, max_insns * 16)
        return linear_disasm(self.arch, code, va, max_insns)

    def func_strings(self, func_va: int) -> list[str]:
        end = func_va + self.func_size(func_va)
        lo = bisect_left(self._xs_sites, func_va)
        hi = bisect_left(self._xs_sites, end)
        out: list[str] = []
        seen: set[str] = set()
        for sva in self._xs_svas[lo:hi]:
            text = self.strings.get(sva)
            if text is not None and text not in seen:
                seen.add(text)
                out.append(text)
        return out

    def func_plt_calls(self, func_va: int) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for target, _site in self._by_caller.get(func_va, ()):
            name = self._plt_by_va.get(target)
            if name is not None and name not in seen:
                seen.add(name)
                out.append(name)
        return out

    def func_size(self, func_va: int) -> int:
        i = bisect_right(self.func_starts, func_va)
        if i < len(self.func_starts):
            return min(self.func_starts[i] - func_va, FUNC_SIZE_CAP)
        for s, e in self._exec_ranges:
            if s <= func_va < e:
                return min(e - func_va, FUNC_SIZE_CAP)
        return FUNC_SIZE_CAP

    def func_indegree(self, func_va: int) -> int:
        return len(set(self._by_target.get(func_va, ())))
