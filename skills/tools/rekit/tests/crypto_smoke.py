from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

KEY = b"s3cretK3y!42"
A_LEN, B_LEN, C_LEN = 2048, 8192, 1024
WINDOW = 4096
SIGNAL = b"X7q!Zk2#vW9p"


def _english(text: str, n: int) -> bytes:
    return ((text + " ") * (n // len(text) + 2)).encode()[:n]


def make_blob(seed: int = 0xC0FFEE) -> tuple[bytes, bytes]:
    rng = np.random.RandomState(seed)
    struct = b"\x7fELF\x02\x01\x01\x00" + bytes(range(16)) + b"\x00" * 8
    signal = SIGNAL * 8
    nl_len = 250
    rh_frac = 0.35
    body_len = 1024 - len(struct) - len(signal) - nl_len
    out = bytearray()
    while len(out) < B_LEN:
        out += struct + signal
        nl = rng.choice(
            np.array([0x0A, 0x09, 0x0D], dtype=np.uint8),
            size=min(nl_len, B_LEN - len(out)),
            p=[0.7, 0.15, 0.15],
        )
        out += nl.tobytes()
        need = min(B_LEN - len(out), body_len)
        nrh = int(need * rh_frac)
        body = np.concatenate(
            [
                rng.randint(0x20, 0x7F, size=need - nrh).astype(np.uint8),
                (0x80 + rng.randint(0, 128, size=nrh)).astype(np.uint8),
            ]
        )
        rng.shuffle(body)
        out += body.tobytes()
    plain = bytes(out[:B_LEN])
    k = np.frombuffer(KEY, dtype=np.uint8)
    arr = np.frombuffer(plain, dtype=np.uint8)
    cipher = (arr ^ np.tile(k, arr.size // 12 + 1)[: arr.size]).tobytes()
    a = _english(
        "the quick brown fox jumps over the lazy dog while the firmware loader verifies the image header and reports status to the console",
        A_LEN,
    )
    c = _english(
        "startup complete; entering main loop and waiting for interrupts from the timer subsystem", C_LEN
    )
    return a + cipher + c, plain


def rotation_equiv(a: bytes, b: bytes) -> bool:
    return len(a) == len(b) and any(a[i:] + a[:i] == b for i in range(len(a)))


def run(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "rekit", *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="rekit-crypto-")
    try:
        env = dict(os.environ)
        env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")
        blob, plain_b = make_blob()
        blob_path = os.path.join(tmp, "blob.bin")
        with open(blob_path, "wb") as f:
            f.write(blob)
        b_off, b_len = A_LEN, B_LEN

        p = run(["crypto", "entropy", blob_path, "--json"], env)
        check(p.returncode == 0, f"entropy rc={p.returncode}: {p.stderr.strip()}")
        ej = json.loads(p.stdout)
        cover = [
            r
            for r in ej["regions"]
            if abs(r["start"] - b_off) <= WINDOW and abs(r["end"] - (b_off + b_len)) <= WINDOW
        ]
        check(cover, f"no region covers B: {ej['regions']!r}")
        check(cover[0]["peak"] >= 7.0, f"peak {cover[0]['peak']} < 7.0")
        check(ej["mean_entropy"] < cover[0]["peak"], "mean entropy not below region peak")

        p = run(["crypto", "xor", blob_path, "--offset", hex(b_off), "--size", hex(b_len), "--json"], env)
        check(p.returncode == 0, f"xor auto rc={p.returncode}: {p.stderr.strip()}")
        xj = json.loads(p.stdout)
        top1 = xj["candidates"][0]
        check(top1["keylen"] in (12, 6, 4, 3, 2, 1), f"top1 keylen {top1['keylen']}")
        check(
            rotation_equiv(bytes.fromhex(top1["key_hex"]), KEY),
            f"top1 key {top1['key_hex']!r} not rotation-equiv",
        )
        check(top1["printable_ratio"] > 0.7, f"ratio {top1['printable_ratio']}")

        crib = (SIGNAL + SIGNAL[:4]).decode()
        p = run(
            ["crypto", "xor", blob_path, "--offset", hex(b_off), "--size", hex(b_len), "--magic-str", crib, "--json"],
            env,
        )
        check(p.returncode == 0, f"xor crib rc={p.returncode}: {p.stderr.strip()}")
        cj = json.loads(p.stdout)
        check(cj["candidates"], "crib mode: no candidates")
        check(
            rotation_equiv(bytes.fromhex(cj["candidates"][0]["key_hex"]), KEY),
            f"crib top1 key {cj['candidates'][0]['key_hex']!r} not rotation-equiv",
        )

        out_path = os.path.join(tmp, "dec.bin")
        p = run(
            ["crypto", "xor", blob_path, "--offset", hex(b_off), "--size", hex(b_len), "--out", out_path, "--json"],
            env,
        )
        check(p.returncode == 0, f"xor --out rc={p.returncode}: {p.stderr.strip()}")
        with open(out_path, "rb") as f:
            dec = f.read()
        check(dec == plain_b, "decrypted output != plaintext B")
        oj = json.loads(p.stdout)
        check(oj["out"]["sha256"] == hashlib.sha256(plain_b).hexdigest(), "out sha256 mismatch")

        p = run(["crypto", "xor", blob_path, "--offset", hex(len(blob) + 0x100)], env)
        check(p.returncode == 2, f"oob offset rc={p.returncode} != 2")

        print("OK")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
