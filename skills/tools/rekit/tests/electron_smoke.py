from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MAIN_JS = r"""
const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');

function createWindow() {
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      preload: path.join(__dirname, 'preload.js'),
    },
  });
  win.loadFile('index.html');
}

ipcMain.handle('get-secret', async () => {
  return 's3cret';
});

ipcMain.on('log-event', (event, msg) => console.log(msg));

app.whenReady().then(createWindow);
"""

PRELOAD_JS = r"""
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  getSecret: () => ipcRenderer.invoke('get-secret'),
});
"""

RENDERER_JS = r"""
async function boot() {
  const secret = await ipcRenderer.invoke('get-secret');
  ipcRenderer.send(' orphans ');
  document.title = secret;
}
window.addEventListener('DOMContentLoaded', boot);
"""

PACKAGE_JSON = '{"name":"rekit-fixture","version":"1.0.0","main":"main.js"}\n'


def build_asar_fallback(srcdir: str, out: str) -> None:
    entries: dict[str, dict] = {}
    blob = bytearray()
    for name in sorted(os.listdir(srcdir)):
        fp = os.path.join(srcdir, name)
        if not os.path.isfile(fp):
            continue
        with open(fp, "rb") as f:
            data = f.read()
        offset = len(blob)
        blob += data
        block_size = 4 << 20
        blocks = [
            hashlib.sha256(data[i : i + block_size]).hexdigest() for i in range(0, len(data), block_size)
        ]
        entries[name] = {
            "size": len(data),
            "offset": str(offset),
            "integrity": {
                "algorithm": "SHA256",
                "hash": hashlib.sha256(data).hexdigest(),
                "blockSize": block_size,
                "blocks": blocks,
            },
        }
    js = json.dumps({"files": entries}, separators=(",", ":")).encode()
    padded = (len(js) + 3) & ~3
    header_buf = struct.pack("<I", 4 + padded) + struct.pack("<I", len(js)) + js + b"\x00" * (padded - len(js))
    size_buf = struct.pack("<I", 4) + struct.pack("<I", len(header_buf))
    with open(out, "wb") as f:
        f.write(size_buf + header_buf + bytes(blob))


def pack_asar(srcdir: str, out: str) -> str:
    try:
        proc = subprocess.run(
            ["npm", "exec", "--yes", "--", "@electron/asar", "pack", srcdir, out],
            capture_output=True,
            text=True,
            timeout=150,
            cwd=os.path.dirname(out) or ".",
        )
        if proc.returncode == 0 and os.path.isfile(out) and os.path.getsize(out) > 16:
            return "npm"
    except (OSError, subprocess.TimeoutExpired):
        pass
    build_asar_fallback(srcdir, out)
    return "fallback"


def _entry_span(asar_path: str, name: str) -> tuple[int, int]:
    with open(asar_path, "rb") as f:
        fixed = f.read(16)
        _outer, _inner, _hdrp, jsize = struct.unpack("<IIII", fixed)
        f.seek(16)
        header = json.loads(f.read(jsize))
    ent = header["files"][name]
    data_start = 16 + ((jsize + 3) & ~3)
    return data_start + int(ent["offset"]), int(ent["size"])


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


def check_evidence(obj: dict, where: str) -> None:
    check("confidence" in obj and "limitations" in obj, f"{where}: missing confidence/limitations")


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="rekit-electron-")
    try:
        env = dict(os.environ)
        env["REKIT_HOME"] = os.path.join(tmp, "cache")
        env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")

        src = os.path.join(tmp, "src")
        os.makedirs(src)
        for name, content in (
            ("main.js", MAIN_JS),
            ("preload.js", PRELOAD_JS),
            ("renderer.js", RENDERER_JS),
            ("package.json", PACKAGE_JSON),
        ):
            with open(os.path.join(src, name), "w") as f:
                f.write(content)

        asar_path = os.path.join(tmp, "app.asar")
        packer = pack_asar(src, asar_path)

        p = run(["electron", "inventory", asar_path, "--json"], env)
        check(p.returncode == 0, f"inventory rc={p.returncode}: {p.stderr.strip()}")
        inv = json.loads(p.stdout)
        check_evidence(inv, "inventory")
        check(inv["type"] == "asar", f"type: {inv['type']}")
        check(inv["entries"] == 4, f"entries: {inv['entries']}")
        check(inv["failed"] == 0 and inv["missing"] == 0, f"failed/missing: {p.stdout}")
        check(inv["verified"] == inv["entries"], f"not all verified: {inv['verified']}/{inv['entries']}")
        check(not inv["contradictions"], f"unexpected contradictions: {inv['contradictions']!r}")

        off, _size = _entry_span(asar_path, "main.js")
        with open(asar_path, "rb") as f:
            raw = bytearray(f.read())
        raw[off] ^= 0xFF
        tampered = os.path.join(tmp, "tampered.asar")
        with open(tampered, "wb") as f:
            f.write(raw)
        p = run(["electron", "inventory", tampered, "--json"], env)
        check(p.returncode == 0, f"tampered inventory rc={p.returncode}: {p.stderr.strip()}")
        tj = json.loads(p.stdout)
        check_evidence(tj, "inventory tampered")
        check(tj["failed"] == 1 and tj["contradictions"], f"tampered not caught: {p.stdout}")
        check(tj["contradictions"][0]["path"] == "main.js", f"wrong path: {tj['contradictions']!r}")
        check(tj["contradictions"][0]["kind"] in ("hash-mismatch", "block-mismatch"), "bad kind")
        p = run(["electron", "inventory", tampered], env)
        check("CONTRADICTION" in p.stdout and "main.js" in p.stdout, f"human output: {p.stdout!r}")

        p = run(["electron", "boundary", asar_path, "--json"], env)
        check(p.returncode == 0, f"boundary rc={p.returncode}: {p.stderr.strip()}")
        bj = json.loads(p.stdout)
        check_evidence(bj, "boundary")
        check(bj["confidence"] == "heuristic", f"boundary confidence: {bj['confidence']}")
        check(any("regex-based" in l for l in bj["limitations"]), "boundary limitation missing")
        check("get-secret" in bj["ipc"]["paired"], f"paired: {bj['ipc']['paired']!r}")
        check(
            any(u["channel"] == "orphans" and u["side"] == "renderer" for u in bj["ipc"]["unpaired"]),
            f"unpaired: {bj['ipc']['unpaired']!r}",
        )
        check(
            any(u["channel"] == "log-event" and u["side"] == "main" for u in bj["ipc"]["unpaired"]),
            f"log-event not unpaired: {bj['ipc']['unpaired']!r}",
        )
        check(
            any(d["kind"] == "nodeIntegration:true" for d in bj["dangerous"]),
            f"dangerous: {bj['dangerous']!r}",
        )
        check(
            any(d["kind"] == "contextIsolation:false" for d in bj["dangerous"]),
            "contextIsolation:false missing",
        )
        check("api" in bj["context_bridge_keys"], f"bridge keys: {bj['context_bridge_keys']!r}")
        pref = bj["web_preferences"][0]
        check(pref["nodeIntegration"] is True and pref["contextIsolation"] is False, f"pref: {pref!r}")
        check(pref["preload"] and "preload.js" in pref["preload"], f"preload: {pref!r}")

        p = run(["electron", "inventory", src, "--json"], env)
        check(p.returncode == 0, f"dir inventory rc={p.returncode}: {p.stderr.strip()}")
        dj = json.loads(p.stdout)
        check_evidence(dj, "dir inventory")
        check(dj["type"] == "dir", f"dir type: {dj['type']}")
        check(
            any("integrity not applicable" in l for l in dj["limitations"]),
            f"dir limitations: {dj['limitations']!r}",
        )
        p = run(["electron", "boundary", src, "--json"], env)
        check(p.returncode == 0, f"dir boundary rc={p.returncode}: {p.stderr.strip()}")
        db = json.loads(p.stdout)
        check("get-secret" in db["ipc"]["paired"], "dir boundary: get-secret not paired")

        print(f"OK (packer={packer})")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
