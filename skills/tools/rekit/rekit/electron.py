"""electron: static inventory and security-boundary mapping for Electron apps (ASAR)."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys

MAX_FILE_BYTES = 5 << 20
MAX_FILES = 2000
MINIFIED_LINE = 10_000

_JS_EXT = (".js", ".mjs", ".cjs")

_IPC_MAIN_ANY = re.compile(r"ipcMain\.(?:on|once|handle|handleOnce)\s*\(")
_IPC_MAIN_LIT = re.compile(r"ipcMain\.(?:on|once|handle|handleOnce)\s*\(\s*(['\"])(.*?)\1")
_IPC_RNDR_ANY = re.compile(r"ipcRenderer\.(?:send|sendSync|invoke|sendTo)\s*\(")
_IPC_RNDR_LIT = re.compile(r"ipcRenderer\.(?:send|sendSync|invoke|sendTo)\s*\(\s*(['\"])(.*?)\1")
_BROWSERWIN = re.compile(r"new\s+BrowserWindow\s*\(")
_WEBPREF_START = re.compile(r"webPreferences\s*:\s*\{")
_PREF_BOOL = {k: re.compile(rf"\b{k}\s*:\s*(true|false)") for k in ("nodeIntegration", "contextIsolation", "sandbox")}
_PREF_PRELOAD = re.compile(r"\bpreload\s*:\s*([^}\n]+?)\s*,?\s*$", re.MULTILINE)
_CONTEXT_BRIDGE = re.compile(r"contextBridge\.exposeInMainWorld\s*\(\s*(['\"])(.*?)\1")

_DANGER_PATS: list[tuple[str, re.Pattern[str]]] = [
    ("remote-module", re.compile(r"@electron/remote|require\(\s*['\"]electron['\"]\s*\)\s*\.?\s*\bremote\b|\bremote\s*=\s*require\(\s*['\"]electron['\"]\s*\)")),
    ("shell.openExternal", re.compile(r"shell\.openExternal\s*\(")),
    ("webview-tag", re.compile(r"<webview[\s>]|webviewTag\s*:\s*true")),
    ("webSecurity:false", re.compile(r"webSecurity\s*:\s*false")),
    ("allowRunningInsecureContent", re.compile(r"allowRunningInsecureContent\s*:\s*true")),
]


class ElectronError(Exception):
    pass


def _align4(n: int) -> int:
    return (n + 3) & ~3


def _parse_asar(path: str) -> tuple[dict, int]:
    with open(path, "rb") as f:
        fixed = f.read(16)
        if len(fixed) < 16:
            raise ElectronError(f"{path}: too small for asar")
        _outer, inner_len, hdr_payload, jsize = struct.unpack("<IIII", fixed)
        if not (0 < jsize <= (64 << 20)):
            raise ElectronError(f"{path}: implausible asar json size {jsize}")
        if inner_len != 8 + _align4(jsize) or hdr_payload != 4 + _align4(jsize):
            raise ElectronError(f"{path}: bad asar header geometry")
        f.seek(16)
        raw = f.read(jsize)
        if len(raw) < jsize:
            raise ElectronError(f"{path}: truncated asar header")
    try:
        header = json.loads(raw)
    except ValueError:
        raise ElectronError(f"{path}: asar header is not valid JSON") from None
    if not isinstance(header.get("files"), dict):
        raise ElectronError(f"{path}: asar header has no files tree")
    return header, 16 + _align4(jsize)


def _iter_entries(node: dict, prefix: str = "") -> list[tuple[str, dict]]:
    out: list[tuple[str, dict]] = []
    for name, ent in node.get("files", {}).items():
        p = f"{prefix}/{name}" if prefix else name
        if isinstance(ent, dict) and "files" in ent:
            out.extend(_iter_entries(ent, p))
        else:
            out.append((p, ent))
    return out


def _verify_bytes(ent: dict, data: bytes | None) -> tuple[str, str | None, str | None]:
    if "link" in ent:
        return "link", None, None
    integ = ent.get("integrity")
    if data is None:
        return "missing", None, None
    if not integ:
        return ("no-integrity" if len(data) == int(ent.get("size", -1)) else "failed"), None, None
    if integ.get("algorithm", "SHA256") != "SHA256":
        return "unsupported-alg", integ.get("algorithm"), None
    declared = integ.get("hash")
    calc = hashlib.sha256(data).hexdigest()
    if calc != declared:
        return "failed", declared, calc
    block_size = int(integ.get("blockSize", 4 << 20))
    for i, bh in enumerate(integ.get("blocks") or []):
        bc = hashlib.sha256(data[i * block_size : (i + 1) * block_size]).hexdigest()
        if bc != bh:
            return "failed", f"block{i}:{bh}", f"block{i}:{bc}"
    return "verified", declared, calc


def _inventory_asar(path: str) -> tuple[list[dict], list[dict], int]:
    header, data_start = _parse_asar(path)
    with open(path, "rb") as f:
        blob = f.read()
    unpacked_root = path + ".unpacked"
    rows: list[dict] = []
    contradictions: list[dict] = []
    total = 0
    for rel, ent in _iter_entries(header):
        size = int(ent.get("size", 0))
        total += size
        if "link" in ent:
            rows.append({"path": rel, "size": size, "status": "link"})
            continue
        if ent.get("unpacked"):
            sib = os.path.join(unpacked_root, rel)
            if os.path.isfile(sib):
                with open(sib, "rb") as f:
                    data: bytes | None = f.read()
            else:
                data = None
            status, declared, calc = _verify_bytes(ent, data)
            rows.append({"path": rel, "size": size, "status": "missing" if data is None else status, "unpacked": True})
            if data is None:
                contradictions.append(
                    {"path": rel, "kind": "missing-unpacked", "declared": sib, "calculated": None}
                )
            elif status == "failed":
                contradictions.append({"path": rel, "kind": "hash-mismatch", "declared": declared, "calculated": calc})
            continue
        if "offset" not in ent:
            rows.append({"path": rel, "size": size, "status": "missing"})
            contradictions.append({"path": rel, "kind": "missing-data", "declared": None, "calculated": None})
            continue
        off = data_start + int(ent["offset"])
        data = blob[off : off + size]
        status, declared, calc = _verify_bytes(ent, data)
        rows.append({"path": rel, "size": size, "status": status})
        if status == "failed":
            kind = "block-mismatch" if declared and str(declared).startswith("block") else "hash-mismatch"
            contradictions.append({"path": rel, "kind": kind, "declared": declared, "calculated": calc})
    return rows, contradictions, total


def _inventory_dir(path: str) -> tuple[list[dict], list[dict], int]:
    rows: list[dict] = []
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in sorted(files):
            fp = os.path.join(root, name)
            rel = os.path.relpath(fp, path)
            size = os.path.getsize(fp)
            total += size
            rows.append({"path": rel, "size": size, "status": "n/a (extracted tree)"})
    return rows, [], total


def _cmd_inventory(args: argparse.Namespace) -> int:
    target = args.target
    if os.path.isdir(target):
        rows, contradictions, total = _inventory_dir(target)
        kind = "dir"
    elif os.path.isfile(target):
        rows, contradictions, total = _inventory_asar(target)
        kind = "asar"
    else:
        raise ElectronError(f"{target}: no such file or directory")
    counts = {
        "verified": sum(1 for r in rows if r["status"] == "verified"),
        "failed": sum(1 for r in rows if r["status"] == "failed"),
        "missing": sum(1 for r in rows if r["status"] == "missing"),
        "no_integrity": sum(1 for r in rows if r["status"] == "no-integrity"),
        "links": sum(1 for r in rows if r["status"] == "link"),
    }
    limitations: list[str] = []
    if kind == "dir":
        limitations.append("integrity not applicable to extracted tree")
    elif counts["no_integrity"]:
        limitations.append(f"{counts['no_integrity']} entries lack integrity metadata; size-checked only")
    result = {
        "input": target,
        "type": kind,
        "entries": len(rows),
        "total_size": total,
        **counts,
        "entries_detail": rows,
        "contradictions": contradictions,
        "confidence": "observed",
        "limitations": limitations,
    }
    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    print(f"input: {target} ({kind})")
    print(f"entries: {len(rows)}  total size: {total}")
    print(
        f"verified: {counts['verified']}  failed: {counts['failed']}  "
        f"missing: {counts['missing']}  no-integrity: {counts['no_integrity']}  links: {counts['links']}"
    )
    for c in contradictions:
        print(f"CONTRADICTION {c['kind']}: {c['path']}  declared={c['declared']}  calculated={c['calculated']}")
    for lim in limitations:
        print(f"limitation: {lim}")
    return 0


def _iter_js_sources(target: str) -> tuple[str, list[tuple[str, str]]]:
    if os.path.isdir(target):
        out: list[tuple[str, str]] = []
        for root, _dirs, files in os.walk(target):
            for name in sorted(files):
                if not name.endswith(_JS_EXT):
                    continue
                fp = os.path.join(root, name)
                if os.path.getsize(fp) > MAX_FILE_BYTES:
                    continue
                with open(fp, encoding="utf-8", errors="replace") as f:
                    out.append((os.path.relpath(fp, target), f.read()))
                if len(out) >= MAX_FILES:
                    return "dir", out
        return "dir", out
    if os.path.isfile(target):
        header, data_start = _parse_asar(target)
        with open(target, "rb") as f:
            blob = f.read()
        unpacked_root = target + ".unpacked"
        out = []
        for rel, ent in _iter_entries(header):
            if not rel.endswith(_JS_EXT) or "link" in ent:
                continue
            size = int(ent.get("size", 0))
            if size > MAX_FILE_BYTES:
                continue
            if ent.get("unpacked"):
                sib = os.path.join(unpacked_root, rel)
                if not os.path.isfile(sib):
                    continue
                with open(sib, encoding="utf-8", errors="replace") as f:
                    out.append((rel, f.read()))
            elif "offset" in ent:
                off = data_start + int(ent["offset"])
                out.append((rel, blob[off : off + size].decode("utf-8", "replace")))
            if len(out) >= MAX_FILES:
                break
        return "asar", out
    raise ElectronError(f"{target}: no such file or directory")


def _extract_webprefs(text: str, rel: str) -> list[dict]:
    out = []
    for m in _BROWSERWIN.finditer(text):
        wm = _WEBPREF_START.search(text, m.end(), m.end() + 4000)
        if not wm:
            continue
        depth = 1
        i = wm.end()
        while i < len(text) and depth:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        block = text[wm.end() : i - 1]
        pref = {"file": rel}
        for key, rx in _PREF_BOOL.items():
            km = rx.search(block)
            pref[key] = (km.group(1) == "true") if km else None
        pm = _PREF_PRELOAD.search(block)
        pref["preload"] = pm.group(1).strip() if pm else None
        out.append(pref)
    return out


def _literal_channels(rx_any: re.Pattern[str], rx_lit: re.Pattern[str], text: str) -> tuple[list[str], int]:
    lits = [m.group(2).strip() for m in rx_lit.finditer(text)]
    lits = [c for c in lits if c and "${" not in c]
    ambiguous = max(0, len(rx_any.findall(text)) - len(lits))
    return lits, ambiguous


def _cmd_boundary(args: argparse.Namespace) -> int:
    kind, sources = _iter_js_sources(args.target)
    prefs: list[dict] = []
    main_ch: dict[str, str] = {}
    rndr_ch: dict[str, str] = {}
    ambiguous = 0
    bridge_keys: list[str] = []
    dangerous: list[dict] = []
    minified = False
    for rel, text in sources:
        if not minified and any(len(line) > MINIFIED_LINE for line in text.splitlines()):
            minified = True
        prefs.extend(_extract_webprefs(text, rel))
        mains, amb1 = _literal_channels(_IPC_MAIN_ANY, _IPC_MAIN_LIT, text)
        rndrs, amb2 = _literal_channels(_IPC_RNDR_ANY, _IPC_RNDR_LIT, text)
        ambiguous += amb1 + amb2
        for c in mains:
            main_ch.setdefault(c, rel)
        for c in rndrs:
            rndr_ch.setdefault(c, rel)
        bridge_keys.extend(m.group(2) for m in _CONTEXT_BRIDGE.finditer(text))
        for kind_name, rx in _DANGER_PATS:
            for dm in rx.finditer(text):
                dangerous.append({"kind": kind_name, "file": rel, "detail": dm.group(0)[:80]})
    for pref in prefs:
        for key, label in (("nodeIntegration", "nodeIntegration:true"), ("contextIsolation", "contextIsolation:false"), ("sandbox", "sandbox:false")):
            enabled = pref.get(key)
            if (key == "nodeIntegration" and enabled) or (key != "nodeIntegration" and enabled is False):
                dangerous.append({"kind": label, "file": pref["file"], "detail": f"webPreferences {label}"})
    paired = sorted(set(main_ch) & set(rndr_ch))
    unpaired = [{"channel": c, "side": "main"} for c in sorted(set(main_ch) - set(rndr_ch))]
    unpaired += [{"channel": c, "side": "renderer"} for c in sorted(set(rndr_ch) - set(main_ch))]
    limitations = ["regex-based static extraction; dynamically computed channel names and bundled/minified code are unresolved"]
    if minified:
        limitations.append("minified/bundled code detected (line > 10KB); extraction degraded")
    result = {
        "input": args.target,
        "type": kind,
        "files_scanned": len(sources),
        "browser_windows": len(prefs),
        "web_preferences": prefs,
        "ipc": {
            "paired": paired,
            "unpaired": unpaired,
            "ambiguous": ambiguous,
            "main_channels": len(main_ch),
            "renderer_channels": len(rndr_ch),
        },
        "context_bridge_keys": sorted(set(bridge_keys)),
        "dangerous": dangerous,
        "confidence": "heuristic",
        "limitations": limitations,
    }
    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    print(f"input: {args.target} ({kind})  js files scanned: {len(sources)}")
    print(f"browser windows: {len(prefs)}")
    for pref in prefs:
        print(
            f"  {pref['file']}: nodeIntegration={pref['nodeIntegration']} "
            f"contextIsolation={pref['contextIsolation']} sandbox={pref['sandbox']} preload={pref['preload']}"
        )
    print(
        f"ipc channels: paired={len(paired)} unpaired={len(unpaired)} ambiguous={ambiguous} "
        f"(main {len(main_ch)} / renderer {len(rndr_ch)})"
    )
    for c in paired:
        print(f"  paired    {c}  ({main_ch[c]} <-> {rndr_ch[c]})")
    for u in unpaired:
        print(f"  unpaired  {u['channel']}  ({u['side']} only)")
    print(f"contextBridge keys: {', '.join(sorted(set(bridge_keys))) or '-'}")
    print(f"dangerous findings: {len(dangerous)}")
    for d in dangerous:
        print(f"  [{d['kind']}] {d['file']}: {d['detail']}")
    for lim in limitations:
        print(f"limitation: {lim}")
    return 0


def _dispatch(args: argparse.Namespace) -> int:
    try:
        return args.handler(args)
    except ElectronError as e:
        print(f"rekit: error: {e}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 3


def _add_subcommands(parser: argparse.ArgumentParser) -> None:
    parser.set_defaults(func=_dispatch)
    sub = parser.add_subparsers(dest="electron_command", metavar="<command>", required=True)

    p = sub.add_parser("inventory", help="verify ASAR integrity tree")
    p.add_argument("target", help="app.asar or extracted directory")
    p.add_argument("--json", action="store_true")
    p.set_defaults(handler=_cmd_inventory)

    p = sub.add_parser("boundary", help="extract Electron security boundary (webPreferences/IPC/contextBridge)")
    p.add_argument("target", help="app.asar or extracted directory")
    p.add_argument("--json", action="store_true")
    p.set_defaults(handler=_cmd_boundary)


def register(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("electron", help="Electron/ASAR static mapping (inventory/boundary)")
    _add_subcommands(parser)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rekit electron", description=__doc__)
    _add_subcommands(parser)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
