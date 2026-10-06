from __future__ import annotations

import argparse
import importlib
import json
import sys

from . import __version__
from .binctx import BinaryContext, RekitError
from .roles import DANGEROUS_PLT, is_suspicious, role_for

STRING_PREVIEW = 40


def _va(text: str) -> int:
    try:
        return int(text, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid address: {text!r}") from None


def _trunc(text: str, limit: int = STRING_PREVIEW) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _load(binary: str) -> BinaryContext:
    try:
        return BinaryContext.load_or_build(binary)
    except RekitError:
        raise
    except Exception as e:
        raise RekitError(f"{binary}: {e}") from e


def _dump(obj: object) -> None:
    print(json.dumps(obj, indent=2))


def _func_record(ctx: BinaryContext, va: int) -> dict:
    plt_calls = ctx.func_plt_calls(va)
    strings = ctx.func_strings(va)
    dangerous = [c for c in plt_calls if c in DANGEROUS_PLT]
    suspicious = [s for s in strings if is_suspicious(s)]
    indegree = ctx.func_indegree(va)
    score = 3 * len(dangerous) + 2 * len(suspicious) + min(indegree, 10) * 0.3
    return {
        "va": va,
        "name": ctx.names.get(va),
        "size": ctx.func_size(va),
        "indegree": indegree,
        "plt_calls": plt_calls,
        "dangerous": [{"name": c, "label": DANGEROUS_PLT[c]} for c in dangerous],
        "strings": strings,
        "suspicious_strings": suspicious,
        "role": role_for(plt_calls, strings),
        "score": round(score, 2),
    }


def _cmd_scan(args: argparse.Namespace) -> int:
    ctx = _load(args.binary)
    dangerous = [
        {"name": n, "va": ctx.plt[n], "label": DANGEROUS_PLT[n]} for n in sorted(ctx.plt) if n in DANGEROUS_PLT
    ]
    suspicious = [{"va": va, "text": s} for va, s in sorted(ctx.strings.items()) if is_suspicious(s)]
    result = {
        "path": ctx.path,
        "sha256": ctx.sha256,
        "arch": ctx.arch,
        "bits": ctx.bits,
        "image_base": ctx.image_base,
        "entry": ctx.entry,
        "functions": len(ctx.func_starts),
        "strings": len(ctx.strings),
        "plt": len(ctx.plt),
        "call_edges": len(ctx.call_edges),
        "string_xrefs": len(ctx.string_xrefs),
        "dangerous_imports": dangerous,
        "suspicious_strings": suspicious[:10],
        "suspicious_total": len(suspicious),
    }
    if args.json:
        _dump(result)
        return 0
    lines = [
        f"binary:     {ctx.path}",
        f"sha256:     {ctx.sha256}",
        f"arch:       {ctx.arch} ({ctx.bits}-bit)",
        f"image_base: {ctx.image_base:#x}",
        f"entry:      {ctx.entry:#x}",
        f"functions:  {len(ctx.func_starts)}",
        f"strings:    {len(ctx.strings)}",
        f"plt:        {len(ctx.plt)}",
        f"call edges: {len(ctx.call_edges)}",
        f"dangerous imports ({len(dangerous)}):",
    ]
    lines += [f"  {d['va']:#x} {d['name']:<16} {d['label']}" for d in dangerous]
    lines.append(f"suspicious strings (top {min(10, len(suspicious))} of {len(suspicious)}):")
    lines += [f"  {s['va']:#x} {_trunc(s['text'], 80)}" for s in suspicious[:10]]
    print("\n".join(lines))
    return 0


def _cmd_funcs(args: argparse.Namespace) -> int:
    ctx = _load(args.binary)
    recs = [_func_record(ctx, va) for va in ctx.func_starts]
    if args.sort == "va":
        recs.sort(key=lambda r: r["va"])
    else:
        recs.sort(key=lambda r: (-r[args.sort], r["va"]))
    if args.json:
        _dump({"count": len(recs), "functions": recs})
        return 0
    for r in recs:
        plt = _trunc(",".join(r["plt_calls"]))
        print(
            f"{r['va']:#014x} {r['size']:>6} {r['indegree']:>4} {r['score']:>7.2f} "
            f"{r['role']:<10} {(r['name'] or '-'):<24} {plt}"
        )
    return 0


def _cmd_strings(args: argparse.Namespace) -> int:
    ctx = _load(args.binary)
    items = sorted(ctx.strings.items())
    if args.query:
        q = args.query.lower()
        items = [(v, s) for v, s in items if q in s.lower()]
    if args.json:
        _dump({"count": len(items), "strings": [{"va": v, "text": s} for v, s in items]})
        return 0
    for v, s in items:
        print(f"{v:#014x}  {s}")
    return 0


def _cmd_xrefs(args: argparse.Namespace) -> int:
    ctx = _load(args.binary)
    target: str = args.target
    if target.lower().startswith("0x"):
        try:
            va = int(target, 16)
        except ValueError:
            raise RekitError(f"invalid target address: {target!r}") from None
        matches = {va: ctx.strings.get(va, "")}
    else:
        q = target.lower()
        matches = {v: s for v, s in ctx.strings.items() if q in s.lower()}
    vas = set(matches)
    hits = sorted((site, sva) for site, sva in ctx.string_xrefs if sva in vas)
    xrefs = [
        {"site": site, "string_va": sva, "func": ctx.func_containing(site), "text": ctx.strings.get(sva, "")}
        for site, sva in hits
    ]
    if args.json:
        _dump(
            {
                "target": target,
                "matches": [{"va": v, "text": s} for v, s in sorted(matches.items())],
                "xrefs": xrefs,
            }
        )
        return 0
    if not matches:
        print(f"no string matches {target!r}")
        return 0
    for x in xrefs:
        where = f" in func {x['func']:#x}" if x["func"] is not None else ""
        print(f"{x['site']:#014x} -> {x['string_va']:#x}{where}  {x['text']!r}")
    if not xrefs:
        print("no xrefs found")
    return 0


def _cmd_calls(args: argparse.Namespace) -> int:
    ctx = _load(args.binary)
    edges = ctx.call_edges
    if args.from_va is not None:
        edges = [e for e in edges if e[0] == args.from_va]
    if args.to_va is not None:
        edges = [e for e in edges if e[1] == args.to_va]
    rows = [
        {
            "caller": c,
            "target": t,
            "site": s,
            "target_name": ctx.plt_name_at(t) or ctx.names.get(t) or "",
        }
        for c, t, s in edges
    ]
    if args.json:
        _dump({"count": len(rows), "edges": rows})
        return 0
    for r in rows:
        print(f"{r['caller']:#014x} -> {r['target']:#014x} @ {r['site']:#x} {r['target_name']}")
    return 0


def _cmd_disasm(args: argparse.Namespace) -> int:
    ctx = _load(args.binary)
    insns = ctx.disasm(args.va, args.n)
    if args.json:
        _dump(
            {
                "va": args.va,
                "count": len(insns),
                "insns": [{"va": a, "mnemonic": m, "op_str": o} for a, m, o in insns],
            }
        )
        return 0
    for a, m, o in insns:
        print(f"{a:#014x}: {m:<8} {o}")
    return 0


def _cmd_triage(args: argparse.Namespace) -> int:
    ctx = _load(args.binary)
    recs = [_func_record(ctx, va) for va in ctx.func_starts]
    recs.sort(key=lambda r: (-r["score"], r["va"]))
    top = recs[: max(args.k, 0)]
    if args.json:
        _dump({"total": len(recs), "k": args.k, "top": top})
        return 0
    for r in top:
        danger = ",".join(f"{d['name']}({d['label']})" for d in r["dangerous"])
        plain = ",".join(c for c in r["plt_calls"] if c not in DANGEROUS_PLT)
        pltcell = ";".join(x for x in (danger, plain) if x) or "-"
        strs = " | ".join(_trunc(s) for s in r["strings"][:3])
        if len(r["strings"]) > 3:
            strs += f" | +{len(r['strings']) - 3} more"
        if not strs:
            strs = "-"
        print(
            f"{r['va']:#014x} {r['size']:>6} {r['indegree']:>4} {r['score']:>7.2f} "
            f"{r['role']:<10} {(r['name'] or '-'):<20} {pltcell:<40} {strs}"
        )
    return 0


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="rekit", description="fast binary pre-triage toolkit")
    ap.add_argument("--version", action="version", version=f"rekit {__version__}")
    sub = ap.add_subparsers(dest="command", required=True, metavar="command")

    p = sub.add_parser("scan", help="binary summary")
    p.add_argument("binary")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=_cmd_scan)

    p = sub.add_parser("funcs", help="list functions")
    p.add_argument("binary")
    p.add_argument("--json", action="store_true")
    p.add_argument("--sort", choices=("va", "size", "indegree", "score"), default="va")
    p.set_defaults(func=_cmd_funcs)

    p = sub.add_parser("strings", help="list strings")
    p.add_argument("binary")
    p.add_argument("--query", "-q", default=None)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=_cmd_strings)

    p = sub.add_parser("xrefs", help="xrefs to a string (0x<va> or substring)")
    p.add_argument("binary")
    p.add_argument("target")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=_cmd_xrefs)

    p = sub.add_parser("calls", help="call edges")
    p.add_argument("binary")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--from", dest="from_va", type=_va, default=None)
    g.add_argument("--to", dest="to_va", type=_va, default=None)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=_cmd_calls)

    p = sub.add_parser("disasm", help="linear disassembly at va")
    p.add_argument("binary")
    p.add_argument("va", type=_va)
    p.add_argument("-n", type=int, default=40)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=_cmd_disasm)

    p = sub.add_parser("triage", help="rank functions by risk score")
    p.add_argument("binary")
    p.add_argument("-k", type=int, default=10)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=_cmd_triage)

    for modname in ("corpus", "findings", "crypto"):
        try:
            mod = importlib.import_module(f".{modname}", __package__)
            mod.register(sub)
        except ImportError:
            stub = sub.add_parser(modname, help="(module not available yet)")
            stub.add_argument("args", nargs="*")
            stub.set_defaults(missing=modname)
        except Exception as e:
            stub = sub.add_parser(modname, help="(module failed to load)")
            stub.add_argument("args", nargs="*")
            stub.set_defaults(missing=f"{modname} ({e})")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    missing = getattr(args, "missing", None)
    if missing is not None:
        print(f"rekit: {missing}: module not available yet", file=sys.stderr)
        return 2
    try:
        return args.func(args)
    except RekitError as e:
        print(f"rekit: error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
