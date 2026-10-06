"""Semantic function corpus: embedding index, natural-language search, cross-version match."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any, Sequence

import numpy as np

from .binctx import BinaryContext, RekitError
from .roles import role_for

EMBED_MODEL = "BAAI/bge-small-en-v1.5"
EMBED_DIM = 384
EMBED_BATCH = 256
EMBED_TEXT_CAP = 256
MIN_FUNC_SIZE = 8
FEAT_SIZE_CAP = 0x4000
DISASM_MAX_INSNS = 1500
MATCH_BLOCK = 512
SIZE_RATIO_LO = 0.4
SIZE_RATIO_HI = 2.5
INDEGREE_TOL = 10
HIGH_STRUCT_MIN = 0.35
HIGH_FINAL_MIN = 0.65
MEDIUM_FINAL_MIN = 0.50

_IMM_RE = re.compile(r"0x[0-9a-fA-F]+|\b\d+\b")

_embedder: Any = None


class Corpus:
    def __init__(
        self,
        directory: str,
        meta: dict[str, Any],
        profiles: list[dict[str, Any]],
        vectors: np.ndarray,
        feats: dict[int, dict[str, Any]],
    ) -> None:
        self.dir = directory
        self.meta = meta
        self.profiles = profiles
        self.vectors = vectors
        self.feats = feats
        self.vas = np.asarray([p["va"] for p in profiles], dtype=np.int64)
        self.sizes = np.asarray([p["size"] for p in profiles], dtype=np.float64)
        self.indegs = np.asarray([p["indegree"] for p in profiles], dtype=np.float64)
        self._index = {int(va): i for i, va in enumerate(self.vas.tolist())}


def _load_embedder() -> Any:
    global _embedder
    if _embedder is None:
        from fastembed import TextEmbedding

        _embedder = TextEmbedding(model_name=EMBED_MODEL, threads=os.cpu_count())
    return _embedder


def _get_embedder() -> Any | None:
    try:
        return _load_embedder()
    except ImportError:
        print("fastembed is required for corpus commands: pip install fastembed", file=sys.stderr)
    except Exception as exc:
        print(f"cannot load embedding model {EMBED_MODEL}: {exc}", file=sys.stderr)
    return None


def _home() -> str:
    home = os.environ.get("REKIT_HOME") or os.path.join(os.path.expanduser("~"), ".cache", "rekit")
    os.makedirs(home, exist_ok=True)
    return home


def _corpus_dir(ctx: BinaryContext) -> str:
    return os.path.join(_home(), f"{ctx.key}.corpus")


def _load_ctx(binary: str) -> BinaryContext:
    try:
        return BinaryContext.load_or_build(binary)
    except RekitError:
        raise
    except Exception as e:
        raise RekitError(f"{binary}: {e}") from e


def _va(text: str) -> int:
    try:
        return int(text, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid address: {text!r}") from None


def _trunc(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _dump(obj: object) -> None:
    print(json.dumps(obj, indent=2))


def _build_feats(
    ctx: BinaryContext, va: int, size: int, indegree: int, calls: list[str], strings: list[str]
) -> dict[str, Any]:
    mnem_hist: dict[str, int] = {}
    imms: set[int] = set()
    if size <= FEAT_SIZE_CAP:
        end = va + size
        for addr, mnem, ops in ctx.disasm(va, max_insns=DISASM_MAX_INSNS):
            if addr >= end:
                break
            mnem_hist[mnem] = mnem_hist.get(mnem, 0) + 1
            for tok in _IMM_RE.findall(ops):
                v = int(tok, 16) if tok.startswith("0x") else int(tok)
                if 0x100 <= v <= 0xFFFFFFFF:
                    imms.add(v)
    return {
        "size": size,
        "indegree": indegree,
        "out_plt": list(calls),
        "strings": list(strings),
        "mnem_hist": mnem_hist,
        "imms": sorted(imms),
    }


def _build_profiles(ctx: BinaryContext) -> tuple[list[dict[str, Any]], dict[int, dict[str, Any]]]:
    plt_vas = set(ctx.plt.values())
    profiles: list[dict[str, Any]] = []
    feats: dict[int, dict[str, Any]] = {}
    starts = ctx.func_starts
    total = len(starts)
    for n, va in enumerate(starts):
        if total >= 1024 and n % 512 == 0:
            print(f"rekit: profiling {n}/{total}", file=sys.stderr)
        if va in plt_vas:
            continue
        size = ctx.func_size(va)
        if size < MIN_FUNC_SIZE:
            continue
        name = ctx.names.get(va) or f"sub_{va:x}"
        calls = ctx.func_plt_calls(va)
        strings = ctx.func_strings(va)
        role = role_for(calls, strings)
        text = (
            f"{name} role={role} | calls: {', '.join(calls[:12])} | "
            f"strings: {', '.join(s[:60] for s in strings[:8])}"
        )
        indegree = ctx.func_indegree(va)
        profiles.append(
            {
                "va": va,
                "name": name,
                "role": role,
                "size": size,
                "indegree": indegree,
                "text": text,
                "calls": calls,
                "strings": strings,
            }
        )
        feats[va] = _build_feats(ctx, va, size, indegree, calls, strings)
    return profiles, feats


def _embed_texts(texts: list[str]) -> np.ndarray:
    model = _load_embedder()
    if not texts:
        return np.zeros((0, EMBED_DIM), dtype=np.float32)
    rows: list[np.ndarray] = []
    for i in range(0, len(texts), EMBED_BATCH):
        batch = [t[:EMBED_TEXT_CAP] for t in texts[i : i + EMBED_BATCH]]
        rows.extend(np.asarray(v, dtype=np.float32) for v in model.embed(batch))
        print(f"rekit: embedded {min(i + EMBED_BATCH, len(texts))}/{len(texts)}", file=sys.stderr)
    mat = np.vstack(rows)
    norms = np.maximum(np.linalg.norm(mat, axis=1, keepdims=True), 1e-12)
    return (mat / norms).astype(np.float32)


def _embed_query(query: str) -> np.ndarray:
    vec = next(iter(_load_embedder().embed([query])))
    q = np.asarray(vec, dtype=np.float32)
    return q / max(float(np.linalg.norm(q)), 1e-12)


def _persist(ctx: BinaryContext, corpus: Corpus) -> None:
    directory = _corpus_dir(ctx)
    os.makedirs(directory, exist_ok=True)
    tmp = os.path.join(directory, "vectors.npy.tmp")
    with open(tmp, "wb") as f:
        np.save(f, corpus.vectors)
    os.replace(tmp, os.path.join(directory, "vectors.npy"))
    for name, obj in (
        ("meta.json", corpus.meta),
        ("profiles.json", corpus.profiles),
        ("feats.json", {str(k): v for k, v in corpus.feats.items()}),
    ):
        tmp = os.path.join(directory, name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, separators=(",", ":"))
        os.replace(tmp, os.path.join(directory, name))


def _try_load(ctx: BinaryContext) -> Corpus | None:
    directory = _corpus_dir(ctx)
    try:
        with open(os.path.join(directory, "meta.json"), encoding="utf-8") as f:
            meta = json.load(f)
        if meta.get("sha256") != ctx.sha256 or meta.get("model") != EMBED_MODEL:
            return None
        with open(os.path.join(directory, "profiles.json"), encoding="utf-8") as f:
            profiles = json.load(f)
        with open(os.path.join(directory, "feats.json"), encoding="utf-8") as f:
            feats = {int(k): v for k, v in json.load(f).items()}
        vectors = np.load(os.path.join(directory, "vectors.npy"))
        if vectors.ndim != 2 or vectors.shape[0] != len(profiles) or vectors.shape[0] != meta.get("count"):
            return None
        return Corpus(directory, meta, profiles, vectors.astype(np.float32, copy=False), feats)
    except (OSError, ValueError, KeyError, EOFError):
        return None


def _build_and_persist(ctx: BinaryContext) -> Corpus:
    t0 = time.monotonic()
    profiles, feats = _build_profiles(ctx)
    vectors = _embed_texts([p["text"] for p in profiles])
    meta = {
        "key": ctx.key,
        "sha256": ctx.sha256,
        "binary": ctx.path,
        "arch": ctx.arch,
        "model": EMBED_MODEL,
        "dim": int(vectors.shape[1]) if vectors.ndim == 2 else EMBED_DIM,
        "count": len(profiles),
        "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    corpus = Corpus(_corpus_dir(ctx), meta, profiles, vectors, feats)
    _persist(ctx, corpus)
    print(
        f"rekit: built corpus {corpus.dir} ({len(profiles)} functions, {time.monotonic() - t0:.1f}s)",
        file=sys.stderr,
    )
    return corpus


def _load_or_build(binary: str, force: bool = False) -> tuple[BinaryContext, Corpus]:
    ctx = _load_ctx(binary)
    corpus = None if force else _try_load(ctx)
    if corpus is None:
        corpus = _build_and_persist(ctx)
    else:
        print(f"rekit: loaded corpus from cache {corpus.dir}", file=sys.stderr)
    return ctx, corpus


def build(binary: str, force: bool = False) -> Corpus:
    _ctx, corpus = _load_or_build(binary, force=force)
    return corpus


def _topk(corpus: Corpus, scores: np.ndarray, k: int) -> list[dict[str, Any]]:
    n = int(scores.shape[0])
    k = max(0, min(k, n))
    if k == 0:
        return []
    part = np.argpartition(-scores, k - 1)[:k]
    order = part[np.argsort(-scores[part], kind="stable")]
    hits: list[dict[str, Any]] = []
    for i in order.tolist():
        s = float(scores[i])
        if s == float("-inf"):
            continue
        p = corpus.profiles[i]
        hits.append(
            {
                "va": p["va"],
                "name": p["name"],
                "role": p["role"],
                "score": round(s, 6),
                "text": p["text"],
            }
        )
    return hits


def search(binary: str, query: str, k: int = 5) -> list[dict[str, Any]]:
    _ctx, corpus = _load_or_build(binary)
    q = _embed_query(query)
    return _topk(corpus, corpus.vectors @ q, k)


def similar(binary: str, va: int, k: int = 5) -> list[dict[str, Any]]:
    _ctx, corpus = _load_or_build(binary)
    idx = corpus._index.get(va)
    if idx is None:
        raise ValueError(f"{va:#x}: not in corpus (PLT stub or below min size)")
    scores = corpus.vectors @ corpus.vectors[idx]
    scores[idx] = -np.inf
    return _topk(corpus, scores, k)


def _jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    if inter == 0:
        return 0.0
    return inter / (len(a) + len(b) - inter)


def _confidence(s_struct: float, final: float) -> str:
    if s_struct >= HIGH_STRUCT_MIN and final >= HIGH_FINAL_MIN:
        return "HIGH"
    if final >= MEDIUM_FINAL_MIN:
        return "MEDIUM"
    return "LOW"


def _mnem_matrix(corpus: Corpus, vocab: dict[str, int]) -> np.ndarray:
    mat = np.zeros((len(corpus.profiles), len(vocab)), dtype=np.float32)
    for i, p in enumerate(corpus.profiles):
        hist = (corpus.feats.get(p["va"]) or {}).get("mnem_hist") or {}
        row = mat[i]
        for m, c in hist.items():
            j = vocab.get(m)
            if j is not None:
                row[j] = c
    norms = np.linalg.norm(mat, axis=1, keepdims=True)
    return mat / np.maximum(norms, 1e-12)


def _struct_sets(corpus: Corpus) -> list[tuple[set[str], set[int], set[str]]]:
    out: list[tuple[set[str], set[int], set[str]]] = []
    for p in corpus.profiles:
        f = corpus.feats.get(p["va"]) or {}
        out.append(
            (
                set(f.get("out_plt") or ()),
                set(f.get("imms") or ()),
                {s.lower() for s in (f.get("strings") or ())},
            )
        )
    return out


def _candidate_record(new: Corpus, j: int, s_struct: float, s_sem: float) -> dict[str, Any]:
    p = new.profiles[j]
    final = 0.55 * s_struct + 0.45 * s_sem
    return {
        "new_va": p["va"],
        "new_name": p["name"],
        "s_struct": round(s_struct, 6),
        "s_sem": round(s_sem, 6),
        "final": round(final, 6),
        "confidence": _confidence(s_struct, final),
    }


def _match_pairs(old: Corpus, new: Corpus) -> list[dict[str, Any]]:
    n_old = len(old.profiles)
    vocab = sorted({m for c in (old, new) for f in c.feats.values() for m in (f.get("mnem_hist") or {})})
    vidx = {m: i for i, m in enumerate(vocab)}
    mo = _mnem_matrix(old, vidx)
    mn = _mnem_matrix(new, vidx)
    old_sets = _struct_sets(old)
    new_sets = _struct_sets(new)
    pairs: list[dict[str, Any]] = []
    for i0 in range(0, n_old, MATCH_BLOCK):
        i1 = min(i0 + MATCH_BLOCK, n_old)
        sem_blk = old.vectors[i0:i1] @ new.vectors.T
        mn_blk = mo[i0:i1] @ mn.T
        for bi in range(i1 - i0):
            i = i0 + bi
            op = old.profiles[i]
            osize = op["size"]
            mask = (
                (new.sizes >= osize * SIZE_RATIO_LO)
                & (new.sizes <= osize * SIZE_RATIO_HI)
                & (np.abs(new.indegs - op["indegree"]) <= INDEGREE_TOL)
            )
            o_plt, o_imm, o_str = old_sets[i]
            cands: list[dict[str, Any]] = []
            for j in np.flatnonzero(mask).tolist():
                n_plt, n_imm, n_str = new_sets[j]
                s_struct = (
                    0.4 * _jaccard(o_plt, n_plt)
                    + 0.3 * float(mn_blk[bi, j])
                    + 0.2 * _jaccard(o_imm, n_imm)
                    + 0.1 * _jaccard(o_str, n_str)
                )
                cands.append(_candidate_record(new, j, s_struct, float(sem_blk[bi, j])))
            cands.sort(key=lambda r: (-r["final"], r["new_va"]))
            rec: dict[str, Any] = {
                "old_va": op["va"],
                "old_name": op["name"],
                "new_va": None,
                "new_name": None,
                "s_struct": None,
                "s_sem": None,
                "final": None,
                "confidence": "LOW",
                "alts": [],
            }
            if cands:
                best = cands[0]
                for field in ("new_va", "new_name", "s_struct", "s_sem", "final", "confidence"):
                    rec[field] = best[field]
                rec["alts"] = cands[1:3]
            pairs.append(rec)
    pairs.sort(key=lambda r: (-(r["final"] if r["final"] is not None else -1.0), r["old_va"]))
    return pairs


def match(old_path: str, new_path: str, k: int = 20) -> dict[str, Any]:
    octx, old = _load_or_build(old_path)
    nctx, new = _load_or_build(new_path)
    pairs = _match_pairs(old, new)
    return {
        "old": octx.path,
        "new": nctx.path,
        "old_count": len(old.profiles),
        "new_count": len(new.profiles),
        "pairs": pairs,
        "total_pairs": len(pairs),
    }


def _print_hits(hits: list[dict[str, Any]]) -> None:
    for h in hits:
        print(
            f"{h['score']:.4f}  {h['va']:#014x}  {h['role']:<10}  "
            f"{_trunc(h['name'], 24):<24}  {_trunc(h['text'], 100)}"
        )


def _print_match_table(pairs: list[dict[str, Any]], k: int) -> None:
    print(
        f"{'OLD_VA':<16}{'OLD_NAME':<26}{'NEW_VA':<16}{'NEW_NAME':<26}"
        f"{'FINAL':>7} {'STRUCT':>7} {'SEM':>7}  CONF"
    )
    for rec in pairs[: max(k, 0)]:
        old_cell = f"{rec['old_va']:#014x} {_trunc(rec['old_name'], 24):<24}"
        if rec["new_va"] is None:
            print(f"{old_cell}  ->  (no candidates)")
            continue
        new_cell = f"{rec['new_va']:#014x} {_trunc(rec['new_name'], 24):<24}"
        print(
            f"{old_cell}  ->  {new_cell}  "
            f"{rec['final']:.4f} {rec['s_struct']:.4f} {rec['s_sem']:.4f}  {rec['confidence']}"
        )


def _cmd_build(args: argparse.Namespace) -> int:
    if _get_embedder() is None:
        return 3
    corpus = build(args.binary, force=args.force)
    out = {
        "key": corpus.meta["key"],
        "binary": corpus.meta["binary"],
        "arch": corpus.meta["arch"],
        "model": corpus.meta["model"],
        "dim": corpus.meta["dim"],
        "count": corpus.meta["count"],
        "built_at": corpus.meta["built_at"],
        "dir": corpus.dir,
    }
    if args.json:
        _dump(out)
    else:
        print(f"corpus:    {out['dir']}")
        print(f"functions: {out['count']}")
        print(f"dim:       {out['dim']}")
        print(f"model:     {out['model']}")
    return 0


def _cmd_search(args: argparse.Namespace) -> int:
    if _get_embedder() is None:
        return 3
    hits = search(args.binary, args.query, args.k)
    if args.json:
        _dump(hits)
    else:
        _print_hits(hits)
    return 0


def _cmd_similar(args: argparse.Namespace) -> int:
    if _get_embedder() is None:
        return 3
    hits = similar(args.binary, args.va, args.k)
    if args.json:
        _dump(hits)
    else:
        _print_hits(hits)
    return 0


def _cmd_match(args: argparse.Namespace) -> int:
    if _get_embedder() is None:
        return 3
    result = match(args.old, args.new, args.k)
    if args.json:
        _dump(result)
    else:
        print(
            f"old: {result['old']} ({result['old_count']} funcs)  "
            f"new: {result['new']} ({result['new_count']} funcs)  "
            f"pairs: {result['total_pairs']}"
        )
        _print_match_table(result["pairs"], args.k)
    return 0


def _dispatch(args: argparse.Namespace) -> int:
    try:
        return args.handler(args)
    except RekitError:
        raise
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3


def _add_corpus_subcommands(parser: argparse.ArgumentParser) -> None:
    parser.set_defaults(func=_dispatch)
    sub = parser.add_subparsers(dest="corpus_command", metavar="<command>", required=True)

    p = sub.add_parser("build", help="build the function corpus for a binary")
    p.add_argument("binary")
    p.add_argument("--force", action="store_true", help="rebuild even if cached")
    p.add_argument("--json", action="store_true")
    p.set_defaults(handler=_cmd_build)

    p = sub.add_parser("search", help="natural-language search over functions")
    p.add_argument("binary")
    p.add_argument("query")
    p.add_argument("-k", type=int, default=5)
    p.add_argument("--json", action="store_true")
    p.set_defaults(handler=_cmd_search)

    p = sub.add_parser("similar", help="functions semantically similar to the one at va")
    p.add_argument("binary")
    p.add_argument("va", type=_va)
    p.add_argument("-k", type=int, default=5)
    p.add_argument("--json", action="store_true")
    p.set_defaults(handler=_cmd_similar)


def register(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("corpus", help="semantic function corpus (build/search/similar)")
    _add_corpus_subcommands(parser)

    p = subparsers.add_parser("match", help="cross-version function match pre-screen")
    p.add_argument("old")
    p.add_argument("new")
    p.add_argument("-k", type=int, default=20)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=_dispatch, handler=_cmd_match)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rekit", description=__doc__)
    sub = parser.add_subparsers(dest="command", metavar="<command>", required=True)
    register(sub)
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except RekitError as e:
        print(f"rekit: error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
