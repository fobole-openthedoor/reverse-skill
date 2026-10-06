"""Findings registry: structured vulnerability findings store backed by SQLite."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from typing import Any, Sequence

import numpy as np

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
EMBED_MODEL = "BAAI/bge-small-en-v1.5"
EMBED_TEXT_LIMIT = 500

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  vendor TEXT, product TEXT, version TEXT,
  binary_sha256 TEXT, binary_name TEXT,
  func_va TEXT,
  cwe TEXT,
  severity TEXT NOT NULL CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
  title TEXT NOT NULL,
  description TEXT,
  evidence TEXT,
  confirmed INTEGER NOT NULL DEFAULT 0,
  embedding BLOB
);
CREATE INDEX IF NOT EXISTS idx_findings_cwe ON findings(cwe);
CREATE INDEX IF NOT EXISTS idx_findings_binary ON findings(binary_sha256);
CREATE INDEX IF NOT EXISTS idx_findings_confirmed ON findings(confirmed);
"""

INSERT_SQL = """
INSERT INTO findings
  (ts, vendor, product, version, binary_sha256, binary_name, func_va, cwe,
   severity, title, description, evidence, confirmed, embedding)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

FIELDS = (
    "id",
    "ts",
    "vendor",
    "product",
    "version",
    "binary_sha256",
    "binary_name",
    "func_va",
    "cwe",
    "severity",
    "title",
    "description",
    "evidence",
    "confirmed",
)

_embedder: Any = None


def _db_path() -> str:
    return os.environ.get(
        "REKIT_FINDINGS_DB",
        os.path.join(os.path.expanduser("~"), ".local", "share", "rekit", "findings.db"),
    )


def _connect() -> sqlite3.Connection:
    path = _db_path()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _embed_text(title: str, cwe: str | None, description: str | None) -> str:
    return f"{title}. {cwe or ''} {description or ''}"[:EMBED_TEXT_LIMIT]


def _load_embedder() -> Any:
    global _embedder
    if _embedder is None:
        from fastembed import TextEmbedding

        _embedder = TextEmbedding(model_name=EMBED_MODEL)
    return _embedder


def _embed_blob(text: str) -> bytes:
    vec = next(iter(_load_embedder().embed([text])))
    return np.asarray(vec, dtype="<f4").tobytes()


def _try_embed_blob(text: str) -> bytes | None:
    try:
        return _embed_blob(text)
    except Exception:
        return None


def _public_row(row: sqlite3.Row) -> dict[str, Any]:
    return {key: row[key] for key in FIELDS}


def _print_table(rows: list[sqlite3.Row]) -> None:
    if not rows:
        print("(no findings)")
        return
    print(f"{'ID':>4}  {'SEVERITY':<8}  {'CWE':<10}  {'C':<1}  {'TS':<19}  TITLE")
    for row in rows:
        mark = "Y" if row["confirmed"] else "-"
        print(
            f"{row['id']:>4}  {row['severity']:<8}  {(row['cwe'] or '-'):<10}  "
            f"{mark:<1}  {row['ts']:<19}  {row['title']}"
        )


def _cmd_add(args: argparse.Namespace) -> int:
    blob = _try_embed_blob(_embed_text(args.title, args.cwe, args.description))
    conn = _connect()
    with conn:
        cur = conn.execute(
            INSERT_SQL,
            (
                _utc_now(),
                args.vendor,
                args.product,
                args.version,
                args.binary_sha256,
                args.binary_name,
                args.func_va,
                args.cwe,
                args.severity,
                args.title,
                args.description,
                args.evidence,
                0,
                blob,
            ),
        )
    print(cur.lastrowid)
    conn.close()
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    clauses: list[str] = []
    params: list[str] = []
    if args.confirmed:
        clauses.append("confirmed = 1")
    if args.cwe:
        clauses.append("cwe = ?")
        params.append(args.cwe)
    if args.binary_sha256:
        clauses.append("binary_sha256 = ?")
        params.append(args.binary_sha256)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = _connect().execute(f"SELECT * FROM findings{where} ORDER BY id", params).fetchall()
    if args.json:
        print(json.dumps([_public_row(row) for row in rows], indent=2))
    else:
        _print_table(rows)
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    row = _connect().execute("SELECT * FROM findings WHERE id = ?", (args.id,)).fetchone()
    if row is None:
        print(f"finding {args.id} not found", file=sys.stderr)
        return 3
    if args.json:
        print(json.dumps(_public_row(row), indent=2))
    else:
        for key in FIELDS:
            print(f"{key}: {row[key]}")
        blob = row["embedding"]
        print(f"embedding: {len(blob) // 4}d float32" if blob else "embedding: (none)")
    return 0


def _set_confirmed(fid: int, value: int) -> int:
    conn = _connect()
    with conn:
        cur = conn.execute("UPDATE findings SET confirmed = ? WHERE id = ?", (value, fid))
    if cur.rowcount == 0:
        print(f"finding {fid} not found", file=sys.stderr)
        return 3
    print(f"{'confirmed' if value else 'unconfirmed'} {fid}")
    return 0


def _cmd_confirm(args: argparse.Namespace) -> int:
    return _set_confirmed(args.id, 1)


def _cmd_unconfirm(args: argparse.Namespace) -> int:
    return _set_confirmed(args.id, 0)


def _like_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _cmd_search(args: argparse.Namespace) -> int:
    pat = f"%{_like_escape(args.text)}%"
    rows = (
        _connect()
        .execute(
            "SELECT * FROM findings WHERE title LIKE ? ESCAPE '\\'"
            " OR description LIKE ? ESCAPE '\\' OR evidence LIKE ? ESCAPE '\\' ORDER BY id",
            (pat, pat, pat),
        )
        .fetchall()
    )
    if args.json:
        print(json.dumps([_public_row(row) for row in rows], indent=2))
    else:
        _print_table(rows)
    return 0


def _cmd_similar(args: argparse.Namespace) -> int:
    try:
        embedder = _load_embedder()
    except ImportError:
        print("fastembed is required for `similar`: pip install fastembed", file=sys.stderr)
        return 3
    except Exception as exc:
        print(f"cannot load embedding model {EMBED_MODEL}: {exc}", file=sys.stderr)
        return 3
    rows = (
        _connect()
        .execute("SELECT * FROM findings WHERE embedding IS NOT NULL ORDER BY id")
        .fetchall()
    )
    if not rows:
        print("no embeddings yet", file=sys.stderr)
        return 3
    try:
        vec = next(iter(embedder.embed([args.text[:EMBED_TEXT_LIMIT]])))
        query = np.asarray(vec, dtype="<f4")
        mat = np.stack([np.frombuffer(row["embedding"], dtype="<f4") for row in rows])
        denom = np.maximum(np.linalg.norm(mat, axis=1) * np.linalg.norm(query), 1e-12)
        scores = (mat @ query) / denom
    except Exception as exc:
        print(f"similarity failed: {exc}", file=sys.stderr)
        return 3
    order = np.argsort(-scores, kind="stable")[: max(args.k, 0)]
    results = [
        {
            "id": int(rows[i]["id"]),
            "score": round(float(scores[i]), 6),
            "severity": rows[i]["severity"],
            "cwe": rows[i]["cwe"],
            "title": rows[i]["title"],
        }
        for i in order
    ]
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for hit in results:
            print(
                f"{hit['score']:.4f}  #{hit['id']:<4}  {hit['severity']:<8}  "
                f"{(hit['cwe'] or '-'):<10}  {hit['title']}"
            )
    return 0


def _cmd_export(args: argparse.Namespace) -> int:
    sql = "SELECT * FROM findings"
    if args.confirmed_only:
        sql += " WHERE confirmed = 1"
    rows = _connect().execute(f"{sql} ORDER BY id").fetchall()
    data = [_public_row(row) for row in rows]
    with open(args.file, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
    print(f"exported {len(data)}")
    return 0


def _cmd_import(args: argparse.Namespace) -> int:
    try:
        with open(args.file, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"cannot read {args.file}: {exc}", file=sys.stderr)
        return 3
    if not isinstance(data, list):
        print(f"{args.file}: top-level JSON array expected", file=sys.stderr)
        return 3
    conn = _connect()
    count = 0
    try:
        with conn:
            for entry in data:
                if not isinstance(entry, dict) or not entry.get("title"):
                    raise ValueError("every entry needs a non-empty title")
                severity = entry.get("severity") or "INFO"
                if severity not in SEVERITIES:
                    raise ValueError(f"invalid severity {severity!r}")
                blob = _try_embed_blob(
                    _embed_text(entry["title"], entry.get("cwe"), entry.get("description"))
                )
                conn.execute(
                    INSERT_SQL,
                    (
                        entry.get("ts") or _utc_now(),
                        entry.get("vendor"),
                        entry.get("product"),
                        entry.get("version"),
                        entry.get("binary_sha256"),
                        entry.get("binary_name"),
                        entry.get("func_va"),
                        entry.get("cwe"),
                        severity,
                        entry["title"],
                        entry.get("description"),
                        entry.get("evidence"),
                        1 if entry.get("confirmed") else 0,
                        blob,
                    ),
                )
                count += 1
    except (ValueError, sqlite3.Error) as exc:
        print(f"import failed: {exc}", file=sys.stderr)
        return 3
    print(f"imported {count}")
    return 0


def _dispatch(args: argparse.Namespace) -> int:
    try:
        return args.handler(args)
    except (sqlite3.Error, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3


def _add_subcommands(parser: argparse.ArgumentParser) -> None:
    parser.set_defaults(func=_dispatch)
    sub = parser.add_subparsers(dest="command", metavar="<command>", required=True)

    p = sub.add_parser("add", help="add a finding")
    p.add_argument("--title", required=True)
    p.add_argument("--vendor")
    p.add_argument("--product")
    p.add_argument("--version")
    p.add_argument("--binary-sha256")
    p.add_argument("--binary-name")
    p.add_argument("--func-va")
    p.add_argument("--cwe")
    p.add_argument("--severity", choices=SEVERITIES, default="INFO")
    p.add_argument("--description")
    p.add_argument("--evidence")
    p.set_defaults(handler=_cmd_add)

    p = sub.add_parser("list", help="list findings")
    p.add_argument("--confirmed", action="store_true")
    p.add_argument("--cwe")
    p.add_argument("--binary-sha256")
    p.add_argument("--json", action="store_true")
    p.set_defaults(handler=_cmd_list)

    p = sub.add_parser("show", help="show one finding")
    p.add_argument("id", type=int)
    p.add_argument("--json", action="store_true")
    p.set_defaults(handler=_cmd_show)

    for name, handler in (("confirm", _cmd_confirm), ("unconfirm", _cmd_unconfirm)):
        p = sub.add_parser(name, help=f"{name} a finding")
        p.add_argument("id", type=int)
        p.set_defaults(handler=handler)

    p = sub.add_parser("search", help="substring search in title/description/evidence")
    p.add_argument("text")
    p.add_argument("--json", action="store_true")
    p.set_defaults(handler=_cmd_search)

    p = sub.add_parser("similar", help="embedding cosine top-k")
    p.add_argument("text")
    p.add_argument("-k", type=int, default=5)
    p.add_argument("--json", action="store_true")
    p.set_defaults(handler=_cmd_similar)

    p = sub.add_parser("export", help="export findings to a JSON array")
    p.add_argument("file")
    p.add_argument("--confirmed-only", action="store_true")
    p.set_defaults(handler=_cmd_export)

    p = sub.add_parser("import", help="import findings from a JSON array")
    p.add_argument("file")
    p.set_defaults(handler=_cmd_import)


def register(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("findings", help="findings registry (SQLite)")
    _add_subcommands(parser)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rekit findings", description=__doc__)
    _add_subcommands(parser)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
