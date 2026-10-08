"""Smoke test for the rekit residual-unknowns registry.

Run from skills/tools/rekit:  python3 tests/unknowns_smoke.py
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

REKIT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(args, env, check=True):
    proc = subprocess.run(
        [sys.executable, "-m", "rekit.findings", *args],
        cwd=REKIT_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    if check and proc.returncode != 0:
        raise AssertionError(
            f"command {args} exited {proc.returncode}\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
        )
    return proc


def show(env, uid):
    return json.loads(run(["unknown", "show", uid, "--json"], env).stdout)


def main():
    tmp = tempfile.mkdtemp(prefix="rekit-unknowns-smoke-")
    try:
        env = dict(os.environ)
        env["REKIT_FINDINGS_DB"] = os.path.join(tmp, "unknowns-a.db")

        fid = int(
            run(
                ["add", "--title", "stack buffer overflow in copy_name", "--cwe", "CWE-787"],
                env,
            ).stdout.strip()
        )

        u1 = run(
            [
                "unknown",
                "add",
                "--title",
                "does parse_header bounds-check the length field?",
                "--detail",
                "length comes straight from the packet; no clamp seen near 0x401100",
                "--binary-sha256",
                "a" * 64,
                "--finding-id",
                str(fid),
            ],
            env,
        ).stdout.strip()
        u2 = run(
            ["unknown", "add", "--title", "is the debug auth bypass reachable in release builds?"],
            env,
        ).stdout.strip()
        assert u1.startswith("unk_") and u2.startswith("unk_") and u1 != u2, (u1, u2)

        rows = json.loads(run(["unknown", "list", "--json"], env).stdout)
        assert len(rows) == 2, f"list returned {len(rows)}"
        assert show(env, u1)["finding_id"] == fid

        run(["unknown", "update", u1, "--status", "investigating", "--revision", "0"], env)
        shown = show(env, u1)
        assert shown["status"] == "investigating" and shown["revision"] == 1, shown

        proc = run(
            ["unknown", "update", u1, "--status", "blocked", "--revision", "0"],
            env,
            check=False,
        )
        assert proc.returncode == 3, f"stale update exited {proc.returncode}"
        assert "stale" in proc.stderr.lower(), proc.stderr

        proc = run(
            ["unknown", "update", u2, "--status", "contradicted", "--revision", "0"],
            env,
            check=False,
        )
        assert proc.returncode == 3, f"evidence-less contradicted exited {proc.returncode}"
        assert "evidence" in proc.stderr.lower(), proc.stderr
        run(
            [
                "unknown",
                "update",
                u2,
                "--status",
                "contradicted",
                "--revision",
                "0",
                "--evidence",
                "release build still enforces auth at 0x402000",
            ],
            env,
        )
        shown = show(env, u2)
        assert shown["status"] == "contradicted" and shown["contradiction_evidence"], shown

        proc = run(
            ["unknown", "update", u1, "--status", "resolved", "--revision", "1"],
            env,
            check=False,
        )
        assert proc.returncode == 3, f"resolution-less resolved exited {proc.returncode}"
        assert "resolution" in proc.stderr.lower(), proc.stderr
        run(
            [
                "unknown",
                "update",
                u1,
                "--status",
                "resolved",
                "--revision",
                "1",
                "--resolution",
                "length clamped at 0x40113c via min(len, 0x100)",
            ],
            env,
        )
        shown = show(env, u1)
        assert shown["status"] == "resolved" and shown["revision"] == 2, shown
        assert shown["resolution"], shown

        run(["unknown", "update", u1, "--status", "open", "--revision", "2"], env)
        shown = show(env, u1)
        assert shown["revision"] == 3, shown
        ts_before = shown["ts"]
        assert shown["updated_at"] and shown["updated_at"] != ts_before, shown

        rows = json.loads(
            run(["unknown", "list", "--json", "--status", "contradicted"], env).stdout
        )
        assert len(rows) == 1 and rows[0]["id"] == u2, rows

        proc = run(
            ["unknown", "update", "unk_0000000000000000", "--status", "open", "--revision", "0"],
            env,
            check=False,
        )
        assert proc.returncode == 3, f"missing id update exited {proc.returncode}"

        export_file = os.path.join(tmp, "export.json")
        run(["export", export_file], env)
        with open(export_file, encoding="utf-8") as fh:
            data = json.load(fh)
        assert len(data["unknowns"]) == 2, data["unknowns"]
        assert len(data["findings"]) == 1, data["findings"]

        env2 = dict(env)
        env2["REKIT_FINDINGS_DB"] = os.path.join(tmp, "unknowns-b.db")
        out = run(["import", export_file], env2).stdout.strip()
        assert out == "imported 1 findings, 2 unknowns", out
        rows = json.loads(run(["unknown", "list", "--json"], env2).stdout)
        assert len(rows) == 2, f"imported db has {len(rows)} unknowns"
        by_id = {row["id"]: row for row in rows}
        assert by_id[u2]["status"] == "contradicted", by_id[u2]
        assert by_id[u1]["revision"] == 3, by_id[u1]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
