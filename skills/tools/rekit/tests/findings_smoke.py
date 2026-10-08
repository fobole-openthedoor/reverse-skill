"""Smoke test for the rekit findings registry.

Run from skills/tools/rekit:  python3 tests/findings_smoke.py
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


def fastembed_available():
    probe = subprocess.run(
        [sys.executable, "-c", "import fastembed"], capture_output=True
    )
    return probe.returncode == 0


def main():
    tmp = tempfile.mkdtemp(prefix="rekit-findings-smoke-")
    try:
        env = dict(os.environ)
        env["REKIT_FINDINGS_DB"] = os.path.join(tmp, "findings-a.db")

        id1 = int(
            run(
                [
                    "add",
                    "--title",
                    "stack buffer overflow in copy_name",
                    "--cwe",
                    "CWE-787",
                    "--severity",
                    "HIGH",
                    "--description",
                    "unchecked strcpy into fixed-size stack buffer",
                    "--evidence",
                    "crash at 0x401234 with 512-byte name field",
                    "--binary-sha256",
                    "a" * 64,
                    "--binary-name",
                    "victim.exe",
                    "--func-va",
                    "0x401234",
                    "--vendor",
                    "ACME",
                    "--product",
                    "widget",
                    "--version",
                    "1.0",
                ],
                env,
            ).stdout.strip()
        )
        id2 = int(
            run(
                [
                    "add",
                    "--title",
                    "sql injection in query builder",
                    "--cwe",
                    "CWE-89",
                    "--severity",
                    "MEDIUM",
                    "--description",
                    "unsanitized user input concatenated into SQL statement",
                    "--evidence",
                    "POST /search q=' OR 1=1--",
                ],
                env,
            ).stdout.strip()
        )
        assert id2 == id1 + 1, f"ids not incrementing: {id1}, {id2}"

        rows = json.loads(run(["list", "--json"], env).stdout)
        assert len(rows) == 2, f"list returned {len(rows)} rows"
        rows = json.loads(run(["list", "--json", "--cwe", "CWE-787"], env).stdout)
        assert len(rows) == 1 and rows[0]["id"] == id1, f"cwe filter wrong: {rows}"

        run(["confirm", str(id1)], env)
        rows = json.loads(run(["list", "--json", "--confirmed"], env).stdout)
        assert len(rows) == 1 and rows[0]["id"] == id1, f"confirmed filter wrong: {rows}"

        rows = json.loads(run(["search", "overflow", "--json"], env).stdout)
        assert len(rows) == 1 and rows[0]["id"] == id1, f"search wrong: {rows}"

        shown = json.loads(run(["show", str(id1), "--json"], env).stdout)
        assert shown["title"] == "stack buffer overflow in copy_name", shown
        assert shown["confirmed"] == 1, shown

        export_all = os.path.join(tmp, "all.json")
        run(["export", export_all], env)
        with open(export_all, encoding="utf-8") as fh:
            data = json.load(fh)
        assert len(data["findings"]) == 2, f"export all returned {len(data['findings'])}"
        assert all(
            "embedding" not in entry for entry in data["findings"]
        ), "export leaked embedding"
        assert data["unknowns"] == [], data["unknowns"]

        export_conf = os.path.join(tmp, "confirmed.json")
        run(["export", export_conf, "--confirmed-only"], env)
        with open(export_conf, encoding="utf-8") as fh:
            data = json.load(fh)
        conf = data["findings"]
        assert len(conf) == 1 and conf[0]["confirmed"] == 1 and conf[0]["id"] == id1, data

        env2 = dict(env)
        env2["REKIT_FINDINGS_DB"] = os.path.join(tmp, "findings-b.db")
        out = run(["import", export_all], env2).stdout.strip()
        assert out == "imported 2 findings, 0 unknowns", out
        rows = json.loads(run(["list", "--json"], env2).stdout)
        assert len(rows) == 2, f"imported db has {len(rows)} rows"

        proc = run(
            ["similar", "memory corruption in copy routine", "--json"], env, check=False
        )
        if fastembed_available():
            assert proc.returncode == 0, f"similar failed: {proc.stderr}"
            hits = json.loads(proc.stdout)
            assert hits, "similar returned no hits"
            assert hits[0]["id"] == id1, f"top hit is {hits[0]['id']}, want {id1}: {hits}"
            branch = "fastembed"
        else:
            assert proc.returncode == 3, f"similar exited {proc.returncode}, want 3"
            assert "fastembed" in proc.stderr.lower(), proc.stderr
            branch = "no-fastembed"
        print(f"similar branch: {branch}")

        run(["unconfirm", str(id1)], env)
        rows = json.loads(run(["list", "--json", "--confirmed"], env).stdout)
        assert len(rows) == 0, f"unconfirm wrong: {rows}"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
