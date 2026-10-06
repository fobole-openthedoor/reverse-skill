from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

V1_C = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void banner(void) { puts("rekit smoke fixture v1"); }

void copy_name(const char *s) {
    char b[64];
    strcpy(b, s);
    puts(b);
}

void log_fmt(const char *u) {
    char b[128];
    sprintf(b, "user=%s", u);
    puts(b);
}

void run_cmd(void) { system("/bin/echo hi"); }

void show_secret(void) {
    const char *p = "password1234";
    puts(p);
}

int main(int argc, char **argv) {
    (void)argc;
    banner();
    copy_name(argv[0]);
    log_fmt("bob");
    run_cmd();
    show_secret();
    return 0;
}
"""


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
    tmp = tempfile.mkdtemp(prefix="rekit-smoke-")
    try:
        env = dict(os.environ)
        env["REKIT_HOME"] = os.path.join(tmp, "cache")
        env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")

        src = os.path.join(tmp, "v1.c")
        with open(src, "w") as f:
            f.write(V1_C)
        v1 = os.path.join(tmp, "v1")
        v1s = os.path.join(tmp, "v1_stripped")
        subprocess.run(["gcc", "-O1", "-fno-inline", "-o", v1, src], check=True)
        subprocess.run(["gcc", "-O1", "-s", "-o", v1s, src], check=True)

        p = run(["scan", "/bin/ls"], env)
        check(p.returncode == 0, f"scan /bin/ls rc={p.returncode}: {p.stderr.strip()}")
        check("x86-64" in p.stdout, f"scan /bin/ls missing arch: {p.stdout!r}")

        p = run(["scan", v1], env)
        check(p.returncode == 0 and "built" in p.stderr, f"first scan v1: {p.stderr.strip()}")
        p = run(["scan", v1], env)
        check(p.returncode == 0 and "loaded from cache" in p.stderr, f"second scan v1: {p.stderr.strip()}")

        p = run(["strings", v1, "--query", "password"], env)
        check(p.returncode == 0 and "password1234" in p.stdout, f"strings query: {p.stdout!r}")

        p = run(["xrefs", v1, "password"], env)
        check(p.returncode == 0, f"xrefs rc={p.returncode}: {p.stderr.strip()}")
        check(re.search(r"0x[0-9a-f]{4,}", p.stdout) is not None, f"xrefs no site: {p.stdout!r}")

        fj = json.loads(run(["funcs", v1, "--json"], env).stdout)
        copy_va = next(
            (f["va"] for f in fj["functions"] if f["name"] == "copy_name" and "strcpy" in f["plt_calls"]),
            None,
        )
        check(copy_va is not None, "copy_name w/ strcpy not in funcs --json")
        tj = json.loads(run(["triage", v1, "-k", "20", "--json"], env).stdout)
        check(
            any("strcpy" in t["plt_calls"] or "system" in t["plt_calls"] for t in tj["top"]),
            "triage top-k has no strcpy/system caller",
        )
        entry = [t for t in tj["top"] if t["va"] == copy_va]
        check(entry and entry[0]["score"] > 0, f"copy_name score not > 0: {entry!r}")

        sj = json.loads(run(["funcs", v1s, "--json"], env).stdout)
        check(sj["count"] > 0, "stripped binary has no functions")
        p = run(["triage", v1s, "-k", "5"], env)
        check(p.returncode == 0, f"stripped triage rc={p.returncode}: {p.stderr.strip()}")

        main_va = next((f["va"] for f in fj["functions"] if f["name"] == "main"), None)
        check(main_va is not None, "main not found in funcs --json")
        p = run(["disasm", v1, hex(main_va), "-n", "5"], env)
        lines = [l for l in p.stdout.splitlines() if l.strip()]
        check(
            len(lines) == 5 and all(l.startswith("0x") for l in lines),
            f"disasm main -n 5 output: {p.stdout!r}",
        )
        sj_scan = json.loads(run(["scan", v1s, "--json"], env).stdout)
        p = run(["disasm", v1s, hex(sj_scan["entry"]), "-n", "5"], env)
        check(p.returncode == 0, f"stripped disasm rc={p.returncode}: {p.stderr.strip()}")

        print("OK")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
