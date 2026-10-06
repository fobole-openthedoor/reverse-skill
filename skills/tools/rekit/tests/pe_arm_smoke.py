from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rekit.binctx import BinaryContext  # noqa: E402

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

MINGW = "x86_64-w64-mingw32-gcc"
A64_GCC = "aarch64-linux-gnu-gcc"


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
    tmp = tempfile.mkdtemp(prefix="rekit-pe-arm-")
    try:
        env = dict(os.environ)
        env["REKIT_HOME"] = os.path.join(tmp, "cache")
        env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")
        os.environ["REKIT_HOME"] = env["REKIT_HOME"]

        src = os.path.join(tmp, "v1.c")
        with open(src, "w") as f:
            f.write(V1_C)
        pe = os.path.join(tmp, "pe_v1.exe")
        pes = os.path.join(tmp, "pe_v1_stripped.exe")
        a64 = os.path.join(tmp, "arm64_v1")
        subprocess.run([MINGW, "-O1", "-fno-inline", "-o", pe, src], check=True)
        subprocess.run([MINGW, "-O1", "-s", "-o", pes, src], check=True)
        subprocess.run([A64_GCC, "-O1", "-fno-inline", "-o", a64, src], check=True)

        p = run(["scan", pe], env)
        check(p.returncode == 0, f"scan pe rc={p.returncode}: {p.stderr.strip()}")
        check("x86-64" in p.stdout, f"scan pe missing arch: {p.stdout!r}")
        ctx = BinaryContext.load_or_build(pe)
        check(ctx.format == "pe", f"format: {ctx.format!r}")
        check(len(ctx.func_starts) > 0, "pe: no functions")
        check(len(ctx.plt) > 0, "pe: no imports")

        p = run(["scan", pe], env)
        check(p.returncode == 0 and "loaded from cache" in p.stderr, f"pe cache: {p.stderr.strip()}")

        tj = json.loads(run(["triage", pe, "-k", "30", "--json"], env).stdout)
        hit = [t for t in tj["top"] if "strcpy" in t["plt_calls"] and t["score"] > 0]
        check(bool(hit), f"pe triage: no strcpy caller with score>0 in top: {tj['top'][:3]!r}")

        p = run(["strings", pe, "--query", "password"], env)
        check(p.returncode == 0 and "password1234" in p.stdout, f"pe strings: {p.stdout!r}")
        p = run(["xrefs", pe, "password"], env)
        check(
            p.returncode == 0 and re.search(r"0x[0-9a-f]{4,}", p.stdout) is not None,
            f"pe xrefs: {p.stdout!r}",
        )

        sctx = BinaryContext.load_or_build(pes)
        check(len(sctx.func_starts) > 0, "stripped pe: no functions (.pdata fallback failed)")
        sj = json.loads(run(["funcs", pes, "--json"], env).stdout)
        check(sj["count"] > 0, "stripped pe: funcs --json empty")

        actx = BinaryContext.load_or_build(a64)
        check(actx.format == "elf" and actx.arch == "arm64", f"arm64: {actx.format}/{actx.arch}")
        check(len(actx.func_starts) > 0, "arm64: no functions")
        p = run(["strings", a64, "--query", "password"], env)
        check("password1234" in p.stdout, f"arm64 strings: {p.stdout!r}")
        p = run(["xrefs", a64, "password"], env)
        check(
            p.returncode == 0 and re.search(r"0x[0-9a-f]{4,}", p.stdout) is not None,
            f"arm64 xrefs: {p.stdout!r} {p.stderr!r}",
        )

        print("OK")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
