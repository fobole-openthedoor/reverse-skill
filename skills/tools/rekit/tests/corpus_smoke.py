"""Smoke test for the rekit semantic corpus (build/search/similar/match).

Run from skills/tools/rekit:  python3 tests/corpus_smoke.py
"""

import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

import numpy as np

REKIT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

V1_C = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void banner(void) { puts("demo v1"); }

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

int cred_check(const char *pw) {
    if (strcmp(pw, "password1234") == 0) {
        puts("granted");
        return 1;
    }
    puts("denied");
    return 0;
}

int main(int argc, char **argv) {
    (void)argc;
    banner();
    copy_name(argv[0]);
    log_fmt("bob");
    run_cmd();
    cred_check("hunter2");
    return 0;
}
"""

V2_C = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void run_cmd(void) { system("/bin/echo hi"); }

void extra_noise(void) {
    for (int i = 0; i < 3; i++)
        puts("noise");
}

int cred_check(const char *pw) {
    if (strcmp(pw, "password1234") == 0) {
        puts("granted");
        return 1;
    }
    puts("denied");
    return 0;
}

void banner(void) { puts("demo v2"); }

void copy_name(const char *s) {
    char b[64];
    strncpy(b, s, sizeof(b) - 1);
    puts(b);
}

void log_fmt(const char *u) {
    char b[128];
    sprintf(b, "user=%s", u);
    puts(b);
}

int main(int argc, char **argv) {
    (void)argc;
    banner();
    copy_name(argv[0]);
    log_fmt("bob");
    run_cmd();
    cred_check("hunter2");
    extra_noise();
    return 0;
}
"""


def run(args, env, check=True):
    proc = subprocess.run(
        [sys.executable, "-m", "rekit", *args],
        cwd=REKIT_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if check and proc.returncode != 0:
        raise AssertionError(
            f"command {args} exited {proc.returncode}\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
        )
    return proc


def corpus_dirs(env):
    return glob.glob(os.path.join(env["REKIT_HOME"], "*.corpus"))


def main():
    tmp = tempfile.mkdtemp(prefix="rekit-corpus-smoke-")
    try:
        env = dict(os.environ)
        env["REKIT_HOME"] = os.path.join(tmp, "cache")
        env["PYTHONPATH"] = REKIT_ROOT + os.pathsep + env.get("PYTHONPATH", "")

        v1 = os.path.join(tmp, "v1")
        v2 = os.path.join(tmp, "v2")
        for src_name, code, out in (("v1.c", V1_C, v1), ("v2.c", V2_C, v2)):
            src = os.path.join(tmp, src_name)
            with open(src, "w") as f:
                f.write(code)
            subprocess.run(["gcc", "-O1", "-fno-inline", "-o", out, src], check=True)

        # 1. build: vectors.npy is (N, 384), N > 0
        t0 = time.monotonic()
        run(["corpus", "build", v1], env)
        first_build_s = time.monotonic() - t0
        dirs = corpus_dirs(env)
        assert len(dirs) == 1, f"expected 1 corpus dir, got {dirs}"
        vec = np.load(os.path.join(dirs[0], "vectors.npy"))
        assert vec.ndim == 2 and vec.shape[1] == 384 and vec.shape[0] > 0, f"vectors shape {vec.shape}"

        # 2. semantic search finds the strcpy copier
        hits = json.loads(run(["corpus", "search", v1, "copy user input into a stack buffer", "-k", "3", "--json"], env).stdout)
        assert hits, "search returned no hits"
        assert any(
            "strcpy" in h["text"] or "copy" in h["name"].lower() for h in hits
        ), f"top3 has no strcpy/copy function: {[(h['name'], h['score']) for h in hits]}"

        # 3. semantic search finds the system() caller
        hits = json.loads(run(["corpus", "search", v1, "run a shell command", "-k", "3", "--json"], env).stdout)
        assert any("system" in h["text"] for h in hits), f"top3 has no system caller: {[(h['name'], h['score']) for h in hits]}"

        # 4. cross-version match
        result = json.loads(run(["match", v1, v2, "--json"], env).stdout)
        pairs = result["pairs"]
        assert pairs, "match returned no pairs"
        for rec in pairs:
            for field in ("s_struct", "s_sem", "final", "confidence", "alts"):
                assert field in rec, f"pair missing field {field}: {rec}"
        v2_dirs = [d for d in corpus_dirs(env) if d != dirs[0]]
        assert len(v2_dirs) == 1, f"expected v2 corpus dir, got {v2_dirs}"
        with open(os.path.join(v2_dirs[0], "profiles.json"), encoding="utf-8") as f:
            v2_profiles = {p["va"]: p for p in json.load(f)}
        cp = next((r for r in pairs if r["old_name"] == "copy_name"), None)
        assert cp is not None and cp["new_va"] is not None, "copy_name has no match candidate"
        new_prof = v2_profiles[cp["new_va"]]
        assert "strncpy" in new_prof["calls"], (
            f"copy_name matched {new_prof['name']} with calls {new_prof['calls']}, want strncpy"
        )
        bn = next((r for r in pairs if r["old_name"] == "banner"), None)
        assert bn is not None and bn["new_name"] == "banner", f"banner best match: {bn}"
        assert bn["confidence"] in ("HIGH", "MEDIUM"), f"banner confidence {bn['confidence']}: {bn}"

        # 5. second build hits the cache
        t0 = time.monotonic()
        p = run(["corpus", "build", v1], env)
        cached_s = time.monotonic() - t0
        assert "loaded corpus from cache" in p.stderr or cached_s < first_build_s / 2, (
            f"second build not cached (stderr={p.stderr!r}, {cached_s:.1f}s vs first {first_build_s:.1f}s)"
        )
        print(f"timings: first build {first_build_s:.1f}s, cached build {cached_s:.1f}s")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
