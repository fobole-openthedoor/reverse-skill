#!/bin/sh
# install.sh — rekit installer (Linux / macOS / Kali)
#
# Steps:
#   1. install the optional fastembed dependency (pip --user)
#   2. write the ~/.local/bin/rekit shim pointing at this repo's rekit package
#   3. pre-download the embedding model (best effort)
#   4. verify with `rekit --version`
# Idempotent: safe to re-run; an existing shim is overwritten.

set -eu

REKIT_DIR="$(cd "$(dirname "$0")" && pwd)"
SHIM_DIR="$HOME/.local/bin"
SHIM="$SHIM_DIR/rekit"
FASTEMBED_PIN="fastembed==0.8.1"
ERR_LOG="$(mktemp "${TMPDIR:-/tmp}/rekit-pip.XXXXXX")"
trap 'rm -f "$ERR_LOG"' EXIT

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 (3.10+) is required but not on PATH" >&2
    exit 1
fi

echo "rekit dir: $REKIT_DIR"

pip_install_fastembed() {
    if python3 -m pip install --user --break-system-packages "$FASTEMBED_PIN" 2>"$ERR_LOG"; then
        return 0
    fi
    if grep -q "no such option" "$ERR_LOG" 2>/dev/null; then
        echo "fastembed: pip does not know --break-system-packages, retrying without it"
        python3 -m pip install --user "$FASTEMBED_PIN"
        return
    fi
    cat "$ERR_LOG" >&2
    return 1
}

# 1. optional fastembed (required by corpus build/search/similar, match, findings similar)
if python3 -c "import fastembed" 2>/dev/null; then
    echo "fastembed: already installed"
elif ! pip_install_fastembed; then
    echo "warn: fastembed install failed — corpus/match/findings-similar will be unavailable" >&2
fi

# 2. shim
mkdir -p "$SHIM_DIR"
cat > "$SHIM" <<EOF
#!/bin/sh
export PYTHONPATH="$REKIT_DIR\${PYTHONPATH:+:\$PYTHONPATH}"
exec python3 -m rekit "\$@"
EOF
chmod +x "$SHIM"
echo "shim: $SHIM"

# 3. embedding model pre-download (best effort; first use downloads it anyway)
python3 -c "from fastembed import TextEmbedding; TextEmbedding('BAAI/bge-small-en-v1.5')" >/dev/null 2>&1 \
    || echo "warn: model pre-download skipped (offline?)"

# 4. PATH hint + verification
case ":$PATH:" in
    *":$SHIM_DIR:"*) ;;
    *) echo "note: $SHIM_DIR is not on PATH — add it with: export PATH=\"$SHIM_DIR:\$PATH\"" ;;
esac

echo "== rekit --version =="
"$SHIM" --version
echo "rekit installed OK"
