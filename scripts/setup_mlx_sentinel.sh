#!/bin/zsh
set -euo pipefail

ROOT="${0:A:h:h}"
VENV="$ROOT/.venv"
PYTHON="${MLX_SENTINEL_PYTHON:-}"

if [[ -z "$PYTHON" ]]; then
  if command -v uv >/dev/null 2>&1; then
    PYTHON="$(uv python find 3.12 2>/dev/null || true)"
  fi
fi
if [[ -z "$PYTHON" ]]; then
  PYTHON="$(command -v python3.12 2>/dev/null || true)"
fi
if [[ -z "$PYTHON" ]]; then
  echo "Python 3.12 is required. Install it with Homebrew or set MLX_SENTINEL_PYTHON." >&2
  exit 1
fi

if [[ ! -x "$VENV/bin/python" ]]; then
  echo "Creating $VENV with $PYTHON"
  "$PYTHON" -m venv "$VENV"
fi

"$VENV/bin/python" -m pip install --upgrade pip
"$VENV/bin/python" -m pip install -e "$ROOT"
echo "MLX Sentinel is ready. Activate with: source $VENV/bin/activate"
echo "Run diagnostics with: $VENV/bin/mlx-sentinel-doctor"
