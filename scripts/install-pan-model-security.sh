#!/usr/bin/env bash
# Install Palo Alto AI Model Security CLI/SDK from your tenant PyPI index.
# Set MODEL_SECURITY_PYPI_URL to the URL returned by SCM mgmt/v1/pypi/authenticate, or put it in
# config/model-security.env / .env / model-security.env, or run: .venv/bin/python scripts/fetch-pan-pypi-url.py
#
#   source .venv/bin/activate
#   ./scripts/install-pan-model-security.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [[ -n "${VIRTUAL_ENV:-}" ]]; then
  PY="$VIRTUAL_ENV/bin/python"
  PIP=(python -m pip)
else
  PY="${PYTHON:-python3}"
  PIP=("$PY" -m pip)
fi

if [[ -z "${MODEL_SECURITY_PYPI_URL:-}" ]]; then
  MODEL_SECURITY_PYPI_URL="$("$PY" -c "
from pathlib import Path
try:
    from dotenv import dotenv_values
except ImportError:
    raise SystemExit('')
for p in (
    Path('config/model-security.env'),
    Path('.env'),
    Path('model-security.env'),
):
    if not p.is_file():
        continue
    url = (dotenv_values(p).get('MODEL_SECURITY_PYPI_URL') or '').strip()
    if url:
        print(url, end='')
        raise SystemExit(0)
" 2>/dev/null || true)"
fi

if [[ -z "${MODEL_SECURITY_PYPI_URL:-}" ]]; then
  echo "MODEL_SECURITY_PYPI_URL is not set." >&2
  echo "Get the URL from Strata Cloud Manager (mgmt/v1/pypi/authenticate) and either export it," >&2
  echo "or add MODEL_SECURITY_PYPI_URL=... to config/model-security.env (copy from config/model-security.env.example)." >&2
  exit 1
fi

exec "${PIP[@]}" install "model-security-client[all]" --extra-index-url "$MODEL_SECURITY_PYPI_URL"
