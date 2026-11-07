#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
bash scripts/setup_crypto.sh
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m scripts.diagnose
.venv/bin/python -m scripts.init_demo
