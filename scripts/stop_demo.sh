#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
[ -x .venv/bin/python ] || { echo 'No project virtual environment found.' >&2; exit 1; }
exec .venv/bin/python -m scripts.demo stop
