#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
PY=.venv/bin/python
[ -x "$PY" ] || { echo 'Run scripts/setup.sh first.' >&2; exit 1; }
"$PY" -m scripts.init_demo
pids=()
cleanup() { for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done; wait || true; }
trap cleanup EXIT
trap 'exit 0' INT TERM
"$PY" -m server.relay & pids+=("$!")
"$PY" -m client.app --name Alice --port 8001 & pids+=("$!")
"$PY" -m client.app --name Bob --port 8002 & pids+=("$!")
echo 'Starting Alice on port 8001, Bob on port 8002, ciphertext relay on 8765. Ctrl-C stops these processes.'
# Fail the whole demo if any required process exits, including port conflicts.
while true; do
  for pid in "${pids[@]}"; do
    if ! kill -0 "$pid" 2>/dev/null; then echo 'A demo service exited; see its startup error above.' >&2; exit 1; fi
  done
  sleep 1
done
