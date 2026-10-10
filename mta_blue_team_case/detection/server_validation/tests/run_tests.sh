#!/usr/bin/env bash
# Run the nrth_guard tests off-server.
# Interpreter probe: Lua 5.1/5.2+/JIT if present, otherwise Python+lupa (pip).
# Logs are written to ../../test_results/server_guard_tests.log by the caller:
#   bash run_tests.sh 2>&1 | tee ../../test_results/server_guard_tests.log
set -uo pipefail
cd "$(dirname "$0")/.."           # -> nrth_guard resource root (tests use it as `here`)
ROOT="$(pwd)"
TESTS="$ROOT/tests"
cd "$TESTS/.."

LUA=""
for c in lua5.1 lua luajit; do
  if command -v "$c" >/dev/null 2>&1; then LUA="$c"; break; fi
done

if [ -z "$LUA" ]; then
  PY=python3
  if ! $PY -c "import lupa" >/dev/null 2>&1; then
    echo "[*] no lua interpreter; creating a venv with lupa (PyPI)..."
    python3 -m venv /tmp/luaenv >/dev/null 2>&1 || true
    /tmp/luaenv/bin/pip install -q lupa >/dev/null 2>&1 || { echo "[!] could not provision a Lua runtime"; exit 2; }
    PY=/tmp/luaenv/bin/python
  fi
  RUNNER="$TESTS/lua_runner.py"
  rc=0
  for t in test_guard.lua test_main_integration.lua; do
    echo "--- $t"
    $PY "$RUNNER" "$TESTS/$t" "$ROOT" || rc=1
  done
  exit $rc
fi

rc=0
for t in test_guard.lua test_main_integration.lua; do
  echo "--- $t"
  "$LUA" "$TESTS/$t" "$ROOT" || rc=1
done
exit $rc
