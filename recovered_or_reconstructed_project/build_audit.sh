#!/usr/bin/env bash
# ============================================================================
# build_audit.sh — build the blue-team audit module (NRTH_audit.dll) + its CLI.
#
# This is the only part of the reconstruction that is *shipped as a working
# binary*: a read-only scanner/verifier. It has no vendor dependencies (no
# MinHook, no ImGui, no Lua), no network, no process access, so it builds from
# three files and can be reviewed as a whole:
#
#   src/nrth_audit.h         API contract + scope notes
#   src/nrth_audit_sigs.h    signature table, GENERATED from working/sigs.json
#   src/nrth_audit.cpp       implementation
#   src/nrth_audit.def       export list (names + pinned ordinals)
#   tools/nrth_audit_cli.cpp command-line front end (selftest/signatures/decode/sweep/audit)
#   tools/pe_summary.py      verifies the produced PE without objdump/dumpbin
#   tests/test_nrth_audit.cpp unit tests, run on the host before anything is cross-built
#
# Order of operations (deliberate):
#   1. host build + unit tests + module self-test   -> the code must be correct first
#   2. cross build for x86-windows-gnu (PE32, the sample's architecture)
#   3. report hashes, sizes and the export table of what was produced
#
# Flags:
#   --host        stop after step 1 (Linux/macOS binaries only)
#   --no-tests    skip step 1 (not recommended; CI uses this to save time)
#   --regen       regenerate src/nrth_audit_sigs.h from working/sigs.json first
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")"

ZIG="python3 -m ziglang"
TARGET="-target x86-windows-gnu"
CXX="${CXX:-g++}"
OUT=bin
OBJ="$OUT/audit-obj"
HOST="$OUT/host"

HOST_ONLY=0
RUN_TESTS=1
REGEN=0
for a in "$@"; do
  case "$a" in
    --host)     HOST_ONLY=1 ;;
    --no-tests) RUN_TESTS=0 ;;
    --regen)    REGEN=1 ;;
    *) echo "[!] unknown flag: $a" >&2; exit 2 ;;
  esac
done

AUDIT_SRC=(src/nrth_audit.cpp)
AUDIT_INC=(-Isrc)
WARN=(-Wall -Wextra -Werror)
STD=-std=c++17

if [ "$REGEN" = 1 ]; then
  echo "[*] Regenerating src/nrth_audit_sigs.h from the evidence catalogue..."
  python3 tools/gen_nrth_audit_sigs_h.py ../working/sigs.json src/nrth_audit_sigs.h
fi

# ---------------------------------------------------------------------------
# 1. host build: this is what actually proves the logic
# ---------------------------------------------------------------------------
mkdir -p "$HOST" "$OBJ"
if [ "$RUN_TESTS" = 1 ]; then
  command -v "$CXX" >/dev/null 2>&1 || { echo "[!] no C++ compiler (\$CXX=$CXX) for the host tests" >&2; exit 1; }
  echo "[*] Host build: unit tests + CLI ($CXX, $STD)"
  $CXX $STD -O2 "${WARN[@]}" "${AUDIT_INC[@]}" tests/test_nrth_audit.cpp "${AUDIT_SRC[@]}" -o "$HOST/test_nrth_audit"
  $CXX $STD -O2 "${WARN[@]}" "${AUDIT_INC[@]}" tools/nrth_audit_cli.cpp "${AUDIT_SRC[@]}" -o "$HOST/nrth_audit"
  echo "[*] Running the unit tests..."
  "$HOST/test_nrth_audit"
  echo "[*] Running the module self-test through the CLI..."
  "$HOST/nrth_audit" selftest
fi

if [ "$HOST_ONLY" = 1 ]; then
  echo "[+] Host build complete: $HOST/nrth_audit"
  exit 0
fi

# ---------------------------------------------------------------------------
# 2. cross build: PE32 x86, same architecture as the original NRTH.dll
# ---------------------------------------------------------------------------
command -v python3 >/dev/null 2>&1 || true
if ! $ZIG version >/dev/null 2>&1; then
  echo "[!] zig not available (\$ZIG='$ZIG'). Install it with:" >&2
  echo "    python3 -m pip install --break-system-packages ziglang" >&2
  echo "    (or run with --host to build only the host binaries)" >&2
  exit 1
fi
mkdir -p "$OUT"

echo "[*] Cross-compiling NRTH_audit.dll (x86-windows-gnu, PE32)..."
$ZIG c++ $TARGET $STD -O2 -g0 "${WARN[@]}" "${AUDIT_INC[@]}" -DNRTH_AUDIT_BUILD \
  -c src/nrth_audit.cpp -o "$OBJ/nrth_audit.o"
$ZIG c++ $TARGET -shared -o "$OUT/NRTH_audit.dll" \
  "$OBJ/nrth_audit.o" src/nrth_audit.def

echo "[*] Cross-compiling nrth_audit.exe (console CLI, same module)..."
$ZIG c++ $TARGET $STD -O2 -g0 "${WARN[@]}" "${AUDIT_INC[@]}" -DNRTH_AUDIT_STATIC \
  -o "$OUT/nrth_audit.exe" tools/nrth_audit_cli.cpp src/nrth_audit.cpp

# ---------------------------------------------------------------------------
# 3. deterministic normalisation + report
# ---------------------------------------------------------------------------
rm -f "$OUT"/*.pdb          # zig emits PDBs even with -g0; nothing here is meant to be debugged

# Zero the per-link entropy (PE TimeDateStamp, CodeView PDB GUID, build id) so the SHA-256 of the
# delivered binaries is a usable pin: two rebuilds of the same sources with the same toolchain then
# hash identically (measured 2026-10-11, BUILD_LOG.txt). No loader-visible field is recomputed and
# relocations are untouched.
if python3 tools/pe_deterministic.py "$OUT/NRTH_audit.dll" "$OUT/nrth_audit.exe"; then
  NORMALISED=1
else
  NORMALISED=0
  echo "[!] normalisation failed - hashes will move on every rebuild" >&2
fi

echo "[*] Headers + export table (dependency-free parser, no objdump/dumpbin needed):"
python3 tools/pe_summary.py "$OUT/NRTH_audit.dll" "$OUT/nrth_audit.exe" \
  | sed -n '1,200p'

echo
echo "[+] Built:"
ls -l "$OUT/NRTH_audit.dll" "$OUT/nrth_audit.exe"
sha256sum "$OUT/NRTH_audit.dll" "$OUT/nrth_audit.exe"
if [ -x "$HOST/nrth_audit" ] && [ -f ../working/NRTH.dll ]; then
  echo "[*] Regression check against the sample itself (expect 0 tamper footprints):"
  "$HOST/nrth_audit" audit ../working/NRTH.dll | sed -n '3p;/verdict/p' | sed 's/^/      /'
fi

if [ "${NORMALISED:-0}" = 1 ]; then
  echo "[*] Reproducibility: the two binaries above are normalised (timestamp/CodeView GUID/build id"
  echo "    zeroed), so re-running this script reproduces the same SHA-256 *with this toolchain*."
  echo "    A different zig/gcc version changes code bytes - then compare size + the 23 exports, and"
  echo "    re-run the unit tests and self-test, which is what actually gates the release."
else
  echo "[!] Reproducibility: NOT normalised this run, so the SHA-256 will move on every rebuild."
  echo "    Compare size + exports instead, or run: python3 tools/pe_deterministic.py $OUT/*.dll $OUT/*.exe"
fi

echo
echo "[!] Honest caveat: step 1 proves the logic on the host; the x86 binaries are"
echo "    built and their headers/exports are verified here, but they are *not* executed"
echo "    in this sandbox (no Windows). Run 'nrth_audit.exe selftest' on a Windows host"
echo "    before trusting a detection verdict from it."
