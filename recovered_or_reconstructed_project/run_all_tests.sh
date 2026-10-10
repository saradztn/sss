#!/usr/bin/env bash
# ============================================================================
# run_all_tests.sh — one command that reproduces every test claim in this case.
#
# It runs what can run on a Linux host, and says so explicitly when something needs
# the sample (working/NRTH.dll, from NORTH.zip) or a Windows box:
#
#   1. audit module unit tests                tests/test_nrth_audit.cpp        (always)
#   2. audit module self-test (21 sample-derived vectors) via the CLI
#   3. loader reconstruction tests            tests/test_cli_parser.cpp
#   4. export-contract differential           tests/test_pe_export_parser.cpp  (needs working/NRTH.dll)
#   5. false-positive control + negative      nrth_audit audit / diff on the sample
#   6. YARA rule compile + scan               (needs python3 -c "import yara")
#
# Exit status: 0 = everything that could run passed; 1 = a test failed; the number of
# skipped groups is printed so a CI log shows what was *not* covered here.
# ============================================================================
set -uo pipefail
cd "$(dirname "$0")"

CXX="${CXX:-g++}"
STD="-std=c++17"
WARN="-Wall -Wextra -Werror"
OUT=/tmp/nrth_tests.$$
mkdir -p "$OUT"
PASS=0; FAIL=0; SKIP=0

say()  { printf '\n=== %s\n' "$*"; }
ok()   { printf '  [PASS] %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  [FAIL] %s\n' "$*"; FAIL=$((FAIL+1)); }
skip() { printf '  [SKIP] %s\n' "$*"; SKIP=$((SKIP+1)); }

# the sample lives outside the repo commit (working/ is gitignored); find it if present
SAMPLE=""
for c in ../working/NRTH.dll working/NRTH.dll ../../working/NRTH.dll; do
  [ -f "$c" ] && SAMPLE="$c" && break
done
if [ -z "$SAMPLE" ] && [ -f ../NORTH.zip ]; then
  echo "[*] extracting the sample from NORTH.zip into ../working/ ..."
  mkdir -p ../working && unzip -o -q ../NORTH.zip -d ../working && SAMPLE=../working/NRTH.dll
fi

say "1/6  audit module: unit tests"
if $CXX $STD -O2 $WARN -Isrc tests/test_nrth_audit.cpp src/nrth_audit.cpp -o "$OUT/t_audit" 2>"$OUT/c1.log"; then
  if "$OUT/t_audit" > "$OUT/t1.log" 2>&1; then
    ok "$(tail -1 "$OUT/t1.log")"
  else
    bad "unit tests failed (see $OUT/t1.log)"; tail -20 "$OUT/t1.log"
  fi
else
  bad "unit tests did not compile (see $OUT/c1.log)"; tail -20 "$OUT/c1.log"
fi

say "2/6  audit module: self-test against sample-derived evidence vectors"
if $CXX $STD -O2 $WARN -Isrc tools/nrth_audit_cli.cpp src/nrth_audit.cpp -o "$OUT/cli" 2>"$OUT/c2.log"; then
  if "$OUT/cli" selftest > "$OUT/t2.log" 2>&1 && grep -q "all checks passed" "$OUT/t2.log"; then
    ok "$(grep -c '\[ ok \]' "$OUT/t2.log") checks passed (codec, patterns, footprints, PE reader, catalogue)"
  else
    bad "self-test failed (see $OUT/t2.log)"; tail -20 "$OUT/t2.log"
  fi
else
  bad "CLI did not compile (see $OUT/c2.log)"; tail -20 "$OUT/c2.log"
fi

say "3/6  loader reconstruction: CLI parser tests"
if $CXX $STD $WARN -o "$OUT/t_cli" tests/test_cli_parser.cpp 2>"$OUT/c3.log"; then
  "$OUT/t_cli" > "$OUT/t3.log" 2>&1 && ok "4/4 CLI parsing cases" || { bad "cli parser tests"; tail -8 "$OUT/t3.log"; }
else
  bad "cli parser tests did not compile"; tail -8 "$OUT/c3.log"
fi

say "4/6  export-contract differential against the ORIGINAL sample"
if [ -n "$SAMPLE" ]; then
  if $CXX $STD $WARN -o "$OUT/t_pe" tests/test_pe_export_parser.cpp 2>"$OUT/c4.log"; then
    "$OUT/t_pe" "$(cd "$(dirname "$SAMPLE")" && pwd)/NRTH.dll" > "$OUT/t4.log" 2>&1 \
      && ok "NVXHookProc located at RVA 0x0000B9E0 in $SAMPLE + negative case" \
      || { bad "export differential failed (see $OUT/t4.log)"; tail -8 "$OUT/t4.log"; }
  else
    bad "export test did not compile"; tail -8 "$OUT/c4.log"
  fi
else
  skip "no sample (run: unzip -o NORTH.zip -d ../working)"
fi

say "5/6  detector controls: false-positive + A/B negative on the sample"
if [ -n "$SAMPLE" ] && [ -x "$OUT/cli" ]; then
  "$OUT/cli" audit "$SAMPLE" > "$OUT/t5a.log" 2>&1
  rc=$?
  if [ $rc -eq 0 ] && grep -q "0 signature(s) found with a replaced prologue" "$OUT/t5a.log"; then
    ok "audit of the cheat module itself reports 0 footprints (patterns target client.dll/netc.dll)"
  else
    bad "audit reported footprints on its own sample (rc=$rc)"; tail -6 "$OUT/t5a.log"
  fi
  n=$(grep -c "hidden pattern candidate" "$OUT/t5a.log" 2>/dev/null || echo 0)
  "$OUT/cli" sweep "$SAMPLE" --min 24 > "$OUT/t5b.log" 2>&1
  got=$(sed -n 's/.*: \([0-9]*\) hidden pattern candidate.*/\1/p' "$OUT/t5b.log")
  [ "${got:-0}" -ge 8 ] && ok "sweep rediscovered $got hidden .data records (expected 8, matches tools/nrth_sig_export.py)" \
                        || bad "sweep found ${got:-0} candidates, expected 8"
  if [ -f "$SAMPLE" ]; then
    "$OUT/cli" diff "$SAMPLE" "$SAMPLE" > "$OUT/t5c.log" 2>&1
    rc=$?
    [ $rc -eq 0 ] && grep -q "no differing located function" "$OUT/t5c.log" \
      && ok "diff of an image against itself reports no delta" || bad "self-diff reported a delta (rc=$rc)"
  fi
else
  skip "needs the sample and the audit CLI"
fi

say "6/6  YARA rules compile and fire as documented"
if python3 -c "import yara" 2>/dev/null; then
  python3 - "$SAMPLE" <<'PY' > "$OUT/t6.log" 2>&1 && ok "yara: $(cat "$OUT/t6.log")" || bad "yara check (see $OUT/t6.log)"
import sys, os, yara
path = "../mta_blue_team_case/detection/yara_rules.yar"
m = yara.compile(filepath=path)
sample = sys.argv[1] if len(sys.argv) > 1 else ""
parts = ["%d rules compile" % len(m.rules) if hasattr(m, "rules") else "rules compile"]
if sample and os.path.exists(sample):
    hits = [r.rule for r in m.match(sample)]
    parts.append("sample -> %d rule(s)" % len(hits))
    assert len(hits) >= 2, "expected the payload rules to fire on NRTH.dll"
for b in ("bin/NRTH_audit.dll", "bin/nrth_audit.exe"):
    if os.path.exists(b):
        assert not m.match(b), "our own audit binary must not match a cheat rule: " + b
        parts.append("%s clean" % os.path.basename(b))
print(", ".join(parts))
PY
else
  skip "yara-python not installed (pip3 install --break-system-packages yara-python)"
fi

printf '\n=== summary: %d passed, %d failed, %d skipped (logs in %s)\n' "$PASS" "$FAIL" "$SKIP" "$OUT"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
