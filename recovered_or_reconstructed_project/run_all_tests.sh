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
#   3b. config record (menu_key / no_spoofer)  tests/test_nrth_config.cpp
#   4. export-contract differential           tests/test_pe_export_parser.cpp  (needs working/NRTH.dll)
#   5. false-positive control + negative      nrth_audit audit / diff on the sample,
#      + report-path health check             tools/nrth_report_path_check.py (fixture + payload),
#      + deliverable hygiene    bin/NRTH_audit.dll free of per-link entropy
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

say "3b/6  config record (loader_config.cfg tokens) unit tests"
if $CXX $STD -O2 $WARN -Isrc tests/test_nrth_config.cpp src/nrth_config.cpp -o "$OUT/t_cfg" 2>"$OUT/c3b.log"; then
  if "$OUT/t_cfg" > "$OUT/t3b.log" 2>&1; then
    ok "$(tail -1 "$OUT/t3b.log") ($(grep -c '\[ ok \]' "$OUT/t3b.log") checks: format strings, tolerance, failure codes, VK names)"
  else
    bad "config tests failed (see $OUT/t3b.log)"; tail -20 "$OUT/t3b.log"
  fi
else
  bad "config tests did not compile (see $OUT/c3b.log)"; tail -20 "$OUT/c3b.log"
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
    if [ $rc -eq 0 ] && grep -q "no differing located function" "$OUT/t5c.log"; then
      # cross-build control: our reconstruction is a *different* build of the same module, so the
      # diff must stay silent (it may mention an unlocated footprint, never an alert).  This is the
      # regression test for the alignment rule added in 1.2.0.
      if [ -f bin/NRTH.dll ]; then
        "$OUT/cli" diff "$SAMPLE" bin/NRTH.dll > "$OUT/t5d.log" 2>&1
        rc2=$?
        if [ $rc2 -eq 0 ] && grep -q "verdict: 0 located function(s)" "$OUT/t5d.log"; then
          ok "self-diff and cross-build diff report no tamper alert (bin/NRTH.dll)"
        else
          bad "cross-build diff alerted (rc=$rc2) - alignment rule broken?"
        fi
      else
        ok "diff of an image against itself reports no delta (no local build for the A/B case)"
      fi
    else
      bad "self-diff reported a delta (rc=$rc)"
    fi
  if [ -f bin/NRTH_audit.dll ]; then
    if python3 tools/pe_deterministic.py --check bin/NRTH_audit.dll > "$OUT/t5e.log" 2>&1; then
      ok "delivered DLL is hash-pinnable (no timestamp / CodeView GUID / build id left)"
    else
      bad "bin/NRTH_audit.dll still carries per-link entropy - run tools/pe_deterministic.py"
    fi
  else
    skip "no bin/NRTH_audit.dll to check for per-link entropy (run ./build_audit.sh)"
  fi
  # positive control for the ALERT path: a fixture image carrying exactly the bytes the sample's
  # writer leaves behind (6 x one-byte C3 kill + 4 x E9 near detour, from the observed netc.dll
  # cluster) must produce that alert count and nothing else.  Generated, never committed:
  # tools/nrth_netc_fixture.py reads src/nrth_audit_sigs.h, so the control cannot drift from the table.
  if python3 tools/nrth_netc_fixture.py --out-dir "$OUT" > "$OUT/t5f.log" 2>&1; then
    vpr=$("$OUT/cli" audit "$OUT/fixture_netc_pristine.dll" | sed -n 's/.*verdict: \([0-9]*\) signature.*/\1/p')
    "$OUT/cli" audit "$OUT/fixture_netc_pristine.dll" > /dev/null 2>&1; vrc=$?
    vkil=$("$OUT/cli" audit "$OUT/fixture_netc_killed.dll" | sed -n 's/.*verdict: \([0-9]*\) signature.*/\1/p')
    "$OUT/cli" diff "$OUT/fixture_netc_pristine.dll" "$OUT/fixture_netc_killed.dll" \
        --csv "$OUT/t5f.csv" > "$OUT/t5f.diff" 2>&1; drc=$?
    vdf=$(sed -n 's/.*verdict: \([0-9]*\) located.*/\1/p' "$OUT/t5f.diff")
    nrow=$(( $(grep -c . "$OUT/t5f.csv" 2>/dev/null || echo 1) - 1 ))
    nalert=$(awk -F, 'NR>1 && $7==1' "$OUT/t5f.csv" | grep -c . || echo 0)
    nkill=$(awk -F, 'NR>1 && $7==1 && $10==5' "$OUT/t5f.csv" | grep -c . || echo 0)
    ndet=$(awk -F, 'NR>1 && $7==1 && $10==2' "$OUT/t5f.csv" | grep -c . || echo 0)
    if [ "${vpr:-x}" = 0 ] && [ "$vrc" = 0 ] && [ "${vkil:-x}" = 10 ] && [ "$drc" = 3 ] \
       && [ "${vdf:-x}" = 10 ] && [ "${nrow:-0}" = 20 ] && [ "${nalert:-0}" = 10 ] \
       && [ "${nkill:-0}" = 6 ] && [ "${ndet:-0}" = 4 ] && grep -q "netc.dll" "$OUT/t5f.csv"; then
      ok "fixture positive control: pristine 0 patched (exit 0) / killed 10 patched / diff verdict 10 (exit 3)"
      ok "fixture csv: 20 located rows, 10 alerts = 6 KILL_RET + 4 DETOUR_JMP32, netc.dll row included"
    else
      bad "fixture control mismatch (pristine=${vpr:-?}/exit$vrc killed=${vkil:-?} diff=${vdf:-?}/exit$drc rows=${nrow:-?} alerts=${nalert:-?} kill=${nkill:-?} det=${ndet:-?})"
    fi
    # (5b) defender-side report-path health check on the SAME fixture: it must flag exactly the 10
    #      overwritten entries on the killed image, say nothing on the pristine one, and confirm that
    #      the original payload still carries the 6 staging+call pairs the check assumes.
    python3 tools/nrth_report_path_check.py entries "$OUT/fixture_netc_killed.dll" \
        --funcs "$OUT/fixture_netc.json" --csv "$OUT/t5f_entries.csv" >"$OUT/t5f.entries" 2>&1; e_rc=$?
    python3 tools/nrth_report_path_check.py entries "$OUT/fixture_netc_pristine.dll" \
        --funcs "$OUT/fixture_netc.json" >"$OUT/t5f.entries0" 2>&1; p_rc=$?
    python3 tools/nrth_report_path_check.py payload "$SAMPLE" >"$OUT/t5f.payload" 2>&1; y_rc=$?
    nflag=$(awk -F, 'NR>1 && $5=="yes"' "$OUT/t5f_entries.csv" 2>/dev/null | grep -c . || echo 0)
    if [ "${e_rc:-x}" = 3 ] && [ "${p_rc:-x}" = 0 ] && [ "${y_rc:-x}" = 0 ] && [ "${nflag:-0}" = 10 ]; then
      ok "report-path health check: killed fixture 10 flagged (exit 3), pristine exit 0, sample 6/6 staging pairs"
    else
      bad "report-path health check mismatch (killed=${e_rc:-?} pristine=${p_rc:-?} payload=${y_rc:-?} flagged=${nflag:-?})"
    fi
  else
    bad "tools/nrth_netc_fixture.py could not build the control images (see $OUT/t5f.log)"
  fi
  # form parity: the reconstruction keeps the optional-header fields that a linker flag can align
  # (Subsystem=3 in particular).  Regression guard for build.sh's FORMAL_FLAGS.
  if [ -f bin/NRTH.dll ]; then
    if python3 tools/nrth_parity.py "$SAMPLE" bin/NRTH.dll 2>/dev/null \
         | grep -qE '^subsystem +3 +3 +Y'; then
      ok "PE form parity: rebuild matches the sample's Subsystem=3 (console-subsystem DLL)"
    else
      bad "rebuild no longer matches the sample subsystem - build.sh FORMAL_FLAGS changed?"
    fi
  fi
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
