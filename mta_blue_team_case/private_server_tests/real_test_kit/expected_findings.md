# Expected findings — real-test kit outputs, and what each verdict means

All sample-side numbers below are **Observed** in `working/NRTH.dll` unless tagged otherwise. This file
is the interpretation layer for `README.txt`; it deliberately separates *what a clean client looks
like* from *what the interference pattern looks like*, and states the confidence of each mapping.

---

## 1. `nrth_acwatch` server resource (report_counter.lua)

Files appear in `mods/deathmatch/resources/nrth_acwatch/cfg/`.

| Output | CLEAN client | client whose report path is neutralised | confidence |
|---|---|---|---|
| `ac_report_counter.csv`, per-minute row | `acinfo/screenshot/modinfo` ≥ 0, and > 0 whenever the server itself requests a screenshot or the client triggers AC info | stays all-zero for a player who is otherwise active (chat, vehicle sync, joins) while other players' rows are non-zero | Strongly inferred for the *mechanism*, Observed for the patch bytes that cause it |
| `ac_report_alerts.log` line `SILENCE <name> (serial) online Ns with ZERO AC-report events` | absent | present for the affected player | same as above |
| `ac_report_alerts.log` line `HEARTBEAT: no AC event was ever received …` | absent | **may appear on either client** — it means the three event names do not exist on this build, i.e. the watch is not measuring. Fix `EVENTS` before reading any verdict | this is the kit's own control |
| `ac_report_state.json` | `"total_fired">0`, `"silent":0` | `"silent">=1` | derived from the above |

Required sanity step: play one minute on a client you believe is clean and confirm `total_fired`
rises above 0 (e.g. after `requestClientScreenshot <player>` from the server console). A clean verdict
with `total_fired == 0` is **not** a clean verdict — it is an uncalibrated sensor.

## 2. `collect_client.ps1` (read-only client snapshot)

`client_<host>_<utc>.csv` sections and their meaning for this case:

| Row | CLEAN | INFECTED (payload present as in the sample) | note |
|---|---|---|---|
| `ioc,dir-C:\NVX,False` | `present=False` | `present=True` | path decrypted at 0x100b0d18 (K for that record measured) |
| `ioc,ads-ProgramData:NT2,False` | `present=False` | `present=True`, `detail=NT2:<len>` | ADS name from `indicators.json` |
| `ioc,cfg-Overwack,…` | `present=False` | `present=True` | `C:\Overwack\loader_config.cfg`, 0x1001fcff |
| `cfg,menu_key,45,…` | no `cfg,` rows | rows for `menu_key` (VK code, decimal) and `no_spoofer` | exactly the two format strings at 0x1001fd7b / 0x1001fdc5 |
| `hash,client.dll,…` / `hash,netc.dll,…` | equal to your known-good baseline hash | equal to baseline too | **the sample patches the loaded copy, so unchanged on-disk hashes are expected** — this row is a regression check, not a detection |
| `candidate,<file>,…,hits=nvx.dll@off 0x…;NVXHookProc@off 0x…` | no rows | row for the payload image | the export-directory module name in the sample literally reads `nvx.dll`; our reconstruction now matches that field |

Limitations to record with any result: the collector is a *presence* snapshot. A loader that deletes
its dropped files after injection, or a payload mapped without a file on disk, produces an all-false
CSV. That is why the two independent legs (server silence + on-image YARA/PE comparison) are both required.

## 3. Offline entry check (`tools/nrth_report_path_check.py entries`)

Input shape (`reportpath_entries.json`) — replace the RVAs with the ones you resolved for **your**
`netc.dll` build from its listing; `reportpath_entries.example.json` in this directory is the shape
template only and its numbers come from the synthetic fixture, not from a real netc.dll.

```
python3 recovered_or_reconstructed_project/tools/nrth_report_path_check.py entries \
    <path-to-netc.dll-on-disk> --funcs reportpath_entries.json --csv entries.csv ; echo "exit=$?"
```

| exit | meaning | how to use it |
|---|---|---|
| 0 | every listed on-disk entry starts with a normal prologue (`55 8B EC` / `53 8B DC`) | expected **even on an infected client** (patch lands on the loaded image) → does not clear the client |
| 3 | one or more entries are `KILLED` (`C3`) or `DETOUR` (`E9`/`FF 25`) or `PUSHRET` (`68 imm32 C3`) | the on-disk image itself is patched/rebuilt → high-severity, page the operator |
| 2 | bad input (no `--funcs`) | tool usage error, not a verdict |

The discriminating power of this check is proven inside the repository by the labelled **synthetic
fixture** (see `recovered_or_reconstructed_project/test_results/fixture_control.log`, stage 5b of
`run_all_tests.sh`): pristine image → exit 0 with 0 flags, killed image → exit 3 with exactly 10
flags (6 `KILLED` + 4 `DETOUR`). The fixture is a hand-built PE that carries none of netc.dll's
content; it validates the *detector*, not any claim about a live client.

## 4. `payload` sub-command (regression on the detector's assumption)

```
python3 recovered_or_reconstructed_project/tools/nrth_report_path_check.py payload working/NRTH.dll
```
Expected on the original sample: `6/6 documented staging sites located … kill plan present as
documented`, exit 0, each staging byte 11 bytes before the `call` site. Any other payload that
reports 6/6 at *different* VAs is a variant worth pulling for analysis; 0/6 means the assumption this
check makes does not hold for that binary and the entry-level check must not be trusted there.

## 5. What this kit does NOT cover (carried into report.md's limitations)

* No live-client hooking, no `netc.dll` write, no report suppression, no driver install, no in-game
  Lua execution — those are the sample's remaining unimplemented behaviours and stay out of scope.
* No run was executed against a real game client from this analysis environment: it has no Windows
  install, no MTA server, and no game files. Steps 1–6 of `README.txt` must be run by the operator on
  the four-person server; this kit is the instrumented procedure, and the fixture + unit tests are the
  evidence that the instruments work.
* `collect_client.ps1` could not be executed here (no PowerShell in this sandbox); its logic was
  reviewed line by line and its output schema is what `expected_findings.md` above consumes. Run it
  once on a clean client before drawing conclusions from a diff.
