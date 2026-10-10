# nrth_probe — read-only code-integrity probe (host-side detection)

**Case:** `mta_blue_team_case` · **Class:** R2 (newly authored defensive tool) · **Date:** 2026-10-10

Detects the *footprint* of the NORTH/NRTH payload on an authorized test client, without re-implementing any part of the payload:

| What the sample does (evidence) | What the probe reports |
|---|---|
| MinHook detour on `ntdll!LdrLoadDll` (VA 0x1000a640) and on two `client.dll` functions found by code-signature scan (VA 0x10005b80, trampolines stored at 0x1013c944/0x1013c94c) | `HOOK_JMP` / `HOOK_PUSH_RET` — code bytes in the module's `.text` differ from the clean baseline at that RVA, and the live block begins with `E9`, `FF25`, `EB`, or `push addr; ret` |
| Writes a single `0xC3` at the first byte of a `netc.dll` routine to disable a check (VA 0x10020640 → byte writer 0x10011870) | `EARLY_RET` — live block starts with `C3`/`C2 imm16` at a location that was not a return in the baseline |
| Module pinning + ImGui/D3D9 hooks (vtable slots 16/17) | `PATCHED` blocks in `d3d9.dll` `.text`, plus any newly mapped module absent from the baseline |

## Why baseline-diffing instead of the sample's own pattern scan

The original locates game functions by byte-signature because those routines are not exported. Reproducing that resolver in a "detection tool" would hand out the hardest building block of the cheat and would break whenever the client build changes. Baseline diffing needs no knowledge of offsets, works on any build (re-baseline after an update), and stays strictly read-only.

## Design boundary — enforced, not just claimed

* Only `OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)` + `ReadProcessMemory` + `psapi!EnumProcessModules` are used. There is no `WriteProcessMemory`, no `VirtualProtectEx`, no `CreateRemoteThread`, no `QueueUserAPC`, no hook installation — and `tests/test_probe_logic.py` asserts this by parsing the source's AST, so the property cannot rot silently.
* Output is a JSON report; exit codes: `0` clean, `1` non-high changes, `2` high-severity (hook/early-ret) changes — suitable for CI on the test rig.

## Usage (authorized test machines only)

```bash
# 1. clean client, before any sample is run — capture the baseline
python nrth_probe.py baseline --pid <gta_sa_pid> \
       --modules client.dll,netc.dll,d3d9.dll --out ../baselines/clean-<build>

# 2. after the sample (or after an incident) — compare
python nrth_probe.py check --pid <gta_sa_pid> \
       --baseline ../baselines/clean-<build> --json ../baselines/incident-1.json

# 3. offline: compare two dumps, or two PE files' .text (no process access at all)
python nrth_probe.py diff before.text.bin after.text.bin
python nrth_probe.py diff --pe working/NRTH.dll other_build/NRTH.dll
```

Bitness: `ReadProcessMemory` requires the probe's Python to match the target's architecture (sample is x86 → use 32-bit Python for a `gta_sa.exe` target), and elevation for a protected/other-user process.

## Status of validation

* **Executed here:** `test_probe_logic.py` — **36/36 checks passed** (classification of `E9`/`FF25`/`EB`/`C3`/`C2`/`int3`, first-differing-byte precision, RVA reporting, truncated/size-mismatch handling, PE `.text` header parsing from a synthetic image, AST read-only guardrail, CLI exit codes). Log: `../../test_results/integrity_probe_logic.log`.
* **NOT executed here:** live `baseline`/`check` against a real `gta_sa.exe` — the analysis host is Linux with no Windows, no MTA:SA client, no game process to inspect. Those two modes must be run on the team's test client per `private_server_tests/test_plan.md` (T0 for baseline, T4/T5 for checks). Do not report them as validated until that is done.
* Short reads and unreadable pages are recorded as zero-filled bytes and will show up as `SIZE_MISMATCH`/`PATCHED`; if a module is unloaded/reloaded the RVA mapping is still valid because offsets are stored module-relative.

## Known blind spots

* A fresh `client.dll`/`netc.dll` version invalidates a baseline — re-baseline on every client update (store the baseline directory per build; the manifest records module base + size + digest).
* Manual mapping / kernel-mode patching or a hypervisor-assisted cheat can hide writes from user-mode reads — then rely on `telemetry.md` Layer 2/3 and on `nrth_guard`.
* A cheat that patches only code the baseline did not cover (sections other than `.text`/`.init`) is invisible to this probe. Extend `CODE_SECTIONS` deliberately and document it here.
* Legit overlays (Steam/Discord/ReShade) hook `d3d9` too → expect `PATCHED`/`HOOK_JMP` in `d3d9.dll` on any modern gaming box. Baseline **with the team's approved overlay set present**, or exclude `d3d9.dll` from sanctioning and keep it for triage only.
