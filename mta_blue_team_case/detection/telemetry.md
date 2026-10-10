# Detection & Telemetry Guidance — NORTH/NRTH/NVX (MTA:SA)

Case: `mta_blue_team_case`. All signals below are tied to observed behavior (see `behavior_timeline.md`). Each rule lists false-positive (FP) caveats; **do not treat any single signal as definitive**. Prefer 2+ independent signals before verdicts or enforcement.

## Layer 1 — File/host indicators (static)

| Signal | Source evidence | Strength | FP caveats |
|---|---|---|---|
| SHA-256 of the two samples | `hashes.sha256` | High (exact) | Trivially bypassed by recompilation; treat as retro-hunting only |
| Export `NVXHookProc` in a DLL | NRTH.dll export table, ordinal 1, RVA 0x0B9E0 | Medium | Any DLL built for `SetWindowsHookEx` injection has a hook-proc export; name is family-specific |
| Strings `=== NORTH Loader ===`, `NVX Loader.pdb`, `[+] Inyectado OK` (Spanish console) | loader `.rdata` | High | Renamed/recompiled loaders lose them |
| `North Cheat` / `%s##nvx_top_%d` / `##nvx_content` | NRTH.dll `.rdata` | High | None likely for the exact strings; renamed clones may drop them |
| PDB path `C:\Users\user\Desktop\src CHEATS\over\Loader\Debug\NVX Loader.pdb` | loader `.rdata` 0x419aa4 | Medium | Developer artifact; may appear in other builds from the same source tree |
| Folder `C:\NVX` | **plain** `.rdata` string at file offset 0x000afd18 (not an encrypted record) | Medium | Generic folder name; its use is unproven — corroborate with child files/timestamps near game sessions |
| Config file `C:\Overwack\loader_config.cfg` | decryptor record, K=0x20, call site 0x1001fcff (`recovered_strings.txt` Section A) | High for this family | Renamed/other-build config path; watch `%OVERWACK%`-style folder creation next to the game dir |
| NTFS alternate data stream `C:\ProgramData:NT2` | decryptor record, K=0x06, site 0x1001e530 | High (unusual) | Only meaningful as an ADS on ProgramData; `dir /r C:\ProgramData` or a file-integrity sensor that reports streams |
| `C:\ProgramData\MTA San Andreas All\Common\data\cache` | K=0x2D, site 0x1001e601 | Low (legit MTA path) | MTA itself uses it — an indicator only when *written by an unsigned injected module* |
| Registry reads `...\Multi Theft Auto: San Andreas All\1.5\1.6\Settings\general`, `...\Internet Settings\Connections`, `...\Explorer\CLSID` | K=0x06 records, sites 0x1001ea1b / 0x1001efbc / 0x1001e484 / 0x1001e3ad | Low–Medium | MTA reads its own keys; the signal is *a non-MTA module* querying them (Sysmon EID 12/13 with the game's image loaded from an unexpected module list) |
| Console/error strings `Error #1019/1029/1031/1036/1038/10395/1099 Send screen error dev-cheat` | K=0x20 / 0x06 records, sites in 0x10020825-0x1002155d | High for this family | Developer-facing error labels: they also prove a `screen`-capture/report path exists in the payload (functionality not traced) |
| Watch filename `NRTH.dll` / `nvx.dll` loaded into `gta_sa.exe` | loader default path + NRTH.dll string 0x100f6cb2 | High in this context | DLL names are changeable; module-in-game-context is the key part |

> Every decoded string above is reproducible: `python3 recovered_or_reconstructed_project/tools/nrth_strings_recover.py working/NRTH.dll` (see `recovered_strings.txt` for the full table, including which records are *not* usable as indicators).

## Layer 2 — Behavioral telemetry (host EDR/Sysmon/ETW)

Recommended event sources: Sysmon (EID 1, 7, 8, 10, 25), Windows Security 4688 with command-line, ETW `Microsoft-Windows-Kernel-Process`, API-level EDR.

1. **Injection chain (BHVR-1+2)** — parent process opens `gta_sa.exe`/MTA with `PROCESS_VM_WRITE|PROCESS_CREATE_THREAD`, allocates remote memory, writes a path ending in `.dll`, then creates a remote thread whose start address resolves to `LoadLibraryA`.
   - Sysmon correlate: EID 10 (ProcessAccess to game with VM_WRITE) + EID 8 (CreateRemoteThread, start module kernel32!LoadLibraryA) + EID 7 (image load of `NRTH.dll` into `gta_sa.exe` shortly after).
   - FP: legitimate injectors (Steam overlay, Discord, graphics tools, AV) — allowlist by signer and module hash.

2. **Hook-injection fallback (BHVR-3)** — `SetWindowsHookExA(WH_GETMESSAGE, ...)` targeting a thread of the game process, followed by `PostThreadMessageA` bursts (10× `WM_NULL`), immediate `UnhookWindowsHookEx`, then module verification via `K32EnumProcessModules`.
   - Correlate with the hook module being unsigned/unknown and the loader's console parentage.
   - FP: IMEs, accessibility tools, clipboard managers use hooks heavily — the *target being the game + the export name + the verify-then-unhook pattern* is the discriminator.

3. **Payload arming (BHVR-4)** — inside `gta_sa.exe`: `GetModuleHandleExA` with `GET_MODULE_HANDLE_EX_FLAG_PIN` on an unsigned third-party DLL, followed by `VirtualProtect` writes inside `ntdll.dll` (MinHook trampoline on `LdrLoadDll`).
   - ntdll `.text` write-protection-change events from a non-Microsoft module are high-value on their own.
   - FP: some overlay/anti-cheat products patch ntdll too — verify signer/allowlist.

4. **Overlay (BHVR-5)** — repeated calls into D3D9 Present from a module that is not the game/graphics stack; device `Reset` followed by texture recreation patterns (ImGui device-object lifecycle).
   - FP: Steam/Discord/ReShade overlays — baseline a clean client image first (see `private_server_tests/test_plan.md`).

5. **MTA interop (BHVR-6)** — a non-MTA-signed module referencing `client.dll`/`netc.dll` load events, or MTA packet-ID constants. On the server side: unexpected packet-ID sequences (`PACKET_ID_CHEAT_*`-class handlers), memory-challenge responses arriving without a corresponding server challenge.

## Layer 3 — Server-side (MTA:SA private server)

- Treat client-side state as untrusted: validate movement/aim/weapon sync server-side (rate checks, impossible-state checks on `SWeaponAimSync`-class structures).
- Log module-load attestations if your anti-cheat supports client module inventories; alert on unsigned DLLs mapped into `gta_sa.exe` after game start.
- Enable verbose netcode logging around reserved/cheat packet IDs during investigations; capture with server resources, not by inspecting third-party players' machines.

## Layer 4 — client-module integrity (where this cheat actually lands)

The payload does not add code to `client.dll`/`netc.dll`; it *re-points* existing functions. That
makes the strongest host signal a prologue check on a handful of known functions, which is what
`NRTH_audit.dll` / `nrth_audit.exe` automate (build, API and honest limits: `audit_tool.md`).

| Checked object | What the tool looks for | Observed in sample | Strength / FP caveat |
|---|---|---|---|
| 20 functions in `client.dll` + 1 in `netc.dll`, located by the cheat's own XOR-decrypted patterns | exact pattern → `PRISTINE`; `C3` / `E9 rel32` / `FF 25 abs32` / `68 abs32 C3` substituted over the entry → tamper footprint with the jump target as `detail` | hook installer `0x10005b80` (11 pattern scans + 11 `MH_CreateHook`), offset resolver `0x1000c390` (20 scans, no hook there), `netc.dll` cluster from `0x10020640` (4 hooks + 6 RET writes) | High — patterns are the attacker's own, so a recompiled cheat keeps them as long as it still hooks the same functions |
| the six `netc.dll` check functions disabled by a one-byte `0xC3` write | first byte == `C3` at a `.data`-fetched pattern's target | write sites 0x100206f0, 0x100208aa, 0x10020927, 0x10020f46, 0x100214bd, 0x100215f1; writer `0x10011870` = `VirtualProtect(...,0x40,...)` + 1-byte copy | The *targets* cannot be named statically (patterns are fetched from `.data` globals at run time) — treat "six functions with a `C3` entry" as the indicator, and confirm function identity on a test client dump |
| the sample itself (`sweep`) | prologue-anchored hidden x86 patterns in `.data`/`.rdata` | 8 candidates at `.data` 0x1013b750…0x1013bd10, identical to the independent Python tool's output | Sweep output is *candidate* evidence only; it must match a decryptor call site to be attributed |

Deployment notes:

- Run it on a **read-only dump of the loaded module**, not only on the file on disk: the detours and
  the `0xC3` writes live in memory. On-disk `client.dll` normally reads `PRISTINE` even on a
  compromised client — that is expected, not a clean result.
- `exit 3` = at least one tamper footprint; `--csv` for one row per signature. Verified behaviour:
  `0 with a match` on `NRTH.dll` and on `NORTH LOADER.exe` (no self-flagging), `0 with a match` on
  a clean image, and the unit tests cover `C3`, `E9`, `FF 25` and the negative (normal-prologue) case.
- Alert only on the `added_footprint` count (the diff's return value). `sus_unlocated` and
  `target_lost` rows are what *different builds* produce and must never page anyone — measured: our
  own reconstruction diffed against the original sample yields `verdict: 0` with one informational
  `unlocated footprint (other build)` row, which is the behaviour 1.2.0 added the alignment rule for.
- **Best practice: `diff`, not `audit`, whenever you can.** Keep one known-good `client.dll` /
  `netc.dll` per MTA build in your corpus and run `nrth_audit.exe diff <baseline> <dump>`; the tool
  then only reports located functions whose state changed, which removes the judgement call about
  what a "normal" prologue looks like for that compiler/build and makes the alert defensible.
- If you write your own YARA instead: match the *concrete* footprint over the entry, never a
  wildcarded head. Wildcarding one token of a 20-token pattern produced 5 false positives out of
  20 rows on a benign image — see `audit_tool.md` §"Why the patched check is strict".

## Regression tests for your detections

1. Run the clean MTA:SA client → record baseline telemetry (must generate zero alerts from rules 1–5 except known overlay FP list).
2. Run the sample on the team's private server per `private_server_tests/test_plan.md` → each step of `behavior_timeline.md` must produce the corresponding alert.
3. Recompile-style variants (renamed export/strings) will evade Layer 1 → Layer 2/3 rules are the safety net; validate them with the reconstruction in `recovered_or_reconstructed_project/` **only inside the authorized private-server scope**.
4. Audit-tool regression (no game needed): `nrth_audit.exe selftest` must print `all checks passed`
   (21 checks whose ciphertexts are taken from the sample), then `nrth_audit.exe audit <clean client.dll>`
   must print `0 with a match`. Patch one located function's first byte to `0xC3` **in a private test
   copy** of an image and re-run: the tool must report `KILL_RET` with the patched RVA. A detector that
   cannot pass its own negative control should not be trusted with a positive one.
5. Codec regression for variants: `nrth_audit.exe sweep <variant.dll>` + `tools/nrth_strings_recover.py`
   must agree on the candidate set; disagreement means the variant changed the decryptor shape, and the
   signature table (`src/nrth_audit_sigs.h`, generated) needs regenerating — do not hand-edit it.

## Known blind spots (honest list)

- Strings in the payload are XOR/SSE-encrypted; variant builds with a different key evade string rules
  entirely. (The codec itself is `plain[p] = cipher[p] ^ ((p-K)&0xFF)` with a *per-decryptor* K — 82
  decryptor functions, keys observed in {0x06,0x20,0x2D,0x3C,0x3F,0x40}; there is no single family key,
  so a per-record brute force is required. `NrthXorCrack` does exactly that.)
- Layer 4 depends on the cheat still hooking the same `client.dll` functions. A variant that changes its
  pattern set needs the table regenerated from that variant (`tools/nrth_sig_export.py` +
  `tools/gen_nrth_audit_sigs_h.py`), which is why both are part of the repository and not a baked-in blob.
- Six `netc.dll` functions stay unnamed: static analysis shows *what* is patched (a one-byte RET) and
  *where* the write comes from, but the target patterns only exist in `.data` at run time.
- Export renaming defeats `NVXHookProc`-based rules.
- No rule here has been validated against a broader variant set — the sample set is exactly 2 files + 1 archive.
- Kernel-mode or manual-map injectors would evade all module-load-based signals (not observed in this sample family).
