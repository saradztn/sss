# Mechanism Analysis: Lua-VM Execution Path in NRTH.dll (the "Execute" system)

Case: `mta_blue_team_case` · Analysis date: 2026-10-10 · Method: static disassembly (Capstone) + cryptographic recovery of the sample's string obfuscation.
All addresses are VAs (ImageBase 0x10000000). Result class: **D2** (decompiler/disassembly output) — this document explains the ORIGINAL sample's mechanism; it is analysis, not an implementation.

> **Scope note:** This writeup exists so defenders can understand and detect the real mechanism. A working re-implementation of game-VM injection is deliberately NOT provided (it is the active cheat weapon). Everything below is observable in the shipped binary.

---

## 0. String obfuscation (recovered algorithm)

All sensitive strings/signatures are encrypted with **positional XOR**:

```
plaintext[p] = ciphertext[p] XOR ((p - 0x2D) & 0xFF)
```

- Short variant: byte loop at VA 0x100078d0 (10 bytes) / 0x10007900 (12 bytes, SSE).
- Long variant: SSE dword loop at 0x10007640 / 0x10007780 + byte tail — the SSE key lanes
  (xmm7 = {-45,-44,-43,-42}, xmm6 = {0,1,2,3}) collapse to the same `(p - 0x2D)` formula.
- After decryption a one-byte flag beside the buffer is cleared (in-place, one-shot decrypt).

Recovered plaintexts (verified against the algorithm):

| Location | Ciphertext VA | Decrypted | Purpose |
|---|---|---|---|
| 0x10005c56 | (inline dwords) | `client.dll` | target module |
| 0x100044df | (inline dwords) | `@auto_inject` | chunk name for auto-injected scripts |
| 0x10005bb3 | 0x100f2060-set | `55 8B EC 8B 45 ? A3 ? ? ? ? 8B 45 ? A3 ? ? ? ? 8B 45` | **signature #1** |
| 0x10005cda | 0x100f2050-set | `55 8B EC 83 EC ? A1 ? ? ? ? 33 C5 89 45 ? 8B 45 ? 53 8B 5D ? 56 57 8B 7D ? ...` | **signature #2** |

## 1. Arming sequence (runs after `client.dll`/`netc.dll` load)

Entry: `Hooked_LdrLoadDll` (VA 0x1000a640) → follow-on init **0x10005b80**.

Function **0x10005b80** ("VM interface resolver"):

1. Resets `default_L` (0x1013c95c = 0) and state flags (0x10148ea0, 0x1013c939).
2. Decrypts **signature #1**, resolves its target inside `client.dll`
   (resolver helper **0x10002960** — module + byte-pattern scan with `?` wildcards).
3. Installs a **MinHook inline hook** on the found function:
   - target = scan result (stored 0x1013c944)
   - detour = **0x10002ff0** (VM-registry callback — see §3)
   - trampoline → back to 0x1013c944 (so the tool can call the original).
   - hook engine calls at 0x10005ca4–0x10005cce: `MH_*` (0x100363f0 / 0x100362c0 / **MH_CreateHook 0x10036020**).
4. Decrypts **signature #2**, scans `client.dll` again, hooks the second function:
   - detour = **0x100047b0** (see §4)
   - trampoline → **0x1013c94c** (this global is the `exec` function pointer used by Execute).

**Interpretation (Strongly inferred):** MTA's client.dll internal functions are located by
code signature (they are not exported by name — hence pattern scanning). Signature #1's
body (`mov [abs], eax` × 3 — storing 3 arguments into globals) matches a **Lua VM
registration** helper; signature #2 matches the **execute-chunk** entry (stack-cookie
prologue + 4-argument frame).

## 2. VM registry (state)

| Global VA | Meaning (evidence-backed) |
|---|---|
| 0x1013bf04–0x1013bf08 | vector of VM descriptors, stride 0x1C: `std::string name` + `lua_State* L` at +0x18 |
| 0x1013c95c | default `lua_State*` ("Default VM") |
| 0x1013be48 | selected VM index (combo) |
| 0x1013c94c | trampoline: `int exec(lua_State*, const char* code, size_t len, const char* chunkName)` |
| 0x1013c974 | post-exec callback `void post(lua_State*, 0, 0, 0)` |
| 0x1013c939 | auto-inject result flag; 0x10148ea0 = auto-inject done flag |
| 0x1013beec–0x1013bf00 | stored auto-inject script (std::string) |

## 3. Detour #1 (0x10002ff0) — VM registration callback

Intercepts the client's VM-creation/registration call; fills the registry + `default_L`.
(Recon at0x10004550 auto-inject driver consults `default_L`, guards it with
`VirtualQuery` — IAT 0x100ae130, checking region flags — then calls the exec primitive.)

## 4. Detour #2 / exec primitive (0x100047b0) and the Execute button

Editor `Execute` handler (ImGui button ref at 0x10025a9e, status "Script executed" 0x10025c7f):

```
select L = registry[vm_index].L  else default_L (0x1013c95c)
VirtualQuery(L) guard (bit 0x1000 check)          ; crash protection
call [0x1013c94c](L, code, len, "@custom")        ; trampoline -> MTA execute-chunk fn
if ok: call [0x1013c974](L, 0, 0, 0)              ; post-callback
status = "Script executed"
```

Auto-inject path (0x10004550 → 0x10004480): same primitive, chunk name `@auto_inject`,
payload = stored script from the Scripts tab (evidence strings "Auto-inject: script
injected successfully" / "... injection failed").

## 5. Why this matters (defender notes)

- **Detection:** the two byte signatures above (with `?` wildcards) will find the hooked
  prologues in `client.dll` memory; a `PAGE_EXECUTE_READWRITE` trampoline near those
  functions + MinHook-style JMP patch is the runtime footprint. See `detection/telemetry.md`.
- **Impact:** once the exec trampoline runs with a live `lua_State*`, arbitrary Lua runs
  in the MTA client VM — i.e., full client-side script execution (the core capability of
  this family). Server-side validation remains the reliable control.
- **Redaction:** no live exploit code is reproduced in this repository; the mechanism is
  documented so the team can build regression tests and server-side checks.

## 6. Confidence

| Claim | Confidence |
|---|---|
| Positional-XOR string scheme `(p-0x2D)` | High (algorithm recovered; plaintexts coherent) |
| Two client.dll functions located by pattern scan and MinHooked | High (call chain disassembled) |
| Signature #2 = execute-chunk; trampoline used by Execute | High (argument shape L, code, len, name + "Script executed" path) |
| Signature #1 = VM registration populating the registry | Medium–High (argument-store prologue + registry writes in detour) |
| `post(L,0,0,0)` role (cleanup/flush) | Tentative |
