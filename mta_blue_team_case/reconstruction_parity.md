# مطابقة إعادة البناء للأصل — Reconstruction parity (form + function)

**ملخص بالعربية:** المطلوب كان "نفس العمل الوظيفي والشكلي". هذا الملف يقيس ذلك بدل أن يدّعيه.
الأداة `recovered_or_reconstructed_project/tools/nrth_parity.py` تقارن حقلًا بحقل ملفّ PE الأصلي
بملفّ إعادة البناء (المحور A = الشّكل)، وتتتبّع كل دالة موثّقة في `function_map.csv` داخل مصادر
إعادة البناء (المحور B = الوظيفة). النتائج مقاسة بتاريخ 2026-10-11: 18/26 حقلاً متطابقة، و9/20
دالة مطبّقة. الفارق المتبقّي سببان: (1) أدوات بناء مختلفة (clang/lld مقابل MSVC) لا يمكن مجاراة
أسمائها إلا بتزوير هوية المترجم؛ (2) خطّ نطاق الحالة: آليّتا الغشّ الحقيقيّتان — خطف Lua-VM للّعبة
الجارية وتعطيل فحوص `netc.dll` — موثّقتان بالدليل لكنهما غير منفَّذتين لأنّ تنفيذهما ينتج برنامج
غشّ فعّالًا بدل أداة كشف.

---

## How to re-measure (nothing here is asserted without a command)

```sh
cd recovered_or_reconstructed_project
python3 tools/nrth_parity.py ../working/NRTH.dll bin/NRTH.dll \
        --out ../mta_blue_team_case/test_results/reconstruction_parity.md
```

Exit code is always 0: this is a report, not a gate. `run_all_tests.sh` stage 5 does keep one
guard on it — if `build.sh` ever loses its form-parity linker flags, the `Subsystem=3` match
disappears and stage 5 fails.

## Axis A — formal / structural parity

Before today the reconstruction matched the original on 16 of 26 comparable header fields.
`build.sh` now links the DLL with (default on, `--no-formal` to opt out):

```sh
FORMAL_FLAGS="-Wl,--subsystem,console -Wl,--strip-all"
```

Measured effect on `bin/NRTH.dll` (original = `working/NRTH.dll`, sha256 `947b81be…7861`):

| measured item | original | before | after | |
|---|---|---|---|---|
| file size | 1,318,400 B | 1,692,160 B | **1,425,408 B** | closer, not equal |
| sections | 5 | 9 | **7** | `.buildid` and `/4` gone |
| Subsystem | 3 (CUI) | 2 (GUI) | **3 (CUI)** | ✅ exact |
| `.text` / `.rdata` / `.data` name+flags | — | index 2 misaligned | ✅ all three match by index | exact |
| size of image | 0x152000 | 0x1A9000 | 0x166000 | closer |
| structure fields matched | — | 16/26 | **18/26** | +2 |

Side benefit for reproducibility: `--strip-all` removes the CodeView/PDB path and the
`.buildid` container, so `tools/pe_deterministic.py` now has exactly **one** entropy source left
to neutralise (the 4-byte COFF `TimeDateStamp`) instead of three sites; two consecutive
`./build.sh` runs produce byte-identical artifacts (see `BUILD_LOG.txt`).

**What cannot be matched, and why it is not matched.** Every remaining difference is listed by
the tool as `toolchain-bound`:

| field | original | reconstruction | reason |
|---|---|---|---|
| linker version | 14.51 | 14.0 | MSVC 14.51 link vs `lld` (reported as LLVM 14). Writing "14.51" into the header would be forging a compiler identity, not reconstructing a build. |
| `.rsrc` section + `resource` data directory | present (480 B, no `VS_VERSION_INFO`) | absent | MSVC emitted a manifest-only resource dir; clang/lld emits none without a `.rc` + `windres` toolchain. |
| `debug` data directory | present | absent | deliberate: a CodeView record is a per-link GUID + PDB path, i.e. the exact thing that made the artifact non-pinnable. Determinism was chosen over that cosmetic match. |
| `.eh_fram`, `.gcc_exc` | absent | present | emitted by the mingw-w64 CRT objects this target links; `-fno-unwind-tables -fno-asynchronous-unwind-tables` was tested on the C++ TUs and changed nothing (verified on `imgui.o`), so they would need a rebuilt CRT. |
| entry RVA / size of image | 0xa8bb0 / 0x152000 | 0xd7180 / 0x166000 | content-determined, not a flag. Matching them would mean padding the image to the original's size, which is size-collision for the sake of it. |
| imports | 247 functions over 17 DLLs incl. `MSVCP140`, `VCRUNTIME140`, `gdiplus`, `IMM32` | 228 over 17 DLLs incl. `GDI32`, `dwmapi` | MSVC C++ runtime imports (`MSVCP140`/`VCRUNTIME140` + the api-ms CRT split) are what the CRT you link against *is*, not a switch. |
| RTTI / SEH prologue fingerprint | 64 `.?AV/.?AU` RTTI records, 143 `53 8B DC` `__SEH_prolog4` | 0, 0 | MSVC-only artefacts (name decoration + SEH4 wrappers). They are, in fact, how the case's own rules distinguish "sample" from "rebuild"; removing them from the rebuild is correct for detection engineering. |
| distinct ASCII strings | 3,858 | 3,787 | only 1,101 shared (28.5 %). The original's set is dominated by the XOR-encrypted `.data` layer and MSVC metadata that the reconstruction deliberately does not contain. |
| YARA | `NORTH_NRTH_Payload_DLL`, `NORTH_Export_Contract_NVXHookProc`, `NORTH_NRTH_HiddenPatternRecords` fire | none fire | by design (see `detection/yara_rules.yar`): the rules key on ciphertext records and the byte-level export-table shape of the *sample*. A reconstruction that matched those rules would be indistinguishable from the malware in a scan, which is the opposite of what a blue-team artifact should be. |

Full generated field-by-field table: `test_results/reconstruction_parity.md`.

## Axis B — functional parity of the mapped behaviour

Coverage is derived from `function_map.csv` (module `NRTH.dll`) cross-checked against
`src/*.cpp/h/def` — "implemented" means the mapped label exists as an identifier in the
reconstruction, not that it is mentioned in a comment.

Implemented and behaviourally equivalent (9 of 20): the observable load/arm/draw chain —
`NVXHookProc` (export @1, RVA 0x1000), `DllMain` (module pin via
`GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|…PIN)` + `CreateThread`),
`MainInitThread`, `Hooked_LdrLoadDll` (MinHook on `ntdll!LdrLoadDll`, arm when `client.dll` /
`netc.dll` appear), `GetD3D9DeviceVTable`, `InstallD3D9Hooks` (vtable index 17 `Present`, 16
`Reset`), `Hooked_Present`, `Hooked_Reset`, and the ImGui menu that the `Insert` toggle opens;
plus the vendored MinHook 1.3.3 / ImGui 1.92.9 / Lua 5.4.6 sandbox that `build.sh` links.

Documented from evidence but deliberately **not** implemented (the case's scope line):

| mapped function | VA (off = VA−0x1000 … see convention) | why it stays a document, not code |
|---|---|---|
| `HookInstaller_ClientLua` | 0x10005b80 | 11 resolver scans + 11 `MH_CreateHook` against the **live** `client.dll`, including the Lua-VM `exec` path. Coding it = working in-game script execution. |
| `OffsetResolver_Client` | 0x1000c390 | 20 `.data`-driven scans, 0 hooks — the feature-slot offset table (aim/weapon/god-mode style writes). |
| `NetcCheckKiller` | 0x10020640 | 6 scans + 4 hooks + 6 one-byte `0xC3` patches that disable `netc.dll` integrity checks (sites 0x100206f0, 0x100208aa, 0x10020927, 0x10020f46, 0x100214bd, 0x100215f1). Coding it = anti-cheat tampering. |
| `BytePatcher_1byte` | 0x10011870 | `VirtualProtect(ptr,1,0x40,&old)` + 1-byte copy — the write primitive above. |
| `PatternRecordLoader` / `HiddenPatternRecords_Data` | 0x10023670 / `.data` | the 20-record scan table; exposed *read-only* through `nrth_audit` instead. |
| `StrDecryptor_Family` | 82 decryptors, 63 ciphertexts | the XOR/SSE string layer (`plain[p] = cipher[p] ^ ((p−K)&0xFF)`, one-shot gate ⇒ `L = F−1`). Decrypting it is detection work and is done (`tools/nrth_strings_recover.py`, `working/recovered.json`); **re-implementing the encryptor in our binary adds evasion value and zero analyzable behaviour**, so the reconstruction keeps plaintext imports and its strings remain greppable. |
| `ConfigRead_Overwack`, `AutoInjectDriver`, `LuaVM_Globals`, `Resolver_ScanModulePattern`, `Hooked_LdrLoadDll_client_arm` | see `function_map.csv` | config/ADS artifacts (`C:\Overwack\loader_config.cfg`, `C:\ProgramData:NT2`) and the injection driver: creating stealth storage in a *reconstruction* would be new behaviour, not recovered behaviour, so it is described in `mechanism_overview_ar.md` / `report.md` instead of implemented. |

Not covered: 0 — every mapped row is either implemented or explicitly accounted for above.

## Honest bottom line

- **Contract:** identical (x86 PE32, ImageBase 0x10000000, one export `NVXHookProc` @1, DllCharacteristics `0x0140`).
- **Form:** 18/26 header fields equal, all three core sections equal by index, size within 108 KB — and the residual gaps are toolchain identity or deliberate determinism, not oversight.
- **Function:** the load→arm→overlay chain behaves like the original; the two cheat mechanisms that make the original *the original* remain documented, not implemented, and no cheat-capable DLL is produced by this project.
- Anything in this file that is a claim about the **sample** is Observed; anything about intent inside the packed feature slots is Strongly inferred at best (see `report.md` §7).
