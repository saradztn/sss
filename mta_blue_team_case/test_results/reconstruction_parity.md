# Reconstruction parity report

Original: `../working/NRTH.dll` · Rebuild: `bin/NRTH.dll`

Structure fields matched: **18/26**

| axis | item | original | rebuilt | match | note |
|---|---|---|---|---|---|
| structure | sections | 5 | 7 | — | toolchain-bound |
| structure | machine | 0x14c | 0x14c | ✅ | other |
| structure | pe32/32+ | 0x10b | 0x10b | ✅ | other |
| structure | linker version | 14.51 | 14.0 | — | toolchain-bound |
| structure | image base | 0x10000000 | 0x10000000 | ✅ | fixable |
| structure | entry RVA | 0xa8bb0 | 0xd7180 | — | fixable |
| structure | size of image | 0x152000 | 0x166000 | — | fixable |
| structure | size of headers | 0x400 | 0x400 | ✅ | fixable |
| structure | section align | 0x1000 | 0x1000 | ✅ | fixable |
| structure | file align | 0x200 | 0x200 | ✅ | fixable |
| structure | OS version | 6.0 | 6.0 | ✅ | toolchain-bound |
| structure | subsystem | 3 | 3 | ✅ | fixable |
| structure | DllCharacteristics | 0x0140 | 0x0140 | ✅ | fixable |
| structure | stack reserve | 0x100000 | 0x100000 | ✅ | toolchain-bound |
| structure | stack commit | 0x1000 | 0x1000 | ✅ | toolchain-bound |
| structure | heap reserve | 0x100000 | 0x100000 | ✅ | toolchain-bound |
| structure | heap commit | 0x1000 | 0x1000 | ✅ | toolchain-bound |
| structure | checksum | 0x0 | 0x0 | ✅ | fixable |
| structure | file characteristics | 0x2102 | 0x2102 | ✅ | other |
| structure | data directories | base_reloc,debug,export,iat,import,load_config,resource,tls | base_reloc,export,iat,import,tls | — | toolchain-bound |
| structure | section names | .text .rdata .data .rsrc .reloc | .text .rdata .data .eh_fram .gcc_exc .tls .reloc | — | toolchain-bound |
| structure | section[0] flags | .text 0x60000020 | .text 0x60000020 | ✅ | toolchain-bound |
| structure | section[1] flags | .rdata 0x40000040 | .rdata 0x40000040 | ✅ | toolchain-bound |
| structure | section[2] flags | .data 0xc0000040 | .data 0xc0000040 | ✅ | toolchain-bound |
| structure | section[3] flags | .rsrc 0x40000040 | .eh_fram 0x40000040 | — | toolchain-bound |
| structure | section[4] flags | .reloc 0x42000040 | .gcc_exc 0x40000040 | — | toolchain-bound |
| behaviour | NVXHookProc | 0x1000b9e0 | yes | ✅ | implemented (same label in the sources) |
| behaviour | DllMain | 0x1000ba00 | yes | ✅ | implemented (same label in the sources) |
| behaviour | MainInitThread | 0x1000a850 | yes | ✅ | implemented (same label in the sources) |
| behaviour | Hooked_LdrLoadDll | 0x1000a640 | yes | ✅ | implemented (same label in the sources) |
| behaviour | GetD3D9DeviceVTable | 0x10012980 | yes | ✅ | implemented (same label in the sources) |
| behaviour | InstallD3D9Hooks | 0x10016500 | yes | ✅ | implemented (same label in the sources) |
| behaviour | Hooked_Present | 0x10014d50 | yes | ✅ | implemented (same label in the sources) |
| behaviour | Hooked_Reset | 0x1001a3c0 | yes | ✅ | implemented (same label in the sources) |
| behaviour | MH_CreateHook | 0x10036020 | yes | ✅ | implemented (same label in the sources) |
| behaviour | Resolver_ScanModulePattern | 0x10002960 | cited | — | documented, not implemented |
| behaviour | HookInstaller_ClientLua | 0x10005b80 | cited | — | documented, not implemented |
| behaviour | OffsetResolver_Client | 0x1000c390 | cited | — | documented, not implemented |
| behaviour | NetcCheckKiller | 0x10020640 | cited | — | documented, not implemented |
| behaviour | BytePatcher_1byte | 0x10011870 | cited | — | documented, not implemented |
| behaviour | PatternRecordLoader | 0x10023670 | no | — | declared out of scope (case decision) |
| behaviour | HiddenPatternRecords_Data | 0x1013b750 - 0x1013bd10 | no | — | declared out of scope (case decision) |
| behaviour | StrDecryptor_Family | 82 functions, e.g. 0x10007640, 0x10007780, 0x100078d0, 0x10007900, 0x1000bc00, 0x1000bc80, 0x100223d0, 0x10023540 | cited | — | documented, not implemented |
| behaviour | LuaVM_Globals | 0x1013bf04 | no | — | declared out of scope (case decision) |
| behaviour | AutoInjectDriver | 0x10004550 -> 0x10004480 | cited | — | documented, not implemented |
| behaviour | ConfigRead_Overwack | call site 0x1001fcff | cited | — | documented, not implemented |

Closable with flags: entry RVA, size of image

Toolchain-bound: sections, linker version, data directories, section names, section[3] flags, section[4] flags
