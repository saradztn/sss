NRTH_audit — defensive audit module built from this case (the only *runnable* deliverable)
===========================================================================================

WHY THIS FOLDER HAS NO BINARIES
  The repository's .gitignore excludes *.dll / *.exe / bin/ (samples and build output are
  not committed). Rebuild in one command; the build is deterministic apart from the embedded
  PE timestamp, so compare *content* (exports, sizes) rather than hashes across machines.

  cd recovered_or_reconstructed_project
  ./build_audit.sh                 # host tests + self-test, then Zig cross-build
  ->  bin/NRTH_audit.dll           PE32 x86 DLL, 23 exports (ordinals 1..21)
      bin/nrth_audit.exe           console CLI, statically includes the same module
      bin/nrth_audit.lib           import library (for linking a scanner instead of LoadLibrary)

WHAT IT IS
  A read-only analyzer for the NORTH/NVX MTA:SA family. It answers two questions:
    1) Are the cheat's own search patterns present in this module, and is the function they
       locate still intact (PRISTINE) or re-pointed (E9 / FF 25 / 68..C3 / C3 / C2 / C7 05)?
    2) What does the sample hide: its per-record positional-XOR codec, and the hidden
       prologue-anchored pattern records that only appear once you decode.
  It never opens another process, never writes, never injects, never hooks, and contains no
  Lua payload. That is the whole point of shipping it as a binary: it is detection, not capability.

LAST VERIFIED BUILD (2026-10-11, Linux host, g++ 12.2 + ziglang 0.17.0)
  bin/NRTH_audit.dll   293,376 bytes
    sha256 c13167666a0a3e16ed870e7b74871410eb848063d71a7682c6773b40e408fe9f
  bin/nrth_audit.exe   304,640 bytes
    sha256 1c24702ac10df6fc1f07cd74f193d36f1aa3ffc7ae9c343881d9ebe6b3fcdf0a
  headers: machine 0x014c (I386), magic 0x10b (PE32), ImageBase 0x10000000 (same as the
  original NRTH.dll), DLL subsystem, DYNAMICBASE + NX_COMPAT, 23 exported C names.
  These hashes are pinnable: ./build_audit.sh normalises the binaries
  (tools/pe_deterministic.py zeroes TimeDateStamp, the CodeView PDB GUID and
  the build id), so two consecutive rebuilds of the same sources produced the
  same SHA-256 (measured 2026-10-11). A different compiler version changes code
  bytes - then compare size + the 23 exports and re-run the tests.
  Verification logs: ../../test_results/audit_build.log,
  ../../test_results/audit_sample_differential.log, ../../test_results/yara_check.log.

EXPORTS (src/nrth_audit.def; ordinals are pinned and append-only)
   1 NrthAuditVersion        8 NrthXorDecodeRecordAt   15 NrthPeSectionData
   2 NrthSigCount            9 NrthPatCompile          16 NrthPeRvaToPtr
   3 NrthSigAt              10 NrthPatScan             17 NrthPeTextRva
   4 NrthPrologueStateName   11 NrthPatWidenHead        18 NrthAuditImage
   5 NrthPrologueIsTamper   12 NrthPatPatchHead        19 NrthAuditImageFile
   6 NrthXorTransform        13 NrthClassifyPrologue    20 NrthFindHiddenSignatures
   7 NrthXorCrack           14 NrthPeMap               21 NrthAuditSelfTest
   22 NrthAuditDiff          23 NrthAuditDiffFiles      (A/B: baseline vs loaded module)

FIRST RUN ON A WINDOWS HOST (always start with these)
  nrth_audit.exe selftest
      -> "result: all checks passed"  (21 checks whose ciphertexts come from the sample)
  nrth_audit.exe audit "C:\Path\To\MTA San Andreas\mods\deathmatch\client.dll"
      -> table per signature; exit code 0 clean, 3 = tamper footprint found, 2 = unreadable/not PE
  nrth_audit.exe diff "<clean client.dll>" "<client.dll dumped from the suspect process>"
      -> only the located functions whose state CHANGED. Alignment is by the located function's
         RVA, so the two files need no common image base - but alert ONLY on the verdict line
         (= number of added_footprint rows, also the function's return value):
             target_lost      pattern present in the baseline, absent in the compared copy
             sus_unlocated    a footprint at an RVA the baseline never locates
         both mean "different build / unrelated code", and 1.2.0 exists precisely so neither can
         page anyone (measured: baseline=original NRTH.dll vs this repository's own reconstruction
         shows a DETOUR_JMP32 at 0x0d9f91 that is a thunk of the other build - verdict stays 0).
      -> --csv columns: sig_id,target,clean_full,clean_patched,sus_full,sus_patched,
         added_footprint,target_lost,sus_unlocated,state,sus_rva,detail
      -> PRISTINE means the located function's entry bytes are intact *in that image*: for the
         on-disk file this is expected even on an infected client, because detours and the 0xC3
         writes live in memory. Audit a read-only dump of the loaded module for live evidence.

CATALOGUE LIMITS (read before writing rules from this)
  * 20 rows compiled in = the High-confidence signatures recovered from decryptor records
    (7 owned by 0x10005b80, 12 by 0x1000c390, 1 by the netc.dll cluster at 0x10020640).
  * 8 further .data candidates are evidence only (over-read past the record boundary; they
    contain trailing junk such as "B900") and are deliberately NOT compiled into the table.
  * The six netc.dll check functions the sample RET-kills cannot be named from static bytes:
    their target patterns are fetched from .data globals at run time (0x1013b750..0x1013bd10).
  * A variant with a different K or a new pattern set needs the tables regenerated:
      python3 tools/nrth_strings_recover.py working/<variant>.dll -o working/recovered.json
      python3 tools/nrth_sig_export.py      working/<variant>.dll -o working/sigs.json
      python3 tools/gen_nrth_audit_sigs_h.py            # rewrites src/nrth_audit_sigs.h
    then re-run ./build_audit.sh (it refuses to ship if the unit tests fail).

NOT INCLUDED, DELIBERATELY
  The live game-Lua-VM exec hijack (trampoline global 0x1013c94c) and the netc.dll integrity-check
  disable are documented from evidence (addresses, keys, write sites, the writer's semantics) in
  ../../mechanism_overview_ar.md sections 3-4 and ../../mechanism_vm_injection.md, but they are NOT
  implemented anywhere in this repository: a working version of either one is the cheat itself, which
  means code injection into another process plus memory patches, and its output is a functional
  aim/health/money/menu weapon rather than a detector. The boundary travels with the code as well:
  src/nrth_audit.h carries the same list under "WHAT THIS MODULE DELIBERATELY DOES *NOT* DO".
