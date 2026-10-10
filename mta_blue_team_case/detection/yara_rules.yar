/*
   MTA:SA Blue-Team Case — candidate detection rules for the NORTH/NRTH/NVX sample family.
   Case: mta_blue_team_case (analysis date 2026-10-10)
   Scope: the two observed samples only. These rules are NOT claimed to catch all variants.
   4 rules: loader, payload, export contract, and the XOR-hidden .data pattern records of the
   netc.dll patch cluster (added after the string-decryption pass; see recovered_strings.txt).
   Compile/scan check actually run with yara-python 4.5.4 (log: test_results/yara_check.log):
     NRTH.dll          -> NORTH_NRTH_Payload_DLL, NORTH_Export_Contract_NVXHookProc,
                          NORTH_NRTH_HiddenPatternRecords
     NORTH LOADER.exe  -> NORTH_Loader_Injector_EXE
   Review false-positive notes in detection/telemetry.md before production deployment.
*/

rule NORTH_Loader_Injector_EXE
{
    meta:
        description = "NORTH/NVX loader: console DLL injector with CreateRemoteThread + SetWindowsHookEx fallback"
        case          = "mta_blue_team_case"
        sha256        = "837650b9f1ca52d2c91c966ba7f16721986e754f3efdfb42a08536610067c5fb"
        confidence    = "High (exact-sample indicators)"
        date          = "2026-10-10"
    strings:
        $banner     = "=== NORTH Loader ===" ascii
        $title      = "NORTH Loader" ascii
        $exp        = "NVXHookProc" ascii
        $pdb        = "NVX Loader.pdb" ascii
        $dbgpriv    = "SeDebugPrivilege" ascii
        $msg1       = "[+] Inyectado OK clasico" ascii
        $msg2       = "[+] Inyectado OK por hook" ascii
        $msg3       = "Entra al juego y pulsa INSERT" ascii
        $opt1       = "--autoclose" ascii
        $opt2       = "--proc" ascii
        $opt3       = "--dll" ascii
    condition:
        uint16(0) == 0x5A4D and
        ( ($banner and $exp) or
          (4 of ($msg1, $msg2, $msg3, $title, $pdb, $dbgpriv) and 2 of ($opt1, $opt2, $opt3)) )
}

rule NORTH_NRTH_Payload_DLL
{
    meta:
        description = "NORTH/NRTH payload DLL: pinned module, MinHook LdrLoadDll detour, D3D9 ImGui overlay self-named 'North Cheat'"
        case          = "mta_blue_team_case"
        sha256        = "947b81be2d0f84cc5f51742ef8e9dbf6183597ed98afaf1377bfc4352e007861"
        confidence    = "High (exact-sample indicators)"
        caveat        = "Most operational strings in this family are XOR/SSE-encrypted; plaintext indicators below may be absent in key-changed variants. Pair with the export rule and behavioral telemetry."
        date          = "2026-10-10"
    strings:
        $export      = "NVXHookProc" ascii
        $overlay     = "North Cheat" ascii
        $imgui       = "Dear ImGui 1.92.9 WIP (19283)" ascii
        $imgui_gen   = "Forgot to call ImGui::NewFrame()?" ascii
        $rtti_aim    = ".?AUSWeaponAimSync@@" ascii
        $pkt1        = "PACKET_ID_CHEAT_CHALLENGEMEMORY" ascii
        $pkt2        = "PACKET_ID_CHEAT_RETURN" ascii
        $pkt3        = "PACKET_ID_MTA_RESERVED_03" ascii
        $menukey     = "Menu Toggle Key" ascii
        $id1         = "%s##nvx_top_%d" ascii
        $id2         = "##nvx_content" ascii
    condition:
        uint16(0) == 0x5A4D and
        ($export) and
        ( ($overlay and $imgui) or
          (2 of ($rtti_aim, $pkt1, $pkt2, $pkt3, $menukey)) or
          (2 of ($id1, $id2) and $imgui_gen) )
}

rule NORTH_Export_Contract_NVXHookProc
{
    meta:
        description = "Export-name contract used by the hook-style injection path (generic; may match unrelated NVX-family tools)"
        case        = "mta_blue_team_case"
        confidence  = "Medium (single indicator; needs corroboration)"
        date        = "2026-10-10"
    strings:
        $exp  = "NVXHookProc" ascii
        $exp2 = "nvx.dll" ascii
    condition:
        uint16(0) == 0x5A4D and ($exp) and filesize < 5MB and ($exp2)
}

rule NORTH_NRTH_HiddenPatternRecords
{
    meta:
        description = "XOR-hidden x86 search-pattern records that the netc.dll patch cluster reads from .data (0x1013b750-0x1013bd10): the cheat's own target patterns. Decoded by tools/nrth_sig_export.py; checked by nrth_audit.exe sweep."
        case          = "mta_blue_team_case"
        sha256        = "947b81be2d0f84cc5f51742ef8e9dbf6183597ed98afaf1377bfc4352e007861"
        confidence    = "High for this exact sample; Medium as a family indicator (a variant rotates K and re-lays out .data)"
        date          = "2026-10-10"
        reference     = "detection/recovered_strings.txt Section C.2"
    strings:
        $rec0  = { CF CE DC C5 BC DF 45 42 22 35 45 25
                    39 27 3E 31 2A 34 2C 32 2E 30 30 2E
                    32 25 20 35 57 26 38 26 3A 24 3C 22
                    3E 20 00 14 12 03 1C 14 06 62 6B 09
                    15 0B 13 0D 11 0F 0F 11 73 02 14 0A
                    16 08 18 06 1A 04 1C 0E 0D 1F 03 74
                    62 7B 7D 65 72 72 68 76 6A 7E 7A 6D
                    7B 78 70 64 62 73 6C 11 76 63 6D 79
                    65 7B 6A 69 7E 1E 53 41 5D 43 5B 45
                    59 47 57 49 52 29 4C 2B 57 4F 48 48
                    52 44 }
                           /* .data 0x1013b8b8: 122-byte hidden record (K=0x06), unique in the sample */
        $rec1  = { CF CE DC C5 BC DF 45 42 22 35 45 25
                    39 27 3E 31 2A 34 2C 32 2E 30 30 2E
                    32 25 2C 35 29 37 27 39 25 3B 23 3D
                    28 2B 00 60 13 03 1B 05 19 07 17 09
                    15 0B 19 1D 0E 17 03 11 77 70 14 0A
                    16 02 0B 19 0F 0D 1C 08 09 1F 01 70
                    62 7C 64 7A 66 78 68 76 6A 78 7D 6D
                    7A 7A 70 6E 72 60 67 75 15 62 78 6C
                    6A 7B 64 19 7E 6B }
                           /* .data 0x1013b9d0: 102-byte hidden record (K=0x06), unique in the sample */
        $duphead = { CF C8 DC C5 BC DF 44 42 22 3B 37 25 43 44 28 36 2A 33 3F 2D 4B 3B 30 2E }
                           /* 5 of the 8 records share their first 89 bytes (the same target pattern
                                   stored repeatedly), so this short head hits several times */
    condition:
        uint16(0) == 0x5A4D and filesize < 4MB and
        (any of ($rec*) or #duphead >= 4)
}
