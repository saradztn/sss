/*
   MTA:SA Blue-Team Case — candidate detection rules for the NORTH/NRTH/NVX sample family.
   Case: mta_blue_team_case (analysis date 2026-10-10)
   Scope: the two observed samples only. These rules are NOT claimed to catch all variants.
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
