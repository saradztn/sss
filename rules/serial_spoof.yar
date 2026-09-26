/*
  rules/serial_spoof.yar
  قواعد YARA لجهة الحماية — مبنية من مؤشرات موثّقة في docs/client_lua_analysis.md.

  الاستخدام:
      yara -r rules/serial_spoof.yar /path/to/samples

  قاعدتان:
    1) CSX_Loader            — مطابقة عالية الثقة لعائلة CSX/XRF تحديداً (IOCs حرفية)
    2) SerialSpoofCapability — مطابقة عامة لقدرة "تغيير معرّف العميل" في أي ملف
*/


rule CSX_Loader
{
    meta:
        description = "CSX / XRF loader for Multi Theft Auto: San Andreas"
        author      = "RevSpec"
        reference   = "docs/client_lua_analysis.md"
        family      = "CSX"
        confidence  = "high"
        hash_note   = "المؤشرات نصوص UTF-16LE داخل .rdata"

    strings:
        // أسماء الحمولة والملفات الجانبية
        $p1  = "csxcheat.dll"      wide ascii nocase
        $p2  = "csxprobe.exe"      wide ascii nocase
        $p3  = "CSXcsxbugs.log"    wide ascii nocase
        $p4  = "csx_update.tag"    wide ascii nocase
        $p5  = "CSX.exe.new"       wide ascii

        // أسماء الأحداث المشتركة (named events)
        $e1  = "XAgentReady"                 wide ascii
        $e2  = "Local\\CSXAgentReady-"       wide ascii
        $e3  = "Local\\CSXClientLoaded-"     wide ascii
        $e4  = "DARKFLAME_AGENT_READY_EVENT" wide ascii
        $e5  = "DARKFLAME_CLIENT_LOADED_EVENT" wide ascii
        $e6  = "DARKFLAME_AGENT_PATH"        wide ascii

        // نصوص النيّة
        $i1  = "Resetting MTA serial..."     wide ascii
        $i2  = "Serial reset complete"       wide ascii
        $i3  = "R E S E T   S E R I A L"     wide ascii
        $i4  = "Server offline (fail-open)"  wide ascii
        $i5  = "I N J E C T"                 wide ascii

        // سلاسل التحديث
        $u1  = "/gh/onlyyoussef/csx-update@main/CSX.exe" ascii
        $u2  = "/onlyyoussef/csx-update/main/CSX.exe"    ascii
        $u3  = "CSX/1.0"                                  ascii

        // بصمة بنيوية: قسم PE باسم .mmap
        $s1  = ".mmap" ascii

    condition:
        uint16(0) == 0x5A4D
        and (
            (3 of ($p*)) or
            (2 of ($e*)) or
            (2 of ($i*)) or
            (any of ($u*)) or
            (1 of ($p*) and $s1)
        )
}


rule SerialSpoofCapability
{
    meta:
        description = "Generic: file can read hardware identifiers AND mutate stored values (serial change capability)"
        author      = "RevSpec"
        reference   = "revspec/analyzers/serial_spoof.py"
        confidence  = "medium — capability, not confirmed behaviour"

    strings:
        // قراءة المعرّفات
        $h1 = "MachineGuid"                          wide ascii nocase
        $h2 = "SOFTWARE\\Microsoft\\Cryptography"    wide ascii nocase
        $h3 = "SELECT SerialNumber FROM Win32_"      wide ascii nocase
        $h4 = "Win32_BIOS"                           wide ascii nocase
        $h5 = "Win32_DiskDrive"                      wide ascii nocase
        $h6 = "ROOT\\CIMV2"                          wide ascii nocase
        $h7 = "GetVolumeInformation"                 ascii

        // القدرة على التعديل/الحذف
        $m1 = "RegDeleteKeyA"    ascii
        $m2 = "RegDeleteKeyW"    ascii
        $m3 = "RegDeleteValueA"  ascii
        $m4 = "RegDeleteValueW"  ascii
        $m5 = "RegSetValueExA"   ascii
        $m6 = "RegSetValueExW"   ascii
        $m7 = "CredDeleteW"      ascii

        // نيّة صريحة
        $x1 = "Resetting MTA serial"          wide ascii nocase
        $x2 = "Serial reset complete"         wide ascii nocase
        $x3 = "R E S E T   S E R I A L"       wide ascii nocase
        $x4 = "spoof"                         wide ascii nocase
        $x5 = "HWID"                          wide ascii nocase

        // أهداف اللعبة
        $g1 = "SOFTWARE\\Multi Theft Auto"    wide ascii nocase
        $g2 = "Multi Theft Auto.exe"          wide ascii nocase
        $g3 = "gta_sa.exe"                    wide ascii nocase

    condition:
        uint16(0) == 0x5A4D
        and (
            // نيّة صريحة وحدها تكفي
            any of ($x1,$x2,$x3)
            // أو: قراءة معرّف + قدرة تعديل
            or (any of ($h*) and any of ($m*))
            // أو: قراءة معرّف + استهداف اللعبة
            or (2 of ($h*) and any of ($g*))
        )
}
