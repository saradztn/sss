# collect_client.ps1 — read-only client-side collector for the NRTH case (defender side, v1).
#
# SCOPE / SAFETY CONTRACT
#   * Reads files, module lists, registry values and directory metadata only.
#   * NEVER opens a process handle with VM_READ/VM_WRITE, never calls VirtualProtect/WriteProcessMemory,
#     never injects, never modifies the game directory, and never touches anti-cheat traffic.
#     If a future step seems to require any of that, it belongs to a different (out-of-scope) case.
#   * Runs as the ordinary game user. Elevation adds the ADS + HKLM rows but is not required.
#
# Evidence the checks correspond to (ORIGINAL sample, all Observed in working/NRTH.dll):
#   "C:\NVX"                        decrypted at 0x100b0d18          -> directory presence probe
#   "C:\ProgramData:NT2"            ADS, indicators.json              -> alternate-data-stream probe
#   "C:\Overwack\loader_config.cfg" decrypted at 0x1001fcff           -> file + token parse
#   " no_spoofer=%d" / " menu_key=%d" 0x1001fdc5 / 0x1001fd7b         -> token names we echo back
#   "nvx.dll" (export-dir module name, .rdata 0x100f6cb2)             -> byte search in candidate DLLs
#   "NVXHookProc" export @1 (rva 0x1000b9e0 in the sample)            -> byte search in candidate DLLs
param(
    [string]$OutDir  = (Join-Path $env:TEMP ("acclient_" + $env:COMPUTERNAME)),
    [string]$GameDir = "",
    [string]$ProcName = "mtasa"
)
$ErrorActionPreference = "SilentlyContinue"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$utc  = (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmss")
$host_ = $env:COMPUTERNAME
$result = [ordered]@{
    host = $host_; utc = $utc; elevated = $false; game_dir = ""; proc_found = $false
    modules = @(); iocs = @(); hashes = @(); cfg = @(); candidates = @()
}
$id = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$result.elevated = $id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# --- locate the game directory (parameter > running process path > MTA uninstall key) -----------
if (-not $GameDir) {
    $p = Get-Process -Name $ProcName | Select-Object -First 1
    if ($p -and $p.Path) { $GameDir = Split-Path $p.Path -Parent }
}
if (-not $GameDir) {
    foreach ($rk in "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MTA:San Andreas",
                    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\MTA:San Andreas") {
        $ip = (Get-ItemProperty $rk)."InstallLocation"
        if ($ip) { $GameDir = $ip; break }
    }
}
$result.game_dir = $GameDir

# --- loaded modules of the game process (module list only — no memory reads) --------------------
$proc_ = Get-Process -Name $ProcName | Select-Object -First 1
if ($proc_) {
    $result.proc_found = $true
    foreach ($m in $proc_.Modules) {
        $result.modules += [ordered]@{ name = $m.ModuleName; path = $m.FileName;
                                       size = $m.Size; base = ("0x{0:X}" -f $m.BaseAddress.ToInt64()) }
    }
}

# --- file hashes for the two modules the payload targets, when present --------------------------
foreach ($f in "client.dll", "netc.dll", "main.o", "mtasa.exe") {
    $full = if ($GameDir) { Join-Path $GameDir $f } else { $null }
    if ($full -and (Test-Path $full)) {
        $h = Get-FileHash -Algorithm SHA256 -Path $full
        $v = (Get-Item $full).VersionInfo
        $result.hashes += [ordered]@{ file = $f; sha256 = $h.Hash; bytes = (Get-Item $full).Length
                                      version = $v.FileVersion; mtime = (Get-Item $full).LastWriteTimeUtc.ToString("o") }
    }
}

# --- persistence / artifact IOCs (existence only; we do not delete or create anything) ------------
foreach ($ioc in @(
    [ordered]@{ id = "dir-C:\\NVX";            kind = "path";  target = "C:\NVX" },
    [ordered]@{ id = "ads-ProgramData:NT2";    kind = "stream"; target = "C:\ProgramData"; stream = "NT2" },
    [ordered]@{ id = "cfg-Overwack";           kind = "path";  target = "C:\Overwack\loader_config.cfg" },
    [ordered]@{ id = "runkey-MTA";             kind = "reg";   target = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" },
    [ordered]@{ id = "iesettings-ZoneMap";     kind = "reg";   target = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" },
    [ordered]@{ id = "clsid-handlers";         kind = "reg";   target = "HKCU:\SOFTWARE\Classes\CLSID" })) {
    $hit = $false; $detail = ""
    if ($ioc.kind -eq "path") {
        $hit = Test-Path $ioc.target
    } elseif ($ioc.kind -eq "stream") {
        $s = Get-Item -Path $ioc.target -Streams * | Where-Object { $_.StreamType -eq "Data" -and $_.Name -like "*$($ioc.stream)*" }
        $hit = [bool]$s; if ($s) { $detail = ($s | ForEach-Object { $_.Name + ":" + $_.Length }) -join ";" }
    } else {
        $props = (Get-ItemProperty $ioc.target).PSObject.Properties.Name |
                 Where-Object { $_ -match "mta|MTA|nvx|NRTH|Overwack" }
        $hit = [bool]$props; $detail = ($props -join ",")
    }
    $result.iocs += [ordered]@{ id = $ioc.id; kind = $ioc.kind; target = $ioc.target;
                                present = $hit; detail = $detail }
}

# --- the config record our reconstruction also reads/writes: echo its tokens back -----------------
$cfgPath = "C:\Overwack\loader_config.cfg"
if (Test-Path $cfgPath) {
    $txt = Get-Content -Raw -Path $cfgPath
    foreach ($m in [regex]::Matches($txt, "\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(-?\d+)")) {
        $result.cfg += [ordered]@{ key = $m.Groups[1].Value; raw = $m.Groups[0].Value;
                                   value = [int]$m.Groups[2].Value }
    }
}

# --- suspicious DLL candidates near the game dir: byte-search two literals, no loading ------------
# ASCII text search over the file image (fast). The literals are the export-directory module name and
# the exported thunk name measured in the sample; a byte-by-byte PS loop would take minutes per file.
$needles = @( "nvx.dll", "NVXHookProc" )
$search  = @()
if ($GameDir) { $search += Get-ChildItem -Path $GameDir -Filter *.dll -File | Select-Object -First 60 }
$search += Get-ChildItem -Path "$env:APPDATA","$env:LOCALAPPDATA" -Filter "*.dll" -File -Recurse -Depth 2 |
           Where-Object { $_.Length -gt 400000 } | Select-Object -First 40
foreach ($fi in $search) {
    $txt = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($fi.FullName))
    $found = @()
    foreach ($k in $needles) {
        $idx = $txt.IndexOf($k, [StringComparison]::Ordinal)
        if ($idx -ge 0) { $found += ("{0}@off 0x{1:X}" -f $k, $idx) }
    }
    if ($found.Count -gt 0) {
        $result.candidates += [ordered]@{ file = $fi.FullName; bytes = $fi.Length
                                          sha256 = (Get-FileHash -Algorithm SHA256 -Path $fi.FullName).Hash
                                          hits = ($found -join ",") }
    }
}

$json = Join-Path $OutDir ("client_{0}_{1}.json" -f $host_, $utc)
$result | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -Path $json
# flat CSV for quick diffing between the clean baseline run and the watched run
$lines = @("section,id,present_or_value,detail")
foreach ($i in $result.iocs)      { $lines += ("ioc,{0},{1},{2}" -f $i.id, $i.present, $i.detail) }
foreach ($h in $result.hashes)   { $lines += ("hash,{0},{1},bytes={2}"   -f $h.file, $h.sha256, $h.bytes) }
foreach ($c in $result.candidates){ $lines += ("candidate,{0},{1},{2}"   -f (Split-Path $c.file -Leaf), $c.sha256, $c.hits) }
foreach ($c in $result.cfg)      { $lines += ("cfg,{0},{1},{2}"          -f $c.key, $c.value, $c.raw.Trim()) }
$csv = Join-Path $OutDir ("client_{0}_{1}.csv" -f $host_, $utc)
$lines | Set-Content -Encoding UTF8 -Path $csv
Write-Host "[+] wrote $json and $csv"
Write-Host "[i] report-path entry list for nrth_report_path_check.py: see expected_findings.md"
Write-Host "[i] nothing was written outside $OutDir; no process memory was read"
