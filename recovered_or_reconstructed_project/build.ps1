# PowerShell Build Script for Windows MSVC (x86)
param(
    [string]$Configuration = "Release"
)

Write-Host "Building NORTH Loader (x86)..." -ForegroundColor Cyan
cl.exe /nologo /O2 /W3 /MT /EHsc src\north_loader.cpp /link /OUT:bin\NORTH_LOADER.exe advapi32.lib user32.lib psapi.lib

Write-Host "Building NRTH.dll (x86)..." -ForegroundColor Cyan
cl.exe /nologo /O2 /W3 /MT /LD /EHsc src\nrth_hook.cpp /link /OUT:bin\NRTH.dll user32.lib d3d9.lib

Write-Host "Build complete." -ForegroundColor Green
