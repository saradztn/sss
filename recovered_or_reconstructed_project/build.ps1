# PowerShell Build Script for Windows MSVC (x86)
# Alternative to build.sh (which uses Zig's MinGW sysroot and WAS the executed path).
# Requires: VS x86 Native Tools prompt; vendor trees fetched first (fetch_vendor.sh).
param(
    [string]$Configuration = "Release"
)

New-Item -ItemType Directory -Force -Path bin, bin\obj | Out-Null

Write-Host "Building MinHook (x86)..." -ForegroundColor Cyan
cl.exe /nologo /O2 /W3 /MT /c /Ivendor\minhook\include vendor\minhook\src\buffer.c /Fo:bin\obj\mh_buffer.obj
cl.exe /nologo /O2 /W3 /MT /c /Ivendor\minhook\include vendor\minhook\src\hook.c /Fo:bin\obj\mh_hook.obj
cl.exe /nologo /O2 /W3 /MT /c /Ivendor\minhook\include vendor\minhook\src\trampoline.c /Fo:bin\obj\mh_trampoline.obj
cl.exe /nologo /O2 /W3 /MT /c /Ivendor\minhook\include vendor\minhook\src\hde\hde32.c /Fo:bin\obj\mh_hde32.obj
cl.exe /nologo /O2 /W3 /MT /c /Ivendor\minhook\include vendor\minhook\src\hde\hde64.c /Fo:bin\obj\mh_hde64.obj

Write-Host "Building Dear ImGui v1.92.9..." -ForegroundColor Cyan
cl.exe /nologo /O2 /W3 /MT /EHsc /c /Ivendor\imgui vendor\imgui\imgui.cpp /Fo:bin\obj\imgui.obj
cl.exe /nologo /O2 /W3 /MT /EHsc /c /Ivendor\imgui vendor\imgui\imgui_draw.cpp /Fo:bin\obj\imgui_draw.obj
cl.exe /nologo /O2 /W3 /MT /EHsc /c /Ivendor\imgui vendor\imgui\imgui_tables.cpp /Fo:bin\obj\imgui_tables.obj
cl.exe /nologo /O2 /W3 /MT /EHsc /c /Ivendor\imgui vendor\imgui\imgui_widgets.cpp /Fo:bin\obj\imgui_widgets.obj
cl.exe /nologo /O2 /W3 /MT /EHsc /c /Ivendor\imgui /Ivendor\imgui\backends vendor\imgui\backends\imgui_impl_dx9.cpp /Fo:bin\obj\imgui_impl_dx9.obj
cl.exe /nologo /O2 /W3 /MT /EHsc /c /Ivendor\imgui /Ivendor\imgui\backends vendor\imgui\backends\imgui_impl_win32.cpp /Fo:bin\obj\imgui_impl_win32.obj

Write-Host "Building NRTH.dll (x86)..." -ForegroundColor Cyan
cl.exe /nologo /O2 /W3 /MT /EHsc /LD /Isrc /Ivendor\minhook\include /Ivendor\imgui /Ivendor\imgui\backends `
    src\nrth_hook.cpp src\nrth_ui.cpp bin\obj\mh_*.obj bin\obj\imgui*.obj `
    /link /DEF:src\nrth_dll.def /OUT:bin\NRTH.dll user32.lib gdi32.lib advapi32.lib dwmapi.lib imm32.lib

Write-Host "Building NORTH_LOADER.exe (x86)..." -ForegroundColor Cyan
cl.exe /nologo /O2 /W3 /MT /EHsc src\north_loader.cpp /link /OUT:bin\NORTH_LOADER.exe advapi32.lib user32.lib psapi.lib

Write-Host "Build complete." -ForegroundColor Green
Get-ChildItem bin\NORTH_LOADER.exe, bin\NRTH.dll | Format-Table Name, Length
Get-FileHash -Algorithm SHA256 bin\NORTH_LOADER.exe, bin\NRTH.dll | Format-Table
