@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo === Building CSX Full (Windows 32-bit) ===
g++ -O2 -std=c++17 "%~dp0CSX_Full.cpp" -o "%~dp0CSX_rebuilt.exe" -ladvapi32
if exist "%~dp0CSX_rebuilt.exe" (
  echo OK - CSX_rebuilt.exe built
  "%~dp0CSX_rebuilt.exe"
) else (
  echo FAILED
)
pause
