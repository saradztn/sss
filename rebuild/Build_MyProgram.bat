@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo === Building MyProgram Full Windows 32-bit ===
g++ -O2 -std=c++17 "%~dp0MyProgram_Full.cpp" -o "%~dp0MyProgram.exe"
if exist "%~dp0MyProgram.exe" (
  echo OK - MyProgram.exe built 32/64-bit
  "%~dp0MyProgram.exe"
) else (
  echo FAILED
)
pause
