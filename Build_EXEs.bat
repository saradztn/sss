@echo off
cd /d "%~dp0"
echo === Building identical EXEs from C++ ===
echo Current dir: %CD%
echo.
echo [1/2] demo_app...
g++ -O2 -std=c++17 "%~dp0demo_app_rebuilt.cpp" -o "%~dp0demo_app_rebuilt.exe"
if exist "%~dp0demo_app_rebuilt.exe" (echo OK - demo_app_rebuilt.exe) else (echo FAILED - check g++ and file)
echo.
echo [2/2] uploaded program...
g++ -O2 -std=c++17 "%~dp0uploaded_rebuilt.cpp" -o "%~dp0uploaded_rebuilt.exe"
if exist "%~dp0uploaded_rebuilt.exe" (echo OK - uploaded_rebuilt.exe) else (echo FAILED)
echo.
echo Done. Run:
echo   "%~dp0demo_app_rebuilt.exe" --help
echo   "%~dp0uploaded_rebuilt.exe"
pause
