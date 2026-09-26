@echo off
REM RevSpec Demo for Windows — دبل كليك للتشغيل
REM يعمل بدون Linux tools، يستخدم عينة Python

echo ========================================================
echo  RevSpec — تجربة سريعة على Windows
echo  للاستخدام فقط على البرامج التي تملكها
echo ========================================================
echo.

REM تحقق من Python
python --version >nul 2>&1
if errorlevel 1 (
  echo [خطأ] Python غير مثبت. حمّله من https://www.python.org/downloads/
  echo وتأكد من تفعيل Add to PATH
  pause
  exit /b 1
)

echo [1/4] تثبيت RevSpec ...
pip install -e . --quiet
if errorlevel 1 pip install -e . --break-system-packages --quiet

echo [2/4] تثبيت محللات Windows (pefile, capstone) ...
pip install pefile capstone --quiet

echo [3/4] تشغيل التحليل على عينة Windows ...
python -m revspec.cli analyze samples\demo_app_win\demo_win.py --output .\runs
if errorlevel 1 (
  echo [خطأ] فشل التحليل
  pause
  exit /b 1
)

echo [4/4] تشغيل التحليل الديناميكي (آمن) ...
python -m revspec.cli analyze samples\demo_app_win\demo_win.py --output .\runs --enable-dynamic --dynamic-args="--debug"

echo.
echo ========================================================
echo  تم! التقارير في مجلد runs\
echo ========================================================
dir runs /b
echo.
echo افتح احدث تقرير:
for /f "delims=" %%i in ('dir runs /b /o-d') do (
  echo   runs\%%i\report.md  (التقرير البشري)
  echo   runs\%%i\report.json (للذكاء الاصطناعي)
  echo.
  start notepad "runs\%%i\report.md"
  goto :end
)
:end
pause
