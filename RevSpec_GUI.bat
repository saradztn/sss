@echo off
REM RevSpec GUI — دبل كليك للتشغيل على Windows
REM لا تحتاج كتابة أوامر، فقط اختر البرنامج

title RevSpec GUI

echo ========================================================
echo  RevSpec GUI — واجهة رسومية
echo  اختر برنامجك وهو يفعل الباقي
echo ========================================================
echo.

REM تحقق من Python
python --version >nul 2>&1
if errorlevel 1 (
  echo [خطأ] Python غير مثبت!
  echo حمّله من: https://www.python.org/downloads/
  echo وتأكد من تفعيل "Add python to PATH"
  pause
  exit /b 1
)

REM تثبيت سريع إذا لزم
if not exist "revspec\__init__.py" (
  echo [خطأ] شغّل هذا الملف من داخل مجلد المشروع sss
  pause
  exit /b 1
)

echo [1/2] تثبيت المتطلبات (اول مرة فقط)...
pip show jinja2 >nul 2>&1
if errorlevel 1 (
  pip install -e . --quiet
  pip install pefile capstone --quiet
)

echo [2/2] فتح الواجهة...
echo.

REM شغّل الواجهة (pyw يخفي الكونسول، py يظهر السجل)
python gui\revspec_gui.py
if errorlevel 1 (
  echo.
  echo [خطأ] فشل فتح الواجهة، جرب:
  echo   python gui/revspec_gui.py
  pause
)

