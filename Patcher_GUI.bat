@echo off
REM === طلب تشغيل كمسؤول (اختياري) ===
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo.
  echo [تنبيه] البرنامج يعمل بدون مسؤول - الحفظ في Program Files سيحتاج Desktop.
  choice /M "هل تريد اعادة التشغيل كمسؤول"
  if errorlevel 2 goto :skip_elevate
  echo جاري طلب التشغيل كمسؤول...
  powershell -Command "Start-Process '%~f0' -Verb RunAs" 2>nul
  if %errorlevel% equ 0 exit /b
  echo تم الالغاء - سيعمل بدون مسؤول
  :skip_elevate
)
REM === استمرار ===

REM Patcher GUI — محرر البرامج مثل Ghidra
REM يتيح تغيير النصوص والاسم والواجهة

title RevSpec Patcher

echo ========================================================
echo  RevSpec Patcher — محرر النصوص والواجهة
echo  للبرامج التي تملكها فقط
echo  يتيح تغيير الاسم، النصوص، VersionInfo وحفظ نسخة جديدة
echo ========================================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
  echo [خطأ] Python غير مثبت! https://www.python.org/downloads/
  pause
  exit /b 1
)

if not exist "revspec\patcher\string_patcher.py" (
  echo [خطأ] شغّل من داخل مجلد sss
  pause
  exit /b 1
)

echo [1/2] تثبيت المتطلبات...
pip show pefile >nul 2>&1
if errorlevel 1 pip install pefile capstone --quiet

echo [2/2] فتح المحرر...
python gui\patcher_gui.py
if errorlevel 1 (
  echo.
  echo جرب: python gui/patcher_gui.py
  pause
)
