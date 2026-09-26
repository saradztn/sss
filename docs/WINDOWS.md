# دليل Windows — كيف تشغّل RevSpec خطوة بخطوة

> **RevSpec يعمل 100% على Windows** بدون Linux. هذا الدليل للمبتدئين.

---

## الطريقة السهلة (موصى بها) — Python مباشرة على Windows

### الخطوة 1: ثبّت Python

1. افتح https://www.python.org/downloads/
2. حمّل Python 3.10 أو 3.11
3. أثناء التثبيت **فعّل** ✅ `Add python.exe to PATH`
4. تأكد:
   - افتح `cmd` أو `PowerShell` واكتب:
     ```powershell
     python --version
     pip --version
     ```

### الخطوة 2: ثبّت Git

- حمّل من https://git-scm.com/download/win
- ثبّت بالخيارات الافتراضية
- تأكد:
  ```powershell
  git --version
  ```

### الخطوة 3: انسخ المشروع

افتح `PowerShell` في المكان الذي تريد (مثلاً `C:\Users\اسمك\Desktop`):

```powershell
git clone https://github.com/saradztn/sss.git
cd sss
git checkout arena/01a0d936-sss
dir
```

يجب أن ترى مجلدات `revspec`, `samples`, `templates` ...

### الخطوة 4: ثبّت RevSpec

في نفس الـ PowerShell:

```powershell
# تثبيت أساسي
pip install -e .

# لتتمكن من تحليل ملفات .exe بشكل أفضل (اختياري لكن مهم على Windows):
pip install pefile capstone
# أو كل الإضافات:
pip install -e .[native]
```

إذا ظهر خطأ `externally-managed-environment` استخدم:
```powershell
pip install -e . --break-system-packages
```

تأكد:
```powershell
python -m revspec.cli --help
python -m revspec.cli list-analyzers
```

يجب أن ترى قائمة 11 محللًا.

### الخطوة 5: جرّب على عينة تجريبية (بدون بناء C)

على Windows لا تحتاج `gcc`. استخدم عينة Python الجاهزة:

```powershell
# هذه عينة تملكها أنت - آمنة للاختبار
python -m revspec.cli analyze samples\demo_app_win\demo_win.py --output .\runs

# أو حلل أي برنامج تملكه، مثلاً:
python -m revspec.cli analyze C:\path\to\your_program.exe --output .\runs
```

**مثال واقعي:**
```powershell
python -m revspec.cli analyze samples\demo_app\demo.c --output .\runs
```

سيُنشئ مجلد `runs\20260925T..._hash\` يحتوي:

```
runs\20260925T154109Z_10a158d7\
  ├── report.md      ← التقرير البشري (افتحه بـ Notepad)
  ├── report.json    ← للذكاء الاصطناعي
  ├── report.yaml
  └── evidence\...   ← الأدلة الخام
```

افتح التقرير:
```powershell
notepad runs\*\report.md
# أو
start runs\*\report.md
```

### الخطوة 6: التحليل الديناميكي (اختياري)

على Windows **لا** يوجد `strace`/`bwrap`، لكن RevSpec يعمل بطريقة آمنة بديلة (timeout + مراقبة):

```powershell
# للبرامج التي تثق بها فقط
python -m revspec.cli analyze samples\demo_app_win\demo_win.py --output .\runs --enable-dynamic --dynamic-args="--help"
```

> ⚠️ لا تشغّل برامج غير موثوقة بالديناميكي على جهازك الأساسي.

---

## الطريقة الثانية — WSL (للحصول على تحليل Linux كامل)

إذا أردت نفس النتائج التي في `examples/reports/demo_report.md` (مع readelf/objdump/strace):

1. ثبّت WSL:
   ```powershell
   wsl --install
   ```
   أعد التشغيل، ثم افتح `Ubuntu`.

2. داخل Ubuntu:
   ```bash
   sudo apt update && sudo apt install -y python3-pip binutils file strace gcc unzip git
   git clone https://github.com/saradztn/sss.git
   cd sss
   git checkout arena/01a0d936-sss
   pip install -e . --break-system-packages
   make -C samples/demo_app
   python3 -m revspec.cli analyze samples/demo_app/demo_app --output ./runs --enable-dynamic
   cat runs/*/report.md
   ```

---

## أسئلة شائعة — Windows

### `revspec` غير معروف؟
استخدم دائماً:
```powershell
python -m revspec.cli analyze ...
```
بدل `revspec analyze ...`

### `pip install` يفشل؟
```powershell
python -m pip install --upgrade pip
pip install -e . --break-system-packages
```

### أريد تحليل `.exe` خاص بي؟
```powershell
python -m revspec.cli analyze "C:\Users\YOU\Desktop\myapp.exe" --output .\runs
# سيعمل حتى بدون أدوات Linux، وسيستخدم pefile تلقائياً إذا ثبّته
```

### أين أجد `report.json` للـ AI الثاني؟
```powershell
dir runs\*\report.json
# انسخ الملف وأعطه للنموذج مع prompts\reimplementation_prompt.md
```

### هل أحتاج Visual Studio أو gcc؟
**لا.** فقط إذا أردت بناء `samples/demo_app/demo.c`. للاختبار على Windows استخدم `samples/demo_app_win/demo_win.py` الجاهز.

### كيف أحوّل التقرير إلى Specification؟
1. افتح `prompts\reimplementation_prompt.md`
2. انسخه + ألصق `report.json` بعده
3. أرسله لـ ChatGPT/Claude

---

## ملفات مساعدة جديدة

- `examples\run_demo.bat` — دبل كليك لتشغيل التجربة على Windows
- `samples\demo_app_win\demo_win.py` — عينة Windows جاهزة بدون compilation
- `docs\WINDOWS.md` — هذا الملف

---

## فيديو تخيلي (خطوات PowerShell)

```powershell
# 1
python --version          # Python 3.11.x
# 2
git clone https://github.com/saradztn/sss.git; cd sss
# 3
pip install -e .; pip install pefile capstone
# 4
python -m revspec.cli analyze samples\demo_app_win\demo_win.py --output .\runs
# 5
notepad .\runs\*\report.md
```

انتهى! 🎉
