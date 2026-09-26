# دليل المحرر — RevSpec Patcher

> **مثل Ghidra لكن أبسط:** يتيح تغيير النصوص، الاسم، ومعلومات البرنامج وحفظ نسخة جديدة.
> للبرامج التي تملكها فقط.

---

## ما الذي يفعله؟

| الميزة | الوصف | الحالة |
|--------|-------|--------|
| **تغيير النصوص** | دبل كليك على أي نص ASCII/UTF-16LE وتعديله | ✅ كامل |
| **تغيير الاسم (Batch Rename)** | يغيّر كل ظهور لاسم قديم إلى جديد في كل الملف | ✅ كامل |
| **VersionInfo (PE .exe)** | يغيّر CompanyName, ProductName, FileVersion ... كما يظهر في خصائص الملف | ✅ كامل |
| **تغيير الأيقونة** | يحتاج Resource Hacker (قريباً) | 🔜 |
| **تعديل الواجهة الرسومية** | النصوص في الأزرار والقوائم هي نفسها strings — تعديلها يغيّر الواجهة | ✅ عبر النصوص |

---

## القيود المهمة

- **النص الجديد يجب أن يكون بنفس الطول أو أقصر.** الزائد يُحشى بـ `\x00`. إذا كان أطول، اختصر أو استخدم اسم أقصر.
  - مثال: `MyApp` (5) → `NewApp` (6) ❌ أطول — استخدم `NewAp` أو `MyApp2` (5) ✅
- **النصوص المشفرة/المضغوطة** لا تظهر (تحتاج فك تشفير)
- **تغيير حجم النافذة/مواضع الأزرار** يحتاج تعديل موارد `.rsrc` — غير مدعوم هنا (استخدم Resource Hacker/PE-bear)

---

## الطريقة 1: الواجهة الرسومية (موصى بها)

### التشغيل
- دبل كليك على `Patcher_GUI.bat` في جذر المشروع
- أو `python gui/patcher_gui.py`

### الخطوات
1. **استعراض** → اختر `program.exe`
2. انتظر تحميل الجدول (سيظهر `120 نص` مثلاً)
3. **بحث** → اكتب جزء من النص (مثلاً `MyApp`)
4. **دبل كليك** على النص → نافذة تعديل → اكتب الجديد → حفظ
5. **أو** استخدم `Batch Rename` → قديم: `MyApp` جديد: `MyNewName` → غيّر كل الظهور
6. تبويب `VersionInfo` → عدّل `ProductName`, `CompanyName` ...
7. **حفظ باسم** → اختر `MyApp_modified.exe` → حفظ

سيُنشئ:
- `MyApp_modified.exe` (الجديد)
- `MyApp.exe.bak` (نسخة أصلية)
- `MyApp_modified.patch_report.json` (تقرير التعديلات)

### نصائح للواجهة
- النصوص في الأزرار والقوائم تظهر في الجدول — غيّرها لتغيّر الواجهة
- فلتر بـ `ascii` لرؤية نصوص إنجليزية، `utf16le` لنصوص Windows
- انسخ الـ Offset بالكليك اليمين للتوثيق

---

## الطريقة 2: سطر الأوامر

```bash
# غيّر كل MyApp إلى NewApp
revspec patch program.exe --replace MyApp:NewApp -o program_new.exe

# غيّر نص محدد
revspec patch program.exe --string "Old Text:New Text" -o out.exe

# غيّر VersionInfo (يظهر في خصائص الملف)
revspec patch program.exe --set-version ProductName=MyNewApp --set-version CompanyName=MyCompany -o out.exe

# عدة تعديلات معاً
revspec patch program.exe --replace MyApp:NewApp --set-version FileVersion=2.0.0 -o out.exe --report patch.json

# عرض النصوص أولاً
revspec patch program.exe --list | head -n 50
```

---

## أمثلة

### مثال 1: تغيير اسم برنامجك
```
قديم: DemoApp
جديد: MySuperApp (9 vs 7 ❌ أطول — استخدم MyApp2)
```
في الواجهة: Batch Rename → Old: `DemoApp` New: `MyApp2` → سيغيّر 6-10 ظهور تلقائياً.

### مثال 2: تغيير نص في الواجهة
- ابحث عن `Click here` → دبل كليك → غيّر إلى `اضغط هنا` (لكن انتبه للطول!)
- إذا كان الأصلي 10 حروف، الجديد يجب ≤10

### مثال 3: تغيير حقوق النشر
تبويب PE → `LegalCopyright` → `Copyright MyCompany 2025`

---

## اختبار على العينة

```bash
# العينة Python (تعمل بدون .exe)
revspec patch samples/demo_app_win/demo_win.py --replace demo_win:my_app__ -o /tmp/test.exe

# أو عبر الواجهة حمّل samples/demo_app_win/demo_win.py وغيّر demo_win
```

---

## الأسئلة

**هل يغيّر الأيقونة؟** حالياً لا، استخدم https://www.angusj.com/resourcehacker/ لاستبدال Icon.

**هل يغيّر لون/حجم النافذة؟** النصوص فقط. التخطيط يحتاج محرر موارد.

**هل يعمل على .exe كبيرة؟** نعم، حتى 500MB، لكن الجدول يعرض أول 3000 نص للسرعة — استخدم البحث.

**هل يحافظ على التوقيع؟** التعديل يُبطل التوقيع الرقمي — طبيعي.

---

*للبرامج التي تملكها فقط.*
