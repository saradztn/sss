# RevSpec — منصة هندسة عكسية معيارية

> **للاستخدام فقط على البرامج التي تملكها أو لديك تصريح كتابي بتحليلها.**  
> الهدف: تحليل برنامج بشكل منهجي وإنتاج تقرير **قابل لإعادة التنفيذ** بواسطة AI آخر.

![RevSpec](https://img.shields.io/badge/RevSpec-v1.0.0-blue) ![Python](https://img.shields.io/badge/python-3.9%2B-green) ![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## ✨ ما الذي يفعله؟

1. يحلل ملف تنفيذي (ELF/PE/Mach-O/script/ZIP) عبر **11 محللًا معياريًا**.
2. يستخرج **metadata, platform, structure, strings, imports, resources, crypto, disassembly, behavior**.
3. يشغل العينة في بيئة **معزولة** (bwrap/firejail/rlimit + strace) إذا فعّلت `--enable-dynamic`.
4. يقارن الثابت بالديناميكي ويحسب **درجة ثقة** لكل استنتاج.
5. ينتج **تقريرًا بشريًا (Markdown)** + **JSON/YAML machine-readable** + **أدلة خام قابلة لإعادة الإنتاج**.

التقرير يحتوي 18 قسمًا مطلوبًا: معلومات العينة، البنية، الواجهات، الاعتمادات، التدفقات، الثقة، المثبت vs المستنتج، القيود، و **Specification جاهزة لإعادة التنفيذ**.

---

## 🏗️ المعمارية

انظر [ARCHITECTURE.md](./ARCHITECTURE.md) للتفاصيل. باختصار:

```
CLI → Pipeline → Analyzers (Plugin) → EvidenceStore → Exporters (JSON/YAML/MD)
```

**لماذا Python؟** سرعة التطوير + تكامل مع أدوات النظام (`readelf`, `objdump`, `strings`, `strace`) + نظام plugins بسيط + تسلسل JSON/YAML/Jinja2 ناضج.

---

## 📦 التثبيت

```bash
git clone https://github.com/saradztn/sss
cd sss
pip install -e .
# أو مع محللات native اختيارية:
pip install -e .[native]   # pefile, lief, capstone, pyelftools

# تحقق
revspec --help
revspec list-analyzers
```

**المتطلبات الاختيارية على النظام (تزيد الدقة):**
```bash
sudo apt install binutils file strace bubblewrap firejail unzip
```

بدونها يعمل المشروع لكن بعض المحللات ستكون `skipped`.

---

## 🖥️ واجهة Windows (بدون أوامر)

> **لديك Windows ولا تريد كتابة أوامر؟**

### التحليل:
1. دبل كليك على **`RevSpec_GUI.bat`** → اضغط **🚀 اختر البرنامج وحلّل تلقائياً** → اختر `.exe` الخاص بك → **📄 فتح التقرير**
   - أو `python gui/revspec_gui.py`

### التعديل مثل Ghidra (جديد):
1. دبل كليك على **`Patcher_GUI.bat`** → **📁 استعراض** → حمّل `program.exe`
2. **دبل كليك على أي نص** لتغييره (مثل اسم البرنامج، رسائل الواجهة)
3. أو استخدم **Batch Rename** لتغيير الاسم في كل مكان
4. تبويب **VersionInfo** لتغيير اسم الشركة/المنتج/الإصدار (يظهر في خصائص الملف)
5. **💾 حفظ البرنامج الجديد** → ينشئ `_modified.exe` + `.bak` + تقرير

راجع `docs/WINDOWS.md`, `docs/PATCHER.md`, `gui/README.md`.

CLI أيضاً:
```powershell
revspec patch program.exe --replace OldName:NewName -o new.exe
revspec patch program.exe --set-version ProductName=MyApp -o new.exe
```

---

## 🚀 الاستخدام السريع (CLI)

### 1) بناء العينة التجريبية

```bash
cd samples/demo_app
make
ls -lh demo_app
```

### 2) تحليل ثابت فقط (آمن)

```bash
revspec analyze samples/demo_app/demo_app --output ./runs
# النتيجة في ./runs/<timestamp>_<hash>/
cat ./runs/*/report.md | head -n 100
```

### 3) تحليل شامل مع ديناميكي معزول

```bash
revspec analyze samples/demo_app/demo_app --output ./runs --enable-dynamic
# مع وسائط للعينة:
revspec analyze samples/demo_app/demo_app --output ./runs --enable-dynamic --dynamic-args "--debug"
```

### 4) استخدام مخصص

```python
from pathlib import Path
from revspec.core.pipeline import Pipeline

pipeline = Pipeline()
result = pipeline.run(Path("samples/demo_app/demo_app"), Path("./runs"), {
    "enable_dynamic": True,
    "dynamic_timeout": 5,
})
print(result.summary)
# التقرير في runs/<ts>_<hash>/report.json
```

---

## 📂 هيكل الملفات

```
.
├── revspec/
│   ├── core/           # Pipeline, EvidenceStore, types, confidence
│   ├── analyzers/      # 8 محللات ثابتة
│   ├── dynamic/        # IsolatedRunner + tracer
│   ├── compare/        # مقارنة ثابت/ديناميكي
│   └── export/         # JSON/YAML/MD
├── templates/
│   └── report.md.j2    # قالب التقرير البشري (18 قسم)
├── schemas/
│   └── report.schema.json
├── prompts/
│   └── reimplementation_prompt.md  # Prompt ثانٍ لإعادة التنفيذ
├── samples/demo_app/   # عينة C تجريبية
├── tests/              # اختبارات وحدة وتكامل
├── runs/               # نتائج التحليل (generated)
└── ARCHITECTURE.md
```

---

## 🧩 إضافة محلل جديد

```python
# revspec/analyzers/my_analyzer.py
from .base import BaseAnalyzer
from ..core.types import AnalyzerResult, Finding
from ..core.confidence import Confidence, Provenance

class MyAnalyzer(BaseAnalyzer):
    name = "my_analyzer"
    description = "وصفي"
    version = "1.0.0"
    requires_tools = []  # أو ["mytool"]

    def analyze(self, ctx):
        res = self._result_shell()
        # ... اكتشف شيئًا ...
        res.findings.append(Finding(
            id="my.finding",
            category="behavior",
            title="...",
            description="...",
            confidence=Confidence.HIGH,
            provenance=Provenance.OBSERVED,
            source="my_analyzer:tool",
            method="كيف",
            data={}
        ))
        return res
```

ثم سجّله في `revspec/core/pipeline.py` في `default_analyzers()`.

---

## 📄 التقرير

### الإنسان: `report.md`

يحتوي 18 قسمًا:

1. معلومات البرنامج والعينة
2. البيئة والمنصة
3. بنية البرنامج
4. المكونات والوحدات
5. الوظائف والسلوكيات
6. الواجهات والمدخلات/المخرجات
7. الاعتمادات
8. تدفقات البيانات والأحداث
9. الحالات والانتقالات
10. الموارد والملفات والإعدادات
11. نتائج التحليل الثابت
12. نتائج التحليل الديناميكي
13. درجة الثقة
14. المثبت vs المستنتج
15. تعذر تحديده
16. القيود
17. Specification لإعادة التنفيذ

### الآلة: `report.json` / `report.yaml`

يطابق `schemas/report.schema.json`. كل `finding` يحمل:

```json
{
  "id": "platform.format",
  "confidence": "proven",
  "provenance": "observed",
  "source": "platform:elf_magic",
  "method": "read ELF header",
  "data": {...}
}
```

**التحقق:**

```bash
python -m jsonschema -i runs/<run>/report.json schemas/report.schema.json
```

---

## 🤖 Prompt إعادة التنفيذ

بعد إنتاج `report.json`، استخدم [prompts/reimplementation_prompt.md](./prompts/reimplementation_prompt.md) مع نموذج AI آخر:

```
انسخ الـPrompt + ألصق report.json
→ يخرج Specification بثمانية أقسام + خطة تنفيذ
```

الـPrompt يفرض:
- التمييز بين `proven` و `inferred` و `unknown`
- عدم اختلاق كود غير مؤكد
- ذكر المصدر لكل قرار

---

## 🧪 الاختبارات

```bash
pip install -e .[dev]
pytest -q
pytest --cov=revspec --cov-report=term-missing
```

الاختبارات تغطي:
- `test_metadata.py` — hashes, file magic
- `test_platform.py` — ELF detection
- `test_pipeline_integration.py` — تشغيل كامل على `demo_app`
- `test_schema.py` — تحقق من المخطط

---

## 🔒 الأمان والأخلاق

- هذا المشروع **لا** يشجع على تحليل برامج لا تملكها.
- التحليل الديناميكي **معطل افتراضياً** ويتطلب `--enable-dynamic`.
- العزل عبر `bwrap`/`firejail`/`rlimit` يقلل الخطر لكنه ليس صندوق رمل كامل — راجع كود `IsolatedRunner`.
- لا يتم إرسال العينات خارج جهازك.

---

## 🛣️ خارطة الطريق

- [ ] محلل Ghidra headless (decompilation حقيقي)
- [ ] محلل شبكة مع `tcpdump` 
- [ ] واجهة ويب لاستعراض التقارير
- [ ] دعم entry_points للـplugins الخارجية
- [ ] محلل سيناريوهات (تشغيل بمدخلات متعددة)

---

## 📜 الترخيص

MIT — انظر `LICENSE` (إن وجد).

---

## 🤝 المساهمة

مرحب بالـPRs لإضافة محللات جديدة. تأكد من:
- كل finding يحمل `confidence` و `provenance` و `method`
- حفظ الأدلة الخام في `evidence/<analyzer>/`
- إضافة اختبار في `tests/`

---

*بُني بواسطة RevSpec Team — للبرامج المملوكة فقط.*
