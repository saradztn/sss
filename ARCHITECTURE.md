# معمارية RevSpec

> **المبدأ:** كل معلومة تحمل `confidence` و `provenance` و `method`. لا تخلط بين الحقيقة والاستنتاج.

## 1) نظرة عامة

```
┌─────────────────────────────────────────┐
│  CLI (revspec analyze)                  │
└──────────────┬──────────────────────────┘
               │ sample path + options
               ▼
┌─────────────────────────────────────────┐
│  Pipeline                               │
│  - يحسب hashes + HostInfo               │
│  - ينشئ EvidenceStore (runs/<ts>_<hash>)│
│  - يمرر AnalysisContext لكل محلل        │
└──────────────┬──────────────────────────┘
               │ sequential
               ▼
┌─────────────────────────────────────────┐
│  Analyzers (Plugin System)              │
│  metadata → platform → structure →      │
│  strings → imports → resources →        │
│  crypto → disasm → behavior →           │
│  dynamic (opt-in, isolated) →           │
│  compare                                │
│  كل محلل يقرأ/يكتب ctx.shared           │
└──────────────┬──────────────────────────┘
               │ AnalyzerResult + Findings
               ▼
┌─────────────────────────────────────────┐
│  EvidenceStore                          │
│  runs/<ts>_<hash>/                      │
│   ├── raw/sample.bin                    │
│   ├── evidence/<analyzer>/raw.json      │
│   ├── evidence/<analyzer>/artifacts/    │
│   ├── findings.json                     │
│   └── pipeline_result.json              │
└──────────────┬──────────────────────────┘
               │ result.to_dict()
               ▼
┌─────────────────────────────────────────┐
│  Exporters                              │
│  - JSON (schema validated)              │
│  - YAML                                 │
│  - Markdown (Jinja2)                    │
│  - HTML (اختياري)                       │
└─────────────────────────────────────────┘
```

## 2) لماذا Python؟

| السبب | التبرير |
|-------|---------|
| **سرعة النمذجة** | Python يسمح ببناء pipeline معياري بسرعة دون تعقيد بناء أدوات native |
| **النظام البيئي** | `pefile`, `lief`, `capstone`, `pyelftools` كلها بايثونية |
| **التعامل مع الأدوات الخارجية** | سهل عبر `subprocess` لـ `readelf/objdump/strings/strace` — لا نعيد اختراع العجلة |
| **Modularity** | نظام Plugin بسيط عبر `BaseAnalyzer` + `import` ديناميكي |
| **التسلسل** | `json`/`yaml`/`jinja2` ناضجة |
| **العزل** | يمكن تشغيل Python داخل `bwrap`/`firejail` بسهولة |

> **بدائل تم رفضها:**  
> - Go/Rust: أداء أعلى لكن تطوير أبطأ وتعقيد في التعامل مع أدوات التحليل النصية.  
> - Node.js: غير مناسب لتحليل binary.  
> - C/C++: مبالغ فيه لمنصة تنسيق.

## 3) تصميم Plugin

```python
class BaseAnalyzer(ABC):
    name: str          # unique id
    description: str
    version: str
    requires_tools: List[str]  # مثلاً ["readelf"]

    def analyze(self, ctx: AnalysisContext) -> AnalyzerResult: ...
```

- كل محلل **مستقل** لكنه يشارك `ctx.shared` (dict) للتواصل.
- الترتيب مهم: `metadata` و `platform` أولاً لأنهما يحددان نوع الملف.
- إضافة محلل جديد = إنشاء ملف جديد + تسجيله في `default_analyzers()` — لا حاجة لتعديل Pipeline.

**مثال لإضافة محلل:**

```python
# revspec/analyzers/my_new.py
from .base import BaseAnalyzer
class MyNewAnalyzer(BaseAnalyzer):
    name = "my_new"
    def analyze(self, ctx):
        ...
```

ثم في `revspec/core/pipeline.py`:

```python
from ..analyzers.my_new import MyNewAnalyzer
...
return [..., MyNewAnalyzer()]
```

مستقبلاً يمكن دعم **entry_points** لاكتشاف تلقائي.

## 4) نموذج البيانات

### Finding (الوحدة الذرية)

```python
Finding(
  id="platform.format",
  category="platform",
  title="...",
  description="...",
  confidence=Confidence.PROVEN,   # proven/high/medium/low/speculative/unknown
  provenance=Provenance.OBSERVED, # observed/inferred/absent/undetermined
  source="platform:elf_magic",
  method="read ELF header",
  data={...},
  evidence_refs=[...]
)
```

### AnalyzerResult

يحتوي على `findings` + `raw` (خرج الأداة) + `artifacts` + `errors`.

### PipelineResult

يجمع كل `AnalyzerResult` ويبني `summary` و `comparison`.

## 5) EvidenceStore وقابلية إعادة الإنتاج

```
runs/20250101T120000Z_a1b2c3d4/
├── meta.json
├── raw/demo_app
├── evidence/
│   ├── metadata/raw.json
│   ├── platform/readelf_h.txt
│   ├── strings/strings_ascii.txt
│   ├── dynamic/strace.log
│   └── ...
├── findings.json
├── pipeline_result.json
├── report.json
├── report.yaml
└── report.md
```

- كل تشغيل **معزول** ب timestamp + hash.
- `meta.json` يحفظ `host.tool_versions` + `options` لإعادة الإنتاج.
- الأدلة الخام محفوظة دائماً، حتى لو فشل المحلل.

## 6) التحليل الديناميكي المعزول

```
IsolatedRunner:
  1. يحاول bwrap --ro-bind / / --unshare-pid --unshare-net
  2. وإلا firejail --net=none
  3. وإلا subprocess مع rlimit (CPU 5s, MEM 256M)
  + strace -f -tt -T -s 256 إذا توفر
  + timeout 8s
```

- **Opt-in**: معطل افتراضياً، يفعّل بـ `--enable-dynamic`.
- يقيس `exit_code`, `stdout`, `stderr`, `syscalls`, `file_access`, `network`.
- النتائج تُحفظ كـ `Finding` بثقة `proven`.

## 7) المقارنة (Static vs Dynamic)

محلل `compare` يقارن:
- هل الثابت أشار لشبكة والديناميكي لم يرصدها؟ → تعارض
- هل المسارات في strings تطابق الملفات المرصودة ديناميكياً؟ → تداخل

## 8) التصدير

- **JSON**: يطابق `schemas/report.schema.json` — يُتحقق عبر `jsonschema`.
- **YAML**: نفس البنية.
- **Markdown**: عبر `Jinja2` + `templates/report.md.j2` — يحتوي 18 قسمًا مطلوبًا.

## 9) الأمان والأخلاق

- تحذير في CLI و README.
- الديناميكي معطل افتراضياً.
- `IsolatedRunner` يحد الموارد ويعزل الشبكة إن أمكن.
- لا يتم رفع العينات خارج الجهاز.

## 10) الاختبارات

```
tests/
├── test_metadata.py      # وحدة: hash, file
├── test_platform.py      # وحدة: ELF detection
├── test_pipeline_integration.py  # تكامل: demo_app
└── test_schema.py        # تحقق من JSON schema
```

## 11) القرارات التي تم تجنبها

- لا ندّعي استعادة مصدر حرفي.
- لا نستخدم تخمين لغوي لتوليد كود.
- لا نعتمد على أدوات ثقيلة (Ghidra) في core — لكن يمكن إضافتها كمحلل لاحقاً.
