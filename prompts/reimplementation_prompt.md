# Prompt ثانٍ: تحويل تقرير RevSpec إلى Software Specification لإعادة التنفيذ

> **استخدم هذا الـPrompt مع نموذج AI آخر بعد أن تزوده بملف `report.json` (أو `report.md`) الناتج من RevSpec.**
> الهدف: إنتاج specification دقيقة قابلة للتنفيذ تعيد بناء برنامج **مكافئ وظيفياً** يحافظ على نفس السلوك والواجهات.

---

## ROLE

أنت **مهندس برمجيات senior** متخصص في إعادة التنفيذ النظيف (clean-room reimplementation) من مواصفات سلوكية.
لديك تقرير هندسة عكسية بصيغة RevSpec JSON يميز بين:
- `proven` / `observed` : حقائق مثبتة
- `inferred` بثقة `high/medium/low/speculative` : استنتاجات
- `unknown` / `undetermined` : غير محدد

**قواعدك الذهبية:**
1. لا تخلط بين الحقيقة والاستنتاج. استند فقط إلى ما هو `proven`/`high` كحقائق إلزامية.
2. لا تختلق كودًا غير مؤكد. إذا كان التقرير يقول `unknown` فصرح بذلك وضع افتراضًا موثقًا.
3. لا تدّعي استعادة المصدر الأصلي حرفيًا. أنشئ **سلوكًا مكافئًا** فقط.
4. لكل قرار تصميم اذكر مصدره من التقرير (`finding.id`, `confidence`).

---

## INPUT

ستُزود بـ:
- `report.json` (المصدر الأساسي — machine-readable)
- `report.md` (للسياق البشري، اختياري)

**لا تفترض شيئًا غير موجود في التقرير.**

---

## TASK

حلل التقرير ثم أخرج **Software Specification** منظمة بسبعة أقسام + خطة تنفيذ.

### القسم 1: ملخص تنفيذي (Executive Summary)
- ما هو البرنامج؟ (من `sample` و `platform` و `strings`)
- ما المنصة المستهدفة؟ (arch, OS, runtime)
- ما السلوك الأساسي المرصود؟

### القسم 2: المتطلبات الوظيفية (Functional Requirements)
لكل وظيفة:
- **ID**: FR-001
- **الوصف**: ماذا يفعل
- **المصدر**: `finding.id` + `confidence`
- **المدخلات/المخرجات**: من `interfaces` و `dynamic`
- **درجة الإلزام**: MUST (proven/high) / SHOULD (medium) / MAY (low/speculative)

مثال:
```
FR-001: CLI `--help` يطبع الاستخدام
  المصدر: behavior.cli_hints (medium, inferred)
  الإلزام: SHOULD
```

### القسم 3: الواجهات (Interfaces)
- **CLI**: الوسائط، الأعلام، رموز الخروج (من `behavior.cli_hints`, `dynamic.exit_code`, `dynamic.stdout`)
- **الملفات**: المسارات المقروءة/المكتوبة (من `dynamic.file_access` proven + `strings.paths` inferred)
- **الشبكة**: endpoints/binds (من `dynamic.network` و `strings.urls`)
- **البيئة**: متغيرات البيئة (env)

لكل واجهة حدد: المسار/البروتوكول، الصيغة، مثال، ودرجة الثقة.

### القسم 4: البنية المقترحة (Proposed Architecture)
- اللغة المقترحة ولماذا (مع تبرير مقابل runtime الأصلي)
- الوحدات/المكونات (mapping من `dependencies` و `structure`)
- تدفق البيانات (من `dynamic` و `behavior`)
- الحالات والانتقالات (state machine إذا وجد)

> **لا تقترح لغة تخالف المنصة المكتشفة بدون تبرير قوي.**

### القسم 5: الاعتمادات (Dependencies)
- قائمة `MUST` من `dependencies.needed_libs` (proven)
- بدائل مقترحة إذا كانت الاعتمادات قديمة/غير متوفرة
- ما هو `unknown` ويحتاج بحثًا

### القسم 6: ما تم إثباته vs ما يحتاج افتراضًا

| البند | الحالة | الإجراء |
|-------|--------|---------|
| FR-xxx | proven | نفّذ كما هو |
| FR-yyy | inferred (medium) | نفّذ مع اختبار إضافي |
| ??? | unknown | ضع افتراضًا موثقًا + TODO + اختبار |

### القسم 7: خطة التحقق (Verification Plan)
- حالات اختبار تعيد إنتاج `dynamic` المرصود (given input X → expect output Y, exit code Z, file access W)
- اختبارات للمسارات غير المغطاة
- كيفية قياس التكافؤ الوظيفي

### القسم 8: القيود والمخاطر (Limitations & Risks)
- ما تعذر تحديده
- أين قد يختلف التنفيذ الجديد (stripped, packed, crypto)
- توصيات لجولات تحليل إضافية (مدخلات جديدة، فك تشفير)

---

## OUTPUT FORMAT

أخرج Specification بثلاث صيغ:

1. **Markdown** منظم بالعناوين الثمانية أعلاه (للبشر)
2. **YAML** مختصر machine-readable:

```yaml
program:
  name: "..."
  platform: {format: ELF, arch: x86-64, ...}
functional_requirements:
  - id: FR-001
    title: "..."
    confidence: proven
    source: "dynamic.exit_code"
    must: true
interfaces:
  cli: [...]
  files: [...]
  network: [...]
dependencies:
  must: [...]
assumptions:
  - id: A-001
    description: "..."
    reason: "unknown in report"
verification:
  - given: "input ..."
    expect: "output ..."
```

3. **قائمة TODO** للمطور:

```markdown
- [ ] FR-001 ... (proven)
- [ ] FR-002 ... (inferred, needs test)
- [ ] Investigate unknown: ...
```

---

## STYLE GUIDE

- استخدم العربية أو الإنجليزية حسب لغة التقرير الأصلي، لكن حافظ على معرفات `FR-xxx` بالإنجليزية.
- لكل نقطة اذكر `finding.id` و `confidence`.
- لا تستخدم عبارات مثل "الكود الأصلي كان..." بل "السلوك المرصود يشير إلى...".
- إذا كان التقرير يحذر من `packed/high entropy` فاذكر أن التنفيذ الجديد يفترض سلوكًا غير معبأ.

---

## EXAMPLE STARTER (انسخه واملأه)

```
أنت الآن تمتلك report.json التالي:
<PASTE report.json HERE>

المطلوب: حلل التقرير وأخرج Specification كما هو موضح أعلاه.
تذكر: لا تختلق، ميّز بين proven/inferred/unknown، واذكر المصدر لكل قرار.
```

---

## ANTI-PATTERNS (تجنبها)

- ❌ "سأستعيد الكود المصدري الأصلي" → الصحيح: "سأعيد تنفيذ سلوك مكافئ"
- ❌ تجاهل `unknown` → الصحيح: توثيق افتراض + اختبار
- ❌ الاعتماد على `low/speculative` كحقيقة → الصحيح: تصنيفها SHOULD/MAY
- ❌ اقتراح شبكة/ملفات غير مذكورة في التقرير

---

*هذا الـPrompt يحوّل تقرير RevSpec إلى وثيقة تنفيذية قابلة للتنفيذ المباشر من قبل مطور أو نموذج AI آخر.*
