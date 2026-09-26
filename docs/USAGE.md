# دليل الاستخدام — RevSpec

## التشغيل السريع

```bash
revspec analyze /path/to/binary --output ./runs
```

## الخيارات

| الخيار | الوصف |
|--------|-------|
| `sample` | مسار العينة (مطلوب) |
| `-o, --output` | مجلد الإخراج (افتراضي ./runs) |
| `--enable-dynamic` | تفعيل التحليل الديناميكي (معزول) |
| `--dynamic-timeout` | مهلة الثواني للتشغيل الديناميكي (افتراضي 8) |
| `--dynamic-args` | وسائط إضافية تمرر للعينة عند التشغيل |
| `--analyzers` | قائمة محللات مفصولة بفواصل (افتراضي الكل) |

## أمثلة

```bash
# ثابت فقط
revspec analyze samples/demo_app/demo_app --output ./runs

# ديناميكي مع وسائط
revspec analyze samples/demo_app/demo_app --output ./runs --enable-dynamic --dynamic-args "--debug"

# تشغيل محللات محددة فقط
revspec analyze samples/demo_app/demo_app --output ./runs --analyzers metadata,platform,strings
```

## ماذا يحدث؟

1. يحسب `sha256, sha1, md5` ويتحقق من نوع الملف.
2. ينشئ `runs/<timestamp>_<hash>/` ويحفظ نسخة من العينة.
3. يشغل كل محلل بالترتيب، يحفظ `evidence/<analyzer>/`.
4. ينتج `report.json`, `report.yaml`, `report.md`.

## قراءة التقرير

### البشري
```bash
less runs/*/report.md
```

### الآلي
```bash
cat runs/*/report.json | jq '.findings[] | {id, confidence, provenance}'
python -m jsonschema -i runs/*/report.json schemas/report.schema.json
```

## إضافة محلل

انظر `ARCHITECTURE.md` قسم "Plugin".

## العزل الديناميكي

- يحاول `bwrap` ثم `firejail` ثم `rlimit`.
- يحدّ CPU/MEM/FS ويعزل الشبكة إن أمكن.
- يستخدم `strace` إذا توفر.

> **تحذير:** لا تشغل عينات غير موثوقة خارج بيئة اختبار معزولة.

## إعادة الإنتاج

```bash
# تحقق من hash
sha256sum runs/<run>/raw/demo_app
# يجب أن يطابق report.json:sample.sha256

# أعد التشغيل بنفس الأدوات
revspec analyze runs/<run>/raw/demo_app --output ./runs --enable-dynamic
```
