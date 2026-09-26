# Demo App — عينة اختبارية لـ RevSpec

هذه عينة **تملكها أنت** لاختبار منصة RevSpec. لا تستخدمها على برامج لا تملكها.

## البناء

```bash
cd samples/demo_app
make
```

## التشغيل

```bash
./demo_app --help
./demo_app --version
./demo_app --debug
./demo_app -c ./config.ini -o /tmp/demo_output.txt
./demo_app --connect   # يحاول اتصال 127.0.0.1:9999
```

## ما يفعله

- يقرأ `config.ini` (إن وجد)
- يكتب `/tmp/demo_output.txt`
- يطبع `https://example.com/api/v1/status` في الملف والسلاسل
- يدعم `--debug` مع token وهمي
- يحاول اتصال شبكة اختياري

## للتحليل

```bash
# من جذر المشروع
revspec analyze samples/demo_app/demo_app --output ./runs --enable-dynamic
# أو بدون ديناميكي
revspec analyze samples/demo_app/demo_app --output ./runs
```
