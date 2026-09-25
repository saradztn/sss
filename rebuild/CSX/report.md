# تقرير الهندسة العكسية — RevSpec
> **للاستخدام فقط على البرامج التي تملكها أو لديك تصريح بتحليلها**
> هذا التقرير يميّز بوضوح بين **الحقيقة المرصودة** و**الاستنتاج**، ويذكر مصدر كل معلومة ودرجة الثقة.

---

## 1) معلومات البرنامج والعينة

| البند | القيمة |
|-------|--------|
| **اسم الملف** | `CSX.exe` |
| **المسار الأصلي** | `/tmp/CSX.exe` |
| **الحجم** | 6175744 بايت (6031.00 KB) |
| **SHA256** | `683520631b81a7283e9d7c0870115867ed29630a782348119308d22eae1b6f31` |
| **SHA1** | `2d0de7e0919b2f2f72dd9388d7c6510513acd132` |
| **MD5** | `d1e7416fa2ef5031f963cb0585a97629` |
| **تاريخ الجمع** | 2026-09-25T17:18:52.986118Z |

### البيئة والمنصة (Host)

| البند | القيمة |
|-------|--------|
| نظام التشغيل | Linux-6.1.158+-x86_64-with-glibc2.36 |
| المعمارية | x86_64 |
| Python | 3.11.2 |
| Hostname | e2b.local |
| وقت التحليل | 2026-09-25T17:18:53.016328Z → 2026-09-25T17:18:56.529213Z |

**إصدارات الأدوات:**

- `readelf`: GNU readelf (GNU Binutils for Debian) 2.40
- `objdump`: GNU objdump (GNU Binutils for Debian) 2.40
- `nm`: GNU nm (GNU Binutils for Debian) 2.40
- `strings`: GNU strings (GNU Binutils for Debian) 2.40
- `ldd`: ldd (Debian GLIBC 2.36-9+deb12u14) 2.36
- `unzip`: caution:  both -n and -o specified; ignoring -o
- `jinja2`: 3.1.6
- `jsonschema`: 4.26.0
- `pefile`: 2024.8.26
- `capstone`: 5.0.9

---

## 2) ملخص تنفيذي

- إجمالي الاستنتاجات: **36**
- موزعة حسب الفئة:
  - metadata: 4
  - platform: 2
  - structure: 2
  - strings: 6
  - dependencies: 2
  - behavior: 8
  - resources: 1
  - crypto: 3
  - disasm: 5
  - interfaces: 1
  - dynamic: 1
  - comparison: 1
- توزيع الثقة:
  - proven: 17
  - low: 2
  - high: 2
  - medium: 14
  - unknown: 1
- توزيع المصدر:
  - observed: 21
  - inferred: 14
  - undetermined: 1

**حالة المحللات:**
- `metadata`: ok (24ms) - `platform`: ok (72ms) - `structure`: ok (208ms) - `strings`: ok (236ms) - `imports_exports`: ok (287ms) - `resources`: ok (92ms) - `crypto`: ok (547ms) - `disasm`: ok (174ms) - `behavior`: ok (54ms) - `dynamic`: skipped (0ms) ⚠️ Dynamic analysis disabled (enable with --enable-dynamic).- `compare`: ok (0ms) - `deep_opcode`: ok (1807ms) 
---

## 3) بنية البرنامج

### PE Sections — ✅ مُثبت (observed)
- **المصدر:** `structure:pefile` — `pefile.PE`
- **الوصف:** PE entry 0x22052 base 0x400000 sections=7
```json
{
  "pe_entry": "0x22052",
  "pe_image_base": "0x400000",
  "pe_sections": [
    {
      "Misc_VirtualSize": 227065,
      "Name": ".text",
      "SizeOfRawData": 227328,
      "VirtualAddress": "0x1000"
    },
    {
      "Misc_VirtualSize": 581,
      "Name": ".mmap",
      "SizeOfRawData": 1024,
      "VirtualAddress": "0x39000"
    },
    {
      "Misc_VirtualSize": 68000,
      "Name": ".rdata",
      "SizeOfRawData": 68096,
      "VirtualAddress": "0x3a000"
    },
    {
      "Misc_VirtualSize": 7944,
      "Name": ".data",
      "SizeOfRawData": 3584,
      "VirtualAddress": "0x4b000"
    },
    {
      "Misc_VirtualSize": 128,
      "Name": ".fptable",
      "SizeOfRawData": 512,
      "VirtualAddress": "0x4d000"
    },
    {
      "Misc_VirtualSize": 5862968,
      "Name": ".rsrc",
      "SizeOfRawData": 5863424,
      "VirtualAddress": "0x4e000"
    },
    {
      "Misc_VirtualSize": 10452,
      "Name": ".reloc",
      "SizeOfRawData": 10752,
      "VirtualAddress": "0x5e6000"
    }
  ]
}
```### Functions مكتشفة: 300 — 🟡 متوسط (observed)
- **المصدر:** `deep:nm+heuristic` — `nm -S + prologue pattern`
- **الوصف:** دوال عبر symbols أو prologue heuristics (push rbp; mov rbp,rsp)
```json
{
  "functions": [
    {
      "address": "0x401060",
      "name": "sub_0x401060",
      "source": "heuristic"
    },
    {
      "address": "0x4010a0",
      "name": "sub_0x4010a0",
      "source": "heuristic"
    },
    {
      "address": "0x401120",
      "name": "sub_0x401120",
      "source": "heuristic"
    },
    {
      "address": "0x401150",
      "name": "sub_0x401150",
      "source": "heuristic"
    },
    {
      "address": "0x401190",
      "name": "sub_0x401190",
      "source": "heuristic"
    },
    {
      "address": "0x4011b0",
      "name": "sub_0x4011b0",
      "source": "heuristic"
    },
    {
      "address": "0x4012ec",
      "name": "sub_0x4012ec",
      "source": "heuristic32"
    },
    {
      "address": "0x401470",
      "name": "sub_0x401470",
      "source": "heuristic"
    },
    {
      "address": "0x401490",
      "name": "sub_0x401490",
      "source": "heuristic"
    },
    {
      "address": "0x4014d0",
      "name": "sub_0x4014d0",
      "source": "heuristic"
    },
    {
      "address": "0x401520",
      "name": "sub_0x401520",
      "source": "heuristic"
    },
    {
      "address": "0x40169c",
      "name": "sub_0x40169c",
      "source": "heuristic32"
    },
    {
      "address": "0x401a6c",
      "name": "sub_0x401a6c",
      "source": "heuristic32"
    },
    {
      "address": "0x401ed0",
      "name": "sub_0x401ed0",
      "source": "heuristic"
    },
    {
      "address": "0x402020",
      "name": "sub_0x402020",
      "source": "heuristic"
    },
    {
      "address": "0x402560",
      "name": "sub_0x402560",
      "source": "heuristic"
    },
    {
      "address": "0x4025a0",
      "name": "sub_0x4025a0",
      "source": "heuristic"
    },
    {
      "address": "0x402600",
      "name": "sub_0x402600",
      "source": "heuristic"
    },
    {
      "address": "0x402680",
      "name": "sub_0x402680",
      "source": "heuristic"
    },
    {
      "address": "0x402790",
      "name": "sub_0x402790",
      "source": "heuristic"
    }
  ],
  "total": 300
}
```
---

## 4) المنصة والمعمارية والـRuntime

### صيغة الملف / المنصة — ✅ مُثبت
- **المنهج:** pe_magic
- **الوصف:** الصيغة المكتشفة: PE | المعمارية: x86 | البت: unknown
```json
{
  "arch": "x86",
  "format": "PE",
  "machine": 332
}
```### تلميحات Runtime / اللغة — 🟠 منخفض
- **المنهج:** keyword search in strings
- **الوصف:** تلميحات لغوية/تقنية مستنتجة من strings و readelf
```json
{
  "hints": [
    "JVM",
    "Rust",
    "Node.js",
    "Python"
  ]
}
```
---

## 5) المكونات والوحدات المكتشفة

- **المكتبات المطلوبة (NEEDED / DLL)** — ✅ مُثبت — عدد 10 مكتبة معتمدة
  - مصدر: `imports_exports:readelf/pefile`
  - libs: `ADVAPI32.dll, GDI32.dll, USER32.dll, WINHTTP.dll, ole32.dll, OLEAUT32.dll, KERNEL32.dll, SHELL32.dll, gdiplus.dll, NETAPI32.dll`
- **الرموز المستوردة** — ✅ مُثبت — عدد 269 رمز مستورد (عينة 100 أولى محفوظة)
  - مصدر: `imports_exports:nm/objdump/pefile`
  - عينة imports: `ADVAPI32.dll!RegEnumKeyExA, ADVAPI32.dll!RegQueryValueExW, ADVAPI32.dll!CredDeleteW, ADVAPI32.dll!GetUserNameW, ADVAPI32.dll!RegOpenKeyExW, ADVAPI32.dll!RegOpenKeyExA, ADVAPI32.dll!RegSetValueExA, ADVAPI32.dll!GetUserNameA, ADVAPI32.dll!RegDeleteKeyA, ADVAPI32.dll!RegCloseKey` (الإجمالي 269)

### الموارد
- **لا توجد موارد ظاهرة بالطرق المتاحة** — ⚪ غير محدد — لم يتم العثور على موارد مضمنة واضحة؛ قد تكون مضمنة كـ blobs أو مشفرة
```json
{
  "config_hints": [],
  "is_zip": false,
  "version_strings": []
}
```
---

## 6) الوظائف والسلوكيات (Static)

- **استيرادات مثيرة للانتباه** — 🟡 متوسط — tags: heuristic, behavior
  - استيرادات قد تشير لقدرات حساسة (لا تعني خبثًا بحد ذاتها)
  - مصدر: `imports_exports:heuristic` / `keyword match against imports`
```json
{
  "suspicious": [
    "USER32.dll!SystemParametersInfoW",
    "WINHTTP.dll!WinHttpOpenRequest",
    "WINHTTP.dll!WinHttpOpen",
    "WINHTTP.dll!WinHttpConnect",
    "KERNEL32.dll!WriteProcessMemory",
    "KERNEL32.dll!VirtualAllocEx",
    "KERNEL32.dll!CreateRemoteThread",
    "KERNEL32.dll!GetSystemTimeAsFileTime"
  ]
}
```- **سلوك محتمل: عمليات شبكة** — 🟡 متوسط — tags: network, heuristic
  - تم العثور على ['socket', 'send'] مطابقة للنمط \b(socket|connect|bind|listen|accept|send|recv)\b
  - مصدر: `behavior:regex over imports+strings` / `regex \b(socket|connect|bind|listen|accept|send|recv)\b`
```json
{
  "description": "\u0639\u0645\u0644\u064a\u0627\u062a \u0634\u0628\u0643\u0629",
  "hits": [
    "socket",
    "send"
  ],
  "pattern": "\\b(socket|connect|bind|listen|accept|send|recv)\\b",
  "tag": "network"
}
```- **سلوك محتمل: عمليات ملفات** — 🟡 متوسط — tags: file-io, heuristic
  - تم العثور على ['read', 'open'] مطابقة للنمط \b(open|read|write|fopen|fwrite|fread|creat)\b
  - مصدر: `behavior:regex over imports+strings` / `regex \b(open|read|write|fopen|fwrite|fread|creat)\b`
```json
{
  "description": "\u0639\u0645\u0644\u064a\u0627\u062a \u0645\u0644\u0641\u0627\u062a",
  "hits": [
    "read",
    "open"
  ],
  "pattern": "\\b(open|read|write|fopen|fwrite|fread|creat)\\b",
  "tag": "file-io"
}
```- **سلوك محتمل: إنشاء عمليات** — 🟡 متوسط — tags: process, heuristic
  - تم العثور على ['system'] مطابقة للنمط \b(execve|execvp|system|popen|fork|clone)\b
  - مصدر: `behavior:regex over imports+strings` / `regex \b(execve|execvp|system|popen|fork|clone)\b`
```json
{
  "description": "\u0625\u0646\u0634\u0627\u0621 \u0639\u0645\u0644\u064a\u0627\u062a",
  "hits": [
    "system"
  ],
  "pattern": "\\b(execve|execvp|system|popen|fork|clone)\\b",
  "tag": "process"
}
```- **سلوك محتمل: تلاعب بالذاكرة / حقن محتمل** — 🟡 متوسط — tags: memory, heuristic
  - تم العثور على ['mmap', 'VirtualProtect'] مطابقة للنمط \b(mmap|mprotect|VirtualAlloc|VirtualProtect)\b
  - مصدر: `behavior:regex over imports+strings` / `regex \b(mmap|mprotect|VirtualAlloc|VirtualProtect)\b`
```json
{
  "description": "\u062a\u0644\u0627\u0639\u0628 \u0628\u0627\u0644\u0630\u0627\u0643\u0631\u0629 / \u062d\u0642\u0646 \u0645\u062d\u062a\u0645\u0644",
  "hits": [
    "mmap",
    "VirtualProtect"
  ],
  "pattern": "\\b(mmap|mprotect|VirtualAlloc|VirtualProtect)\\b",
  "tag": "memory"
}
```- **سلوك محتمل: حقن/تتبع عمليات** — 🟡 متوسط — tags: injection, heuristic
  - تم العثور على ['CreateRemoteThread', 'WriteProcessMemory'] مطابقة للنمط \b(ptrace|CreateRemoteThread|WriteProcessMemory)\b
  - مصدر: `behavior:regex over imports+strings` / `regex \b(ptrace|CreateRemoteThread|WriteProcessMemory)\b`
```json
{
  "description": "\u062d\u0642\u0646/\u062a\u062a\u0628\u0639 \u0639\u0645\u0644\u064a\u0627\u062a",
  "hits": [
    "CreateRemoteThread",
    "WriteProcessMemory"
  ],
  "pattern": "\\b(ptrace|CreateRemoteThread|WriteProcessMemory)\\b",
  "tag": "injection"
}
```- **سلوك محتمل: عمليات تشفير** — 🟡 متوسط — tags: crypto, heuristic
  - تم العثور على ['RSA', 'AES'] مطابقة للنمط \b(crypt|encrypt|decrypt|AES|RSA|EVP_)\b
  - مصدر: `behavior:regex over imports+strings` / `regex \b(crypt|encrypt|decrypt|AES|RSA|EVP_)\b`
```json
{
  "description": "\u0639\u0645\u0644\u064a\u0627\u062a \u062a\u0634\u0641\u064a\u0631",
  "hits": [
    "RSA",
    "AES"
  ],
  "pattern": "\\b(crypt|encrypt|decrypt|AES|RSA|EVP_)\\b",
  "tag": "crypto"
}
```- **Control Flow — 10626 basic blocks** — ✅ مُثبت — tags: 
  - متوسط 4.71 تعليمة لكل block. Jumps/Calls تحدد التدفق.
  - مصدر: `deep:cfg` / `split on jmp/call/ret`
```json
{
  "avg": 4.71,
  "blocks": 10626
}
```
---

## 7) الواجهات والمدخلات والمخرجات

- **تلميحات واجهة سطر الأوامر** — 🟠 منخفض
  - سلاسل تشبه خيارات CLI
```json
{
  "cli_hints": [
    "-jd_;",
    "-h%D",
    "-t%D",
    "-J0D",
    "-@0D",
    "-^0D",
    "-gqdt",
    "-]q}",
    "-+HC[",
    "-e@f",
    "-[bU\u0027*",
    "-tON",
    "-}\t/",
    "-RHj=",
    "-fa0o",
    "-%k0",
    "-{\u0027wb",
    "R--Plk",
    "-( ,",
    "-bH)",
    "-lh!20",
    "-ph!20",
    "-lth!20",
    "-U026C5x",
    "-lth!20=a",
    "-lth!20T",
    "-\u003c86",
    "-O|{",
    "-uh!",
    "-A~S",
    "-v\u0027}",
    "-Pte",
    "-%th!",
    "-D\u003e\"",
    "-Xh!20",
    "-+lt",
    "-002",
    "-p8p",
    "-!G4",
    "-uh!3",
    "-302",
    "-mth",
    "-Keam",
    "-#!20mh6\u0027",
    "-lth.",
    "-102",
    "-y6C5",
    "-lth",
    "-y024Lb",
    "-lti"
  ]
}
```
> **ملاحظة:** الواجهات الموثقة هنا هي **قابلة للملاحظة** فقط (CLI args, file paths, env vars, network endpoints). لا ندّعي معرفة بروتوكول داخلي غير مرصود.

---

## 8) الاعتمادات

انظر قسم المكونات أعلاه. ملخص `needed` و `imports` يمثل **الاعتمادات المباشرة المرصودة**. الاعتمادات العابرة (transitive) غير مستنتجة إلا إذا ظهرت في `ldd` الديناميكي.

---

## 9) تدفقات البيانات والأحداث

- **تم تخطي التحليل الديناميكي** — ✅ مُثبت (observed)
  - التحليل الديناميكي معطل افتراضياً لتجنب تنفيذ كود غير موثوق. فعّله صراحة مع --enable-dynamic بعد التأكد من العزل.

---

## 10) الحالات والانتقالات المهمة

- يتم اشتقاق الحالات من رموز الخروج و stdout/stderr و syscalls.
- إذا كان التطبيق تفاعليًا، فإن هذا القسم يحتاج تشغيلًا بمُدخلات متنوعة وتسجيل الانتقالات (يُنصح بإضافة محلل scenario).

**مقارنة ثابت/ديناميكي:**
```json
{
  "dynamic_files_sample": [],
  "dynamic_network_observed": false,
  "overlap": [],
  "static_network_hint": true,
  "static_paths_sample": [
    "/1U",
    "/trustInfo",
    "/Gzm",
    "/Pma",
    "/B-",
    "/D_b",
    "/cgHc",
    "/2j2",
    "/api/event",
    "/Av"
  ]
}
```

---

## 11) الموارد والملفات والإعدادات

انظر قسم الموارد. الملفات التي يعتمد عليها البرنامج تُقسم إلى:
- **مرصودة ديناميكياً** (proven): من `strace` — دقيقة.
- **مستنتجة من السلاسل** (medium/low): قد تكون بقايا أو مسارات افتراضية.

---

## 12) نتائج التحليل الثابت

| المحلل | الحالة | النتائج |
| metadata | ok | 4 findings |
| platform | ok | 2 findings |
| structure | ok | 1 findings |
| strings | ok | 6 findings |
| imports_exports | ok | 3 findings |
| resources | ok | 1 findings |
| crypto | ok | 3 findings |
| disasm | ok | 3 findings |
| behavior | ok | 7 findings |
| deep_opcode | ok | 4 findings |

**أبرز الاستنتاجات الثابتة:**

- [✅ مُثبت] **SHA256** — SHA256 للعينة = 683520631b81a7283e9d7c0870115867ed29630a782348119308d22eae1b6f31 — *metadata:hashlib.sha256*
- [✅ مُثبت] **حجم الملف** — حجم الملف 6175744 بايت — *metadata:stat*
- [✅ مُثبت] **طوابع زمنية لنظام الملفات** — mtime/ctime من نظام الملفات (قد لا تعكس وقت البناء) — *metadata:stat*
- [✅ مُثبت] **Magic bytes** — أول 16 بايت hex: 4d5a90000300000004000000ffff0000 — *metadata:read*
- [✅ مُثبت] **صيغة الملف / المنصة** — الصيغة المكتشفة: PE | المعمارية: x86 | البت: unknown — *platform:pe_magic*
- [🟠 منخفض] **تلميحات Runtime / اللغة** — تلميحات لغوية/تقنية مستنتجة من strings و readelf — *platform:strings+readelf*
- [✅ مُثبت] **PE Sections** — PE entry 0x22052 base 0x400000 sections=7 — *structure:pefile*
- [✅ مُثبت] **ملخص السلاسل** — إجمالي 137384 سلسلة ascii (+ 833 utf16) — *strings:strings(1)*
- [🔵 عالي] **URLs مكتشفة** — عناوين URL مستخرجة من السلاسل — *strings:regex*
- [🟡 متوسط] **عناوين IP** — عناوين IP محتملة — *strings:regex*
- [🔵 عالي] **عناوين بريد** — عناوين بريد مستخرجة — *strings:regex*
- [🟡 متوسط] **كلمات مفتاحية مثيرة** — كلمات دلالية قد تشير لوظائف حساسة — *strings:keyword search*
- [🟡 متوسط] **مسارات ملفات** — مسارات ملفات مستخرجة (عينة من 50) — *strings:regex*
- [✅ مُثبت] **المكتبات المطلوبة (NEEDED / DLL)** — عدد 10 مكتبة معتمدة — *imports_exports:readelf/pefile*
- [✅ مُثبت] **الرموز المستوردة** — عدد 269 رمز مستورد (عينة 100 أولى محفوظة) — *imports_exports:nm/objdump/pefile*
- [🟡 متوسط] **استيرادات مثيرة للانتباه** — استيرادات قد تشير لقدرات حساسة (لا تعني خبثًا بحد ذاتها) — *imports_exports:heuristic*
- [🟡 متوسط] **إنتروبي عالي — محتمل تشفير/ضغط/حزم** — إنتروبي كلي 7.95 (>7.2) يشير لاحتمال تشفير أو ضغط أو packer — *crypto:entropy*
- [🟡 متوسط] **نوافذ عالية الإنتروبي كثيرة** — 4276/6031 نوافذ بإنتروبي >7.5 — قد تشير لمقاطع مشفرة/مضغوطة — *crypto:window_entropy*
- [🟡 متوسط] **لا توجد ثوابت تشفير واضحة** — لم يتم العثور على S-box أو PEM markers أو base64 alphabet كامل — *crypto:constant search*
- [✅ مُثبت] **Disassembly عبر objdump** — تم تفكيك 74673 سطر، 2 دالة محتملة — *disasm:objdump -d*
- [✅ مُثبت] **Capstone متاح** — يمكن استخدام capstone للتحليل البرمجي لاحقًا — *disasm:capstone import*
- [✅ مُثبت] **قيود الاستعادة** — لا يمكن استعادة المصدر الأصلي حرفيًا من binary؛ ما نستعيده هو سلوك مكافئ عبر الملاحظة والتفكيك. Decompilation الحقيقي يتطلب Ghidra/IDA غير مضمنة هنا. — *disasm:disclaimer*
- [🟡 متوسط] **سلوك محتمل: عمليات شبكة** — تم العثور على ['socket', 'send'] مطابقة للنمط \b(socket|connect|bind|listen|accept|send|recv)\b — *behavior:regex over imports+strings*
- [🟡 متوسط] **سلوك محتمل: عمليات ملفات** — تم العثور على ['read', 'open'] مطابقة للنمط \b(open|read|write|fopen|fwrite|fread|creat)\b — *behavior:regex over imports+strings*
- [🟡 متوسط] **سلوك محتمل: إنشاء عمليات** — تم العثور على ['system'] مطابقة للنمط \b(execve|execvp|system|popen|fork|clone)\b — *behavior:regex over imports+strings*
- [🟡 متوسط] **سلوك محتمل: تلاعب بالذاكرة / حقن محتمل** — تم العثور على ['mmap', 'VirtualProtect'] مطابقة للنمط \b(mmap|mprotect|VirtualAlloc|VirtualProtect)\b — *behavior:regex over imports+strings*
- [🟡 متوسط] **سلوك محتمل: حقن/تتبع عمليات** — تم العثور على ['CreateRemoteThread', 'WriteProcessMemory'] مطابقة للنمط \b(ptrace|CreateRemoteThread|WriteProcessMemory)\b — *behavior:regex over imports+strings*
- [🟡 متوسط] **سلوك محتمل: عمليات تشفير** — تم العثور على ['RSA', 'AES'] مطابقة للنمط \b(crypt|encrypt|decrypt|AES|RSA|EVP_)\b — *behavior:regex over imports+strings*
- [✅ مُثبت] **Opcodes (capstone) — 50001 تعليمة** — تم تفكيك 50001 تعليمة عبر capstone. أهمها: mov:12739, push:8970, call:3537, cmp:3409, lea:2637 | Blocks: 10626 | Functions: 300 — *deep:capstone*
- [🟡 متوسط] **Functions مكتشفة: 300** — دوال عبر symbols أو prologue heuristics (push rbp; mov rbp,rsp) — *deep:nm+heuristic*
- [✅ مُثبت] **Control Flow — 10626 basic blocks** — متوسط 4.71 تعليمة لكل block. Jumps/Calls تحدد التدفق. — *deep:cfg*
- [✅ مُثبت] **تقرير جاهز لإعادة البناء في C++** — يحتوي opcodes_full.json.gz + skeleton.cpp + ai_report.json — يمكن إرسالها لنموذج AI لبناء C++ مكافئ. — *deep:export*

---

## 13) نتائج التحليل الديناميكي

- [✅ مُثبت] **تم تخطي التحليل الديناميكي** — التحليل الديناميكي معطل افتراضياً لتجنب تنفيذ كود غير موثوق. فعّله صراحة مع --enable-dynamic بعد التأكد من العزل.

---

## 14) درجة الثقة في كل استنتاج

| المستوى | المعنى | متى تُستخدم |
|---------|--------|-------------|
| ✅ **proven** | حقيقة مرصودة مباشرة | hash محسوب، syscall مرصود، header مقروء |
| 🔵 **high** | استنتاج قوي بأدلة متعددة | توافق file+readelf+strings |
| 🟡 **medium** | معقول بدليل واحد | keyword في strings فقط |
| 🟠 **low** | ضعيف | heuristic عام |
| 🔴 **speculative** | تخميني | نمط غير مكتمل |
| ⚪ **unknown** | غير محدد | لا يوجد دليل |

كل finding في الـJSON يحمل `confidence` و `provenance` و `method`.

---

## 15) الأشياء التي تم إثباتها مقابل المستنتجة

### ✅ مثبتة (proven/observed)
- **SHA256** — SHA256 للعينة = 683520631b81a7283e9d7c0870115867ed29630a782348119308d22eae1b6f31 — `metadata:hashlib.sha256` — `hashlib.sha256 over file bytes`
- **حجم الملف** — حجم الملف 6175744 بايت — `metadata:stat` — `stat.st_size`
- **طوابع زمنية لنظام الملفات** — mtime/ctime من نظام الملفات (قد لا تعكس وقت البناء) — `metadata:stat` — `stat.st_mtime/ctime`
- **Magic bytes** — أول 16 بايت hex: 4d5a90000300000004000000ffff0000 — `metadata:read` — `read first 16 bytes`
- **صيغة الملف / المنصة** — الصيغة المكتشفة: PE | المعمارية: x86 | البت: unknown — `platform:pe_magic` — `pe_magic`
- **PE Sections** — PE entry 0x22052 base 0x400000 sections=7 — `structure:pefile` — `pefile.PE`
- **ملخص السلاسل** — إجمالي 137384 سلسلة ascii (+ 833 utf16) — `strings:strings(1)` — `strings -a -n 4`
- **URLs مكتشفة** — عناوين URL مستخرجة من السلاسل — `strings:regex` — `regex https?://`
- **عناوين بريد** — عناوين بريد مستخرجة — `strings:regex` — `email regex`
- **المكتبات المطلوبة (NEEDED / DLL)** — عدد 10 مكتبة معتمدة — `imports_exports:readelf/pefile` — `readelf -d / pefile`
- **الرموز المستوردة** — عدد 269 رمز مستورد (عينة 100 أولى محفوظة) — `imports_exports:nm/objdump/pefile` — `nm -D / objdump`
- **لا توجد ثوابت تشفير واضحة** — لم يتم العثور على S-box أو PEM markers أو base64 alphabet كامل — `crypto:constant search` — `byte pattern search`
- **Disassembly عبر objdump** — تم تفكيك 74673 سطر، 2 دالة محتملة — `disasm:objdump -d` — `objdump -d -M intel`
- **Capstone متاح** — يمكن استخدام capstone للتحليل البرمجي لاحقًا — `disasm:capstone import` — `import capstone`
- **قيود الاستعادة** — لا يمكن استعادة المصدر الأصلي حرفيًا من binary؛ ما نستعيده هو سلوك مكافئ عبر الملاحظة والتفكيك. Decompilation الحقيقي يتطلب Ghidra/IDA غير مضمنة هنا. — `disasm:disclaimer` — `design principle`
- **تم تخطي التحليل الديناميكي** — التحليل الديناميكي معطل افتراضياً لتجنب تنفيذ كود غير موثوق. فعّله صراحة مع --enable-dynamic بعد التأكد من العزل. — `dynamic:opt-in` — `ctx.options.enable_dynamic == False`
- **منهجية المقارنة** — المقارنة تزيد الثقة عند التوافق وتخفضها عند التعارض؛ كل تعارض يجب التحقيق بمدخلات إضافية. — `compare:disclaimer` — `design`
- **Opcodes (capstone) — 50001 تعليمة** — تم تفكيك 50001 تعليمة عبر capstone. أهمها: mov:12739, push:8970, call:3537, cmp:3409, lea:2637 | Blocks: 10626 | Functions: 300 — `deep:capstone` — `capstone disassembly`
- **Functions مكتشفة: 300** — دوال عبر symbols أو prologue heuristics (push rbp; mov rbp,rsp) — `deep:nm+heuristic` — `nm -S + prologue pattern`
- **Control Flow — 10626 basic blocks** — متوسط 4.71 تعليمة لكل block. Jumps/Calls تحدد التدفق. — `deep:cfg` — `split on jmp/call/ret`
- **تقرير جاهز لإعادة البناء في C++** — يحتوي opcodes_full.json.gz + skeleton.cpp + ai_report.json — يمكن إرسالها لنموذج AI لبناء C++ مكافئ. — `deep:export` — `capstone + skeleton gen`

### 🔍 مستنتجة (inferred)
- **تلميحات Runtime / اللغة** — تلميحات لغوية/تقنية مستنتجة من strings و readelf — ثقة: 🟠 منخفض — `keyword search in strings`
- **عناوين IP** — عناوين IP محتملة — ثقة: 🟡 متوسط — `ipv4 regex`
- **كلمات مفتاحية مثيرة** — كلمات دلالية قد تشير لوظائف حساسة — ثقة: 🟡 متوسط — `case-insensitive substring count`
- **مسارات ملفات** — مسارات ملفات مستخرجة (عينة من 50) — ثقة: 🟡 متوسط — `path regex`
- **استيرادات مثيرة للانتباه** — استيرادات قد تشير لقدرات حساسة (لا تعني خبثًا بحد ذاتها) — ثقة: 🟡 متوسط — `keyword match against imports`
- **إنتروبي عالي — محتمل تشفير/ضغط/حزم** — إنتروبي كلي 7.95 (>7.2) يشير لاحتمال تشفير أو ضغط أو packer — ثقة: 🟡 متوسط — `shannon entropy`
- **نوافذ عالية الإنتروبي كثيرة** — 4276/6031 نوافذ بإنتروبي >7.5 — قد تشير لمقاطع مشفرة/مضغوطة — ثقة: 🟡 متوسط — `1KB sliding window`
- **سلوك محتمل: عمليات شبكة** — تم العثور على ['socket', 'send'] مطابقة للنمط \b(socket|connect|bind|listen|accept|send|recv)\b — ثقة: 🟡 متوسط — `regex \b(socket|connect|bind|listen|accept|send|recv)\b`
- **سلوك محتمل: عمليات ملفات** — تم العثور على ['read', 'open'] مطابقة للنمط \b(open|read|write|fopen|fwrite|fread|creat)\b — ثقة: 🟡 متوسط — `regex \b(open|read|write|fopen|fwrite|fread|creat)\b`
- **سلوك محتمل: إنشاء عمليات** — تم العثور على ['system'] مطابقة للنمط \b(execve|execvp|system|popen|fork|clone)\b — ثقة: 🟡 متوسط — `regex \b(execve|execvp|system|popen|fork|clone)\b`
- **سلوك محتمل: تلاعب بالذاكرة / حقن محتمل** — تم العثور على ['mmap', 'VirtualProtect'] مطابقة للنمط \b(mmap|mprotect|VirtualAlloc|VirtualProtect)\b — ثقة: 🟡 متوسط — `regex \b(mmap|mprotect|VirtualAlloc|VirtualProtect)\b`
- **سلوك محتمل: حقن/تتبع عمليات** — تم العثور على ['CreateRemoteThread', 'WriteProcessMemory'] مطابقة للنمط \b(ptrace|CreateRemoteThread|WriteProcessMemory)\b — ثقة: 🟡 متوسط — `regex \b(ptrace|CreateRemoteThread|WriteProcessMemory)\b`
- **سلوك محتمل: عمليات تشفير** — تم العثور على ['RSA', 'AES'] مطابقة للنمط \b(crypt|encrypt|decrypt|AES|RSA|EVP_)\b — ثقة: 🟡 متوسط — `regex \b(crypt|encrypt|decrypt|AES|RSA|EVP_)\b`
- **تلميحات واجهة سطر الأوامر** — سلاسل تشبه خيارات CLI — ثقة: 🟠 منخفض — `lines starting with -`

### ❓ غير محددة / تعذر تحديدها
- **لا توجد موارد ظاهرة بالطرق المتاحة** — لم يتم العثور على موارد مضمنة واضحة؛ قد تكون مضمنة كـ blobs أو مشفرة

---

## 16) الأشياء التي تعذر تحديدها

- المصدر الأصلي الحرفي لا يمكن استعادته من binary بدون معلومات debug/full symbols؛ ما نستعيده هو **سلوك مكافئ**.
- المسارات غير المُنفذة أثناء الديناميكي تظل غير مؤكدة.
- البروتوكولات المشفرة/المضغوطة تحتاج مفاتيح أو عينات إضافية.
- المنطق الداخلي المعقد (خوارزميات مخصصة) يحتاج تحليل يدوي إضافي بـ Ghidra/IDA.

---

## 17) القيود ومواطن عدم اليقين

- **الثابت لا يرى السلوك وقت التشغيل**؛ الديناميكي لا يغطي كل المسارات.
- **Stripped binaries** تخفي الأسماء؛ الثقة تنخفض إلى medium/low.
- **Packers/Crypto**: الإنتروبي العالي قد يعني تشفيرًا لكنه ليس دليلاً قاطعًا.
- **العزل**: يمنع الوصول للشبكة الخارجية؛ قد يُظهر سلوكًا مختلفًا عن البيئة الحقيقية.
- **الأدوات المتوفرة**: إذا غابت `pefile/lief/capstone` تنخفض الدقة لكن التقرير يذكر ذلك.

---

## 18) Specification قابلة للاستخدام لإعادة التنفيذ (AI-Ready)

> **هذه الفقرة هي الخلاصة التنفيذية لنموذج AI آخر.**

**السلوك القابل للملاحظة الذي يجب الحفاظ عليه:**

- SHA256: SHA256 للعينة = 683520631b81a7283e9d7c0870115867ed29630a782348119308d22eae1b6f31
- حجم الملف: حجم الملف 6175744 بايت
- طوابع زمنية لنظام الملفات: mtime/ctime من نظام الملفات (قد لا تعكس وقت البناء)
- Magic bytes: أول 16 بايت hex: 4d5a90000300000004000000ffff0000
- صيغة الملف / المنصة: الصيغة المكتشفة: PE | المعمارية: x86 | البت: unknown
- PE Sections: PE entry 0x22052 base 0x400000 sections=7
- ملخص السلاسل: إجمالي 137384 سلسلة ascii (+ 833 utf16)
- URLs مكتشفة: عناوين URL مستخرجة من السلاسل
- عناوين بريد: عناوين بريد مستخرجة
- المكتبات المطلوبة (NEEDED / DLL): عدد 10 مكتبة معتمدة
- الرموز المستوردة: عدد 269 رمز مستورد (عينة 100 أولى محفوظة)
- Disassembly عبر objdump: تم تفكيك 74673 سطر، 2 دالة محتملة
- Capstone متاح: يمكن استخدام capstone للتحليل البرمجي لاحقًا
- قيود الاستعادة: لا يمكن استعادة المصدر الأصلي حرفيًا من binary؛ ما نستعيده هو سلوك مكافئ عبر الملاحظة والتفكيك. Decompilation الحقيقي يتطلب Ghidra/IDA غير مضمنة هنا.
- تم تخطي التحليل الديناميكي: التحليل الديناميكي معطل افتراضياً لتجنب تنفيذ كود غير موثوق. فعّله صراحة مع --enable-dynamic بعد التأكد من العزل.
- منهجية المقارنة: المقارنة تزيد الثقة عند التوافق وتخفضها عند التعارض؛ كل تعارض يجب التحقيق بمدخلات إضافية.
- Opcodes (capstone) — 50001 تعليمة: تم تفكيك 50001 تعليمة عبر capstone. أهمها: mov:12739, push:8970, call:3537, cmp:3409, lea:2637 | Blocks: 10626 | Functions: 300
- Control Flow — 10626 basic blocks: متوسط 4.71 تعليمة لكل block. Jumps/Calls تحدد التدفق.
- تقرير جاهز لإعادة البناء في C++: يحتوي opcodes_full.json.gz + skeleton.cpp + ai_report.json — يمكن إرسالها لنموذج AI لبناء C++ مكافئ.

**الواجهات التي يجب إعادة تنفيذها:**
- تلميحات واجهة سطر الأوامر — سلاسل تشبه خيارات CLI — data: `{"cli_hints": ["-jd_;", "-h%D", "-t%D", "-J0D", "-@0D", "-^0D", "-gqdt", "-]q}", "-+HC[", "-e@f", "-[bU\u0027*", "-tON", "-}\t/", "-RHj=", "-fa0o", "-%k0", "-{\u0027wb", "R--Plk", "-( ,", "-bH)", "-lh!20", "-ph!20", "-lth!20", "-U026C5x", "-lth!20=a", "-lth!20T", "-\u003c86", "-O|{", "-uh!", "-A~S", "-v\u0027}", "-Pte", "-%th!", "-D\u003e\"", "-Xh!20", "-+lt", "-002", "-p8p", "-!G4", "-uh!3", "-302", "-mth", "-Keam", "-#!20mh6\u0027", "-lth.", "-102", "-y6C5", "-lth", "-y024Lb", "-lti"]}` 

**الاعتمادات الإلزامية:**
- عدد 10 مكتبة معتمدة — `{'needed_libs': ['ADVAPI32.dll', 'GDI32.dll', 'USER32.dll', 'WINHTTP.dll', 'ole32.dll', 'OLEAUT32.dll', 'KERNEL32.dll', 'SHELL32.dll', 'gdiplus.dll', 'NETAPI32.dll']}`
- عدد 269 رمز مستورد (عينة 100 أولى محفوظة) — `{'imports_sample': ['ADVAPI32.dll!RegEnumKeyExA', 'ADVAPI32.dll!RegQueryValueExW', 'ADVAPI32.dll!CredDeleteW', 'ADVAPI32.dll!GetUserNameW', 'ADVAPI32.dll!RegOpenKeyExW', 'ADVAPI32.dll!RegOpenKeyExA', 'ADVAPI32.dll!RegSetValueExA', 'ADVAPI32.dll!GetUserNameA', 'ADVAPI32.dll!RegDeleteKeyA', 'ADVAPI32.dll!RegCloseKey', 'GDI32.dll!CreateSolidBrush', 'GDI32.dll!DeleteObject', 'GDI32.dll!SetBkColor', 'GDI32.dll!SetTextColor', 'GDI32.dll!DeleteDC', 'GDI32.dll!CreateRoundRectRgn', 'GDI32.dll!CreateFontW', 'GDI32.dll!CreateCompatibleDC', 'GDI32.dll!SelectObject', 'GDI32.dll!CreateCompatibleBitmap', 'GDI32.dll!BitBlt', 'USER32.dll!GetClientRect', 'USER32.dll!SetClipboardData', 'USER32.dll!SetCapture', 'USER32.dll!LoadCursorW', 'USER32.dll!LoadIconW', 'USER32.dll!TranslateMessage', 'USER32.dll!DestroyMenu', 'USER32.dll!EnumWindows', 'USER32.dll!TrackMouseEvent', 'USER32.dll!RegisterClassW', 'USER32.dll!EmptyClipboard', 'USER32.dll!CloseClipboard', 'USER32.dll!ClientToScreen', 'USER32.dll!DispatchMessageW', 'USER32.dll!GetCapture', 'USER32.dll!OpenClipboard', 'USER32.dll!IsWindow', 'USER32.dll!ShowWindow', 'USER32.dll!TrackPopupMenu', 'USER32.dll!CreatePopupMenu', 'USER32.dll!SendMessageW', 'USER32.dll!GetWindowTextW', 'USER32.dll!ScreenToClient', 'USER32.dll!CreateWindowExW', 'USER32.dll!SetWindowRgn', 'USER32.dll!MessageBoxW', 'USER32.dll!SetWindowPos', 'USER32.dll!IsWindowVisible', 'USER32.dll!GetDC', 'USER32.dll!DestroyWindow', 'USER32.dll!GetWindow', 'USER32.dll!PostMessageW', 'USER32.dll!DefWindowProcW', 'USER32.dll!GetMessageW', 'USER32.dll!InvalidateRect', 'USER32.dll!IsIconic', 'USER32.dll!ReleaseDC', 'USER32.dll!BeginPaint', 'USER32.dll!EndPaint', 'USER32.dll!UpdateWindow', 'USER32.dll!PostQuitMessage', 'USER32.dll!SystemParametersInfoW', 'USER32.dll!AppendMenuW', 'USER32.dll!PtInRect', 'USER32.dll!SetWindowTextW', 'USER32.dll!ReleaseCapture', 'WINHTTP.dll!WinHttpSetTimeouts', 'WINHTTP.dll!WinHttpSendRequest', 'WINHTTP.dll!WinHttpCloseHandle', 'WINHTTP.dll!WinHttpOpenRequest', 'WINHTTP.dll!WinHttpReadData', 'WINHTTP.dll!WinHttpQueryHeaders', 'WINHTTP.dll!WinHttpOpen', 'WINHTTP.dll!WinHttpReceiveResponse', 'WINHTTP.dll!WinHttpConnect', 'ole32.dll!CoSetProxyBlanket', 'ole32.dll!CoInitializeEx', 'ole32.dll!CreateStreamOnHGlobal', 'ole32.dll!CoCreateInstance', 'ole32.dll!CoUninitialize', 'OLEAUT32.dll!SysFreeString', 'OLEAUT32.dll!SysAllocString', 'OLEAUT32.dll!VariantClear', 'KERNEL32.dll!DecodePointer', 'KERNEL32.dll!HeapReAlloc', 'KERNEL32.dll!HeapSize', 'KERNEL32.dll!GetConsoleMode', 'KERNEL32.dll!GetConsoleOutputCP', 'KERNEL32.dll!FlushFileBuffers', 'KERNEL32.dll!GetStringTypeW', 'KERNEL32.dll!SetStdHandle', 'KERNEL32.dll!GetProcessHeap', 'KERNEL32.dll!FreeEnvironmentStringsW', 'KERNEL32.dll!GetEnvironmentStringsW', 'KERNEL32.dll!GetCommandLineW', 'KERNEL32.dll!GetCommandLineA', 'KERNEL32.dll!GetCPInfo', 'KERNEL32.dll!GetOEMCP', 'KERNEL32.dll!GetACP'], 'total': 269}`

**القيود:**
- لا تختلق كودًا غير مؤكد؛ وثّق السلوك فقط.
- إذا كان التقرير يذكر `unknown`، يجب أن يطلب التنفيذ الجديد توضيحًا أو يضع افتراضًا موثقًا.

**المخرجات المطلوبة للتنفيذ الجديد:**
1. برنامج مكافئ وظيفياً يحقق نفس المدخلات/المخرجات المرصودة.
2. نفس الواجهات (CLI/Files/Network) كما في `interfaces` و `dynamic`.
3. نفس الاعتمادات أو بدائل موثقة.
4. اختبارات تعيد إنتاج السلوك الديناميكي المرصود.

---

## الملاحق

### A) الأدلة الخام

جميع الأدلة محفوظة تحت `evidence/` داخل مجلد الـrun:
- `evidence/metadata/` — 4 findings — status ok
- `evidence/platform/` — 2 findings — status ok
- `evidence/structure/` — 1 findings — status ok
- `evidence/strings/` — 6 findings — status ok
- `evidence/imports_exports/` — 3 findings — status ok
- `evidence/resources/` — 1 findings — status ok
- `evidence/crypto/` — 3 findings — status ok
- `evidence/disasm/` — 3 findings — status ok
- `evidence/behavior/` — 7 findings — status ok
- `evidence/dynamic/` — 1 findings — status skipped
- `evidence/compare/` — 1 findings — status ok
- `evidence/deep_opcode/` — 4 findings — status ok

### B) كيفية إعادة الإنتاج

```bash
# إعادة تشغيل التحليل بنفس البيئة
revspec analyze "/tmp/CSX.exe" --output ./runs --enable-dynamic

# التحقق من الـhash
sha256sum "/tmp/CSX.exe"
# يجب أن يطابق 683520631b81a7283e9d7c0870115867ed29630a782348119308d22eae1b6f31

# التحقق من المخطط
python -m jsonschema -i report.json schemas/report.schema.json
```

### C) الترخيص والأخلاق

هذا التحليل أُجري على عينة يملكها المحلل أو لديه تصريح بها. لا تستخدم هذه المنهجية على برامج لا تملكها.

---

*تم إنشاء هذا التقرير بواسطة RevSpec v1.0.0 — 2026-09-25T17:18:56.529213Z*