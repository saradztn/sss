# تقرير الهندسة العكسية — RevSpec
> **للاستخدام فقط على البرامج التي تملكها أو لديك تصريح بتحليلها**
> هذا التقرير يميّز بوضوح بين **الحقيقة المرصودة** و**الاستنتاج**، ويذكر مصدر كل معلومة ودرجة الثقة.

---

## 1) معلومات البرنامج والعينة

| البند | القيمة |
|-------|--------|
| **اسم الملف** | `demo_app` |
| **المسار الأصلي** | `/home/user/sss/samples/demo_app/demo_app` |
| **الحجم** | 24640 بايت (24.06 KB) |
| **SHA256** | `10a158d7ca71d3b204fbf852145987952c560a02b0c2fc139e4a60d8bfb15761` |
| **SHA1** | `a354c8efb5fa5e3d3275aa5ff3681309ab399091` |
| **MD5** | `5c025f522cccae2155e89f84aed4f2fe` |
| **تاريخ الجمع** | 2026-09-25T15:41:09.039596Z |

### البيئة والمنصة (Host)

| البند | القيمة |
|-------|--------|
| نظام التشغيل | Linux-6.1.158+-x86_64-with-glibc2.36 |
| المعمارية | x86_64 |
| Python | 3.11.2 |
| Hostname | e2b.local |
| وقت التحليل | 2026-09-25T15:41:09.091279Z → 2026-09-25T15:41:09.163170Z |

**إصدارات الأدوات:**

- `readelf`: GNU readelf (GNU Binutils for Debian) 2.40
- `objdump`: GNU objdump (GNU Binutils for Debian) 2.40
- `nm`: GNU nm (GNU Binutils for Debian) 2.40
- `strings`: GNU strings (GNU Binutils for Debian) 2.40
- `ldd`: ldd (Debian GLIBC 2.36-9+deb12u14) 2.36
- `unzip`: caution:  both -n and -o specified; ignoring -o
- `jinja2`: 3.1.6
- `jsonschema`: 4.26.0

---

## 2) ملخص تنفيذي

- إجمالي الاستنتاجات: **32**
- موزعة حسب الفئة:
  - metadata: 4
  - platform: 2
  - structure: 2
  - strings: 5
  - dependencies: 1
  - behavior: 4
  - resources: 2
  - crypto: 2
  - disasm: 2
  - interfaces: 1
  - dynamic: 5
  - comparison: 2
- توزيع الثقة:
  - proven: 17
  - low: 2
  - high: 3
  - medium: 10
- توزيع المصدر:
  - observed: 19
  - inferred: 13

**حالة المحللات:**
- `metadata`: ok (0ms) - `platform`: ok (6ms) - `structure`: ok (9ms) - `strings`: ok (5ms) - `imports_exports`: ok (15ms) - `resources`: ok (10ms) - `crypto`: ok (4ms) - `disasm`: ok (8ms) - `behavior`: ok (2ms) - `dynamic`: ok (5ms) - `compare`: ok (0ms) 
---

## 3) بنية البرنامج

### ELF header — ✅ مُثبت (observed)
- **المصدر:** `structure:readelf -h` — `readelf -h`
- **الوصف:** Entry: 0x1480 | OSABI: SystemV
```json
{
  "entry_point": "0x1480",
  "header": "ELF Header:\n  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 \n  Class:                             ELF64\n  Data:                              2\u0027s complement, little endian\n  Version:                           1 (current)\n  OS/ABI:                            UNIX - System V\n  ABI Version:                       0\n  Type:                              DYN (Position-Independent Executable file)\n  Machine:                           Advanced Micro Devices X86-64\n  Version:                           0x1\n  Entry point address:               0x1480\n  Start of program headers:          64 (bytes into file)\n  Start of section headers:          22144 (bytes into file)\n  Flags:                             0x0\n  Size of this header:               64 (bytes)\n  Size of program headers:           56 (bytes)\n  Number of program headers:         13\n  Size of section headers:           64 (bytes)\n  Number of section headers:         39\n  Section header string table index: 38\n"
}
```### Sections / Segments — ✅ مُثبت (observed)
- **المصدر:** `structure:readelf -S/-l` — `readelf`
- **الوصف:** قائمة sections و segments كما أظهرها readelf
```json
{
  "sections_raw": "There are 39 section headers, starting at offset 0x5680:\n\nSection Headers:\n  [Nr] Name              Type             Address           Offset\n       Size              EntSize          Flags  Link  Info  Align\n  [ 0]                   NULL             0000000000000000  00000000\n       0000000000000000  0000000000000000           0     0     0\n  [ 1] .interp           PROGBITS         0000000000000318  00000318\n       000000000000001c  0000000000000000   A       0     0     1\n  [ 2] .note.gnu.pr[...] NOTE             0000000000000338  00000338\n       0000000000000020  0000000000000000   A       0     0     8\n  [ 3] .note.gnu.bu[...] NOTE             0000000000000358  00000358\n       0000000000000024  0000000000000000   A       0     0     4\n  [ 4] .note.ABI-tag     NOTE             000000000000037c  0000037c\n       0000000000000020  0000000000000000   A       0     0     4\n  [ 5] .gnu.hash         GNU_HASH         00000000000003a0  000003a0\n       0000000000000028  0000000000000000   A       6     0     8\n  [ 6] .dynsym           DYNSYM           00000000000003c8  000003c8\n       00000000000001e0  0000000000000018   A       7     1     8\n  [ 7] .dynstr           STRTAB           00000000000005a8  000005a8\n       00000000000000e1  0000000000000000   A       0     0     1\n  [ 8] .gnu.version      VERSYM           000000000000068a  0000068a\n       0000000000000028  0000000000000002   A       6     0     2\n  [ 9] .gnu.version_r    VERNEED          00000000000006b8  000006b8\n       0000000000000030  0000000000000000   A       7     1     8\n  [10] .rela.dyn         RELA             00000000000006e8  000006e8\n       00000000000000d8  0000000000000018   A       6     0     8\n  [11] .rela.plt         RELA             00000000000007c0  000007c0\n       0000000000000138  0000000000000018  AI       6    24     8\n  [12] .init             PROGBITS         0000000000001000  00001000\n       0000000000000017  0000000000000000  AX       0     0     4\n  [13] .plt              PROGBITS         0000000000001020  00001020\n       00000000000000e0  0000000000000010  AX       0     0     16\n  [14] .plt.got          PROGBITS         0000000000001100  00001100\n       0000000000000008  0000000000000008  AX       0     0     8\n  [15] .text             PROGBITS         0000000000001110  00001110\n       0000000000000710  0000000000000000  AX       0     0     16\n  [16] .fini             PROGBITS         0000000000001820  00001820\n       0000000000000009  0000000000000000  AX       0     0     4\n  [17] .rodata           PROGBITS         0000000000002000  00002000\n       00000000000004c1  0000000000000000   A       0     0     8\n  [18] .eh_frame_hdr     PROGBITS         00000000000024c4  000024c4\n       0000000000000054  0000000000000000   A       0     0     4\n  [19] .eh_frame         PROGBITS         0000000000002518  00002518\n       0000000000000198  0000000000000000   A       0     0     8\n  [20] .init_array       INIT_ARRAY       0000000000003dd0  00002dd0\n       0000000000000008  0000000000000008  WA       0     0     8\n  [21] .fini_array       FINI_ARRAY       0000000000003dd8  00002dd8\n       0000000000000008  0000000000000008  WA       0     0     8\n  [22] .dynamic          DYNAMIC          0000000000003de0  00002de0\n       00000000000001e0  0000000000000010  WA       7     0     8\n  [23] .got              PROGBITS         0000000000003fc0  00002fc0\n       0000000000000028  0000000000000008  WA       0     0     8\n  [24] .got.plt          PROGBITS         0000000000003fe8  00002fe8\n       0000000000000080  0000000000000008  WA       0     0     8\n  [25] .data             PROGBITS         0000000000004068  00003068\n       0000000000000010  0000000000000000  WA       0     0     8\n  [26] .bss              NOBITS           0000000000004080  00003078\n       0000000000000010  0000000000000000  WA       0     0     32\n  [27] .comment          PROGBITS         0000000000000000  00003078\n       0000000000000027  0000000000000001  MS       0     0     1\n  [28] .",
  "segments_raw": "\nElf file type is DYN (Position-Independent Executable file)\nEntry point 0x1480\nThere are 13 program headers, starting at offset 64\n\nProgram Headers:\n  Type           Offset             VirtAddr           PhysAddr\n                 FileSiz            MemSiz              Flags  Align\n  PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040\n                 0x00000000000002d8 0x00000000000002d8  R      0x8\n  INTERP         0x0000000000000318 0x0000000000000318 0x0000000000000318\n                 0x000000000000001c 0x000000000000001c  R      0x1\n      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]\n  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000\n                 0x00000000000008f8 0x00000000000008f8  R      0x1000\n  LOAD           0x0000000000001000 0x0000000000001000 0x0000000000001000\n                 0x0000000000000829 0x0000000000000829  R E    0x1000\n  LOAD           0x0000000000002000 0x0000000000002000 0x0000000000002000\n                 0x00000000000006b0 0x00000000000006b0  R      0x1000\n  LOAD           0x0000000000002dd0 0x0000000000003dd0 0x0000000000003dd0\n                 0x00000000000002a8 0x00000000000002c0  RW     0x1000\n  DYNAMIC        0x0000000000002de0 0x0000000000003de0 0x0000000000003de0\n                 0x00000000000001e0 0x00000000000001e0  RW     0x8\n  NOTE           0x0000000000000338 0x0000000000000338 0x0000000000000338\n                 0x0000000000000020 0x0000000000000020  R      0x8\n  NOTE           0x0000000000000358 0x0000000000000358 0x0000000000000358\n                 0x0000000000000044 0x0000000000000044  R      0x4\n  GNU_PROPERTY   0x0000000000000338 0x0000000000000338 0x0000000000000338\n                 0x0000000000000020 0x0000000000000020  R      0x8\n  GNU_EH_FRAME   0x00000000000024c4 0x00000000000024c4 0x00000000000024c4\n                 0x0000000000000054 0x0000000000000054  R      0x4\n  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000\n                 0x0000000000000000 0x0000000000000000  RW     0x10\n  GNU_RELRO      0x0000000000002dd0 0x0000000000003dd0 0x0000000000003dd0\n                 0x0000000000000230 0x0000000000000230  R      0x1\n\n Section to Segment mapping:\n  Segment Sections...\n   00     \n   01     .interp \n   02     .interp .note.gnu.property .note.gnu.build-id .note.ABI-tag .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt \n   03     .init .plt .plt.got .text .fini \n   04     .rodata .eh_frame_hdr .eh_frame \n   05     .init_array .fini_array .dynamic .got .got.plt .data .bss \n   06     .dynamic \n   07     .note.gnu.property \n   08     .note.gnu.build-id .note.ABI-tag \n   09     .note.gnu.property \n   10     .eh_frame_hdr \n   11     \n   12     .init_array .fini_array .dynamic .got \n"
}
```
---

## 4) المنصة والمعمارية والـRuntime

### صيغة الملف / المنصة — ✅ مُثبت
- **المنهج:** elf_magic
- **الوصف:** الصيغة المكتشفة: ELF | المعمارية: x86-64 | البت: 64
```json
{
  "arch": "x86-64",
  "bitness": 64,
  "e_machine": 62,
  "e_type": "DYN",
  "ei_osabi_raw": 0,
  "endian": "little",
  "format": "ELF",
  "osabi": "SystemV"
}
```### تلميحات Runtime / اللغة — 🟠 منخفض
- **المنهج:** keyword search in strings
- **الوصف:** تلميحات لغوية/تقنية مستنتجة من strings و readelf
```json
{
  "hints": [
    "interpreter:/lib64/ld-linux-x86-64.so.2]"
  ]
}
```
---

## 5) المكونات والوحدات المكتشفة

- **الرموز المستوردة** — ✅ مُثبت — عدد 14 رمز مستورد (عينة 100 أولى محفوظة)
  - مصدر: `imports_exports:nm/objdump/pefile`
  - عينة imports: `__libc_start_main@GLIBC_2.34, access@GLIBC_2.2.5, fclose@GLIBC_2.2.5, fgets@GLIBC_2.2.5, fopen@GLIBC_2.2.5, fprintf@GLIBC_2.2.5, fwrite@GLIBC_2.2.5, perror@GLIBC_2.2.5, printf@GLIBC_2.2.5, puts@GLIBC_2.2.5` (الإجمالي 14)

### الموارد
- **سلاسل إصدار** — 🟡 متوسط — سلاسل تشبه أرقام إصدار
```json
{
  "versions": [
    "127.0.0.1",
    "12.2.0",
    "1.2.3"
  ]
}
```- **تلميحات ملفات إعداد** — 🟡 متوسط — مسارات تشبه ملفات إعداد/قواعد بيانات
```json
{
  "configs": [
    "/config.ini"
  ]
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
    "system@GLIBC_2.2.5"
  ]
}
```- **سلوك محتمل: عمليات شبكة** — 🟡 متوسط — tags: network, heuristic
  - تم العثور على ['connect'] مطابقة للنمط \b(socket|connect|bind|listen|accept|send|recv)\b
  - مصدر: `behavior:regex over imports+strings` / `regex \b(socket|connect|bind|listen|accept|send|recv)\b`
```json
{
  "description": "\u0639\u0645\u0644\u064a\u0627\u062a \u0634\u0628\u0643\u0629",
  "hits": [
    "connect"
  ],
  "pattern": "\\b(socket|connect|bind|listen|accept|send|recv)\\b",
  "tag": "network"
}
```- **سلوك محتمل: عمليات ملفات** — 🟡 متوسط — tags: file-io, heuristic
  - تم العثور على ['fwrite', 'fopen', 'open'] مطابقة للنمط \b(open|read|write|fopen|fwrite|fread|creat)\b
  - مصدر: `behavior:regex over imports+strings` / `regex \b(open|read|write|fopen|fwrite|fread|creat)\b`
```json
{
  "description": "\u0639\u0645\u0644\u064a\u0627\u062a \u0645\u0644\u0641\u0627\u062a",
  "hits": [
    "fwrite",
    "fopen",
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
```
---

## 7) الواجهات والمدخلات والمخرجات

- **تلميحات واجهة سطر الأوامر** — 🟠 منخفض
  - سلاسل تشبه خيارات CLI
```json
{
  "cli_hints": [
    "-h, --help       Show help",
    "--help",
    "--version",
    "--connect",
    "--debug",
    "-v, --version    Show version"
  ]
}
```
> **ملاحظة:** الواجهات الموثقة هنا هي **قابلة للملاحظة** فقط (CLI args, file paths, env vars, network endpoints). لا ندّعي معرفة بروتوكول داخلي غير مرصود.

---

## 8) الاعتمادات

انظر قسم المكونات أعلاه. ملخص `needed` و `imports` يمثل **الاعتمادات المباشرة المرصودة**. الاعتمادات العابرة (transitive) غير مستنتجة إلا إذا ظهرت في `ldd` الديناميكي.

---

## 9) تدفقات البيانات والأحداث

- **رمز الخروج** — ✅ مُثبت (observed)
  - exit code = 0
- **مخرجات stdout** — ✅ مُثبت (observed)
  - [DEBUG] debug enabled, config=./config.ini output=/tmp/demo_output.txt
[DEBUG] token=demo-secret-token-12345
=== demo_app v1.2.3 ===
Platform: Linux x86-64 (ELF)
[*] Config not found at ./config.ini, using defaults
[*] Wrote output to /tmp/demo_output.txt
[DEBUG] b64 alphabet: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
[*] Done. Exit 0.

- **مخرجات stderr** — ✅ مُثبت (observed)
  - (لا يوجد stderr)
- **strace غير متوفر** — ✅ مُثبت (observed)
  - لا يمكن تتبع syscalls بدون strace
- **قيود التحليل الديناميكي** — ✅ مُثبت (observed)
  - السلوك المرصود يعتمد على المدخلات المقدمة والبيئة المعزولة؛ قد يختلف بمدخلات أخرى. لا يشمل كل المسارات.

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
  "static_network_hint": false,
  "static_paths_sample": [
    "/usr/include",
    "/tmp/demo_output.txt",
    "/usr/lib/gcc/x86_64-linux-gnu/12/include",
    "/config.ini",
    "/usr/include/x86_64-linux-gnu/bits/types",
    "/dev/tcp/127.0.0.1/9999",
    "/dev/null",
    "/example.com/api/v1/status",
    "/lib64/ld-linux-x86-64.so.2",
    "/home/user/sss/samples/demo_app"
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
| structure | ok | 2 findings |
| strings | ok | 5 findings |
| imports_exports | ok | 2 findings |
| resources | ok | 2 findings |
| crypto | ok | 2 findings |
| disasm | ok | 2 findings |
| behavior | ok | 4 findings |

**أبرز الاستنتاجات الثابتة:**

- [✅ مُثبت] **SHA256** — SHA256 للعينة = 10a158d7ca71d3b204fbf852145987952c560a02b0c2fc139e4a60d8bfb15761 — *metadata:hashlib.sha256*
- [✅ مُثبت] **حجم الملف** — حجم الملف 24640 بايت — *metadata:stat*
- [✅ مُثبت] **طوابع زمنية لنظام الملفات** — mtime/ctime من نظام الملفات (قد لا تعكس وقت البناء) — *metadata:stat*
- [✅ مُثبت] **Magic bytes** — أول 16 بايت hex: 7f454c46020101000000000000000000 — *metadata:read*
- [✅ مُثبت] **صيغة الملف / المنصة** — الصيغة المكتشفة: ELF | المعمارية: x86-64 | البت: 64 — *platform:elf_magic*
- [🟠 منخفض] **تلميحات Runtime / اللغة** — تلميحات لغوية/تقنية مستنتجة من strings و readelf — *platform:strings+readelf*
- [✅ مُثبت] **ELF header** — Entry: 0x1480 | OSABI: SystemV — *structure:readelf -h*
- [✅ مُثبت] **Sections / Segments** — قائمة sections و segments كما أظهرها readelf — *structure:readelf -S/-l*
- [✅ مُثبت] **ملخص السلاسل** — إجمالي 241 سلسلة ascii (+ 0 utf16) — *strings:strings(1)*
- [🔵 عالي] **URLs مكتشفة** — عناوين URL مستخرجة من السلاسل — *strings:regex*
- [🟡 متوسط] **عناوين IP** — عناوين IP محتملة — *strings:regex*
- [🟡 متوسط] **كلمات مفتاحية مثيرة** — كلمات دلالية قد تشير لوظائف حساسة — *strings:keyword search*
- [🟡 متوسط] **مسارات ملفات** — مسارات ملفات مستخرجة (عينة من 50) — *strings:regex*
- [✅ مُثبت] **الرموز المستوردة** — عدد 14 رمز مستورد (عينة 100 أولى محفوظة) — *imports_exports:nm/objdump/pefile*
- [🟡 متوسط] **استيرادات مثيرة للانتباه** — استيرادات قد تشير لقدرات حساسة (لا تعني خبثًا بحد ذاتها) — *imports_exports:heuristic*
- [🟡 متوسط] **إنتروبي منخفض — نص/كود غير مضغوط** — إنتروبي 3.90 منخفض يشير لملف غير مشفر/غير مضغوط — *crypto:entropy*
- [🔵 عالي] **ثوابت تشفير معروفة** — تم العثور على ثوابت/علامات تشفير — *crypto:constant search*
- [✅ مُثبت] **Disassembly عبر objdump** — تم تفكيك 557 سطر، 28 دالة محتملة — *disasm:objdump -d*
- [✅ مُثبت] **قيود الاستعادة** — لا يمكن استعادة المصدر الأصلي حرفيًا من binary؛ ما نستعيده هو سلوك مكافئ عبر الملاحظة والتفكيك. Decompilation الحقيقي يتطلب Ghidra/IDA غير مضمنة هنا. — *disasm:disclaimer*
- [🟡 متوسط] **سلوك محتمل: عمليات شبكة** — تم العثور على ['connect'] مطابقة للنمط \b(socket|connect|bind|listen|accept|send|recv)\b — *behavior:regex over imports+strings*
- [🟡 متوسط] **سلوك محتمل: عمليات ملفات** — تم العثور على ['fwrite', 'fopen', 'open'] مطابقة للنمط \b(open|read|write|fopen|fwrite|fread|creat)\b — *behavior:regex over imports+strings*
- [🟡 متوسط] **سلوك محتمل: إنشاء عمليات** — تم العثور على ['system'] مطابقة للنمط \b(execve|execvp|system|popen|fork|clone)\b — *behavior:regex over imports+strings*

---

## 13) نتائج التحليل الديناميكي

- [✅ مُثبت] **رمز الخروج** — exit code = 0
- [✅ مُثبت] **مخرجات stdout** — [DEBUG] debug enabled, config=./config.ini output=/tmp/demo_output.txt
[DEBUG] token=demo-secret-token-12345
=== demo_app v1.2.3 ===
Platform: Linux x86-64 (ELF)
[*] Config not found at ./config.ini, using defaults
[*] Wrote output to /tmp/demo_output.txt
[DEBUG] b64 alphabet: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
[*] Done. Exit 0.

- [✅ مُثبت] **مخرجات stderr** — (لا يوجد stderr)
- [✅ مُثبت] **strace غير متوفر** — لا يمكن تتبع syscalls بدون strace
- [✅ مُثبت] **قيود التحليل الديناميكي** — السلوك المرصود يعتمد على المدخلات المقدمة والبيئة المعزولة؛ قد يختلف بمدخلات أخرى. لا يشمل كل المسارات.

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
- **SHA256** — SHA256 للعينة = 10a158d7ca71d3b204fbf852145987952c560a02b0c2fc139e4a60d8bfb15761 — `metadata:hashlib.sha256` — `hashlib.sha256 over file bytes`
- **حجم الملف** — حجم الملف 24640 بايت — `metadata:stat` — `stat.st_size`
- **طوابع زمنية لنظام الملفات** — mtime/ctime من نظام الملفات (قد لا تعكس وقت البناء) — `metadata:stat` — `stat.st_mtime/ctime`
- **Magic bytes** — أول 16 بايت hex: 7f454c46020101000000000000000000 — `metadata:read` — `read first 16 bytes`
- **صيغة الملف / المنصة** — الصيغة المكتشفة: ELF | المعمارية: x86-64 | البت: 64 — `platform:elf_magic` — `elf_magic`
- **ELF header** — Entry: 0x1480 | OSABI: SystemV — `structure:readelf -h` — `readelf -h`
- **Sections / Segments** — قائمة sections و segments كما أظهرها readelf — `structure:readelf -S/-l` — `readelf`
- **ملخص السلاسل** — إجمالي 241 سلسلة ascii (+ 0 utf16) — `strings:strings(1)` — `strings -a -n 4`
- **URLs مكتشفة** — عناوين URL مستخرجة من السلاسل — `strings:regex` — `regex https?://`
- **الرموز المستوردة** — عدد 14 رمز مستورد (عينة 100 أولى محفوظة) — `imports_exports:nm/objdump/pefile` — `nm -D / objdump`
- **ثوابت تشفير معروفة** — تم العثور على ثوابت/علامات تشفير — `crypto:constant search` — `byte pattern search`
- **Disassembly عبر objdump** — تم تفكيك 557 سطر، 28 دالة محتملة — `disasm:objdump -d` — `objdump -d -M intel`
- **قيود الاستعادة** — لا يمكن استعادة المصدر الأصلي حرفيًا من binary؛ ما نستعيده هو سلوك مكافئ عبر الملاحظة والتفكيك. Decompilation الحقيقي يتطلب Ghidra/IDA غير مضمنة هنا. — `disasm:disclaimer` — `design principle`
- **رمز الخروج** — exit code = 0 — `dynamic:runner` — `waitpid`
- **مخرجات stdout** — [DEBUG] debug enabled, config=./config.ini output=/tmp/demo_output.txt
[DEBUG] token=demo-secret-token-12345
=== demo_app v1.2.3 ===
Platform: Linux x86-64 (ELF)
[*] Config not found at ./config.ini, using defaults
[*] Wrote output to /tmp/demo_output.txt
[DEBUG] b64 alphabet: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
[*] Done. Exit 0.
 — `dynamic:runner` — `capture stdout`
- **مخرجات stderr** — (لا يوجد stderr) — `dynamic:runner` — `capture stderr`
- **strace غير متوفر** — لا يمكن تتبع syscalls بدون strace — `dynamic:missing` — `which strace`
- **قيود التحليل الديناميكي** — السلوك المرصود يعتمد على المدخلات المقدمة والبيئة المعزولة؛ قد يختلف بمدخلات أخرى. لا يشمل كل المسارات. — `dynamic:disclaimer` — `design`
- **منهجية المقارنة** — المقارنة تزيد الثقة عند التوافق وتخفضها عند التعارض؛ كل تعارض يجب التحقيق بمدخلات إضافية. — `compare:disclaimer` — `design`

### 🔍 مستنتجة (inferred)
- **تلميحات Runtime / اللغة** — تلميحات لغوية/تقنية مستنتجة من strings و readelf — ثقة: 🟠 منخفض — `keyword search in strings`
- **عناوين IP** — عناوين IP محتملة — ثقة: 🟡 متوسط — `ipv4 regex`
- **كلمات مفتاحية مثيرة** — كلمات دلالية قد تشير لوظائف حساسة — ثقة: 🟡 متوسط — `case-insensitive substring count`
- **مسارات ملفات** — مسارات ملفات مستخرجة (عينة من 50) — ثقة: 🟡 متوسط — `path regex`
- **استيرادات مثيرة للانتباه** — استيرادات قد تشير لقدرات حساسة (لا تعني خبثًا بحد ذاتها) — ثقة: 🟡 متوسط — `keyword match against imports`
- **سلاسل إصدار** — سلاسل تشبه أرقام إصدار — ثقة: 🟡 متوسط — `version regex`
- **تلميحات ملفات إعداد** — مسارات تشبه ملفات إعداد/قواعد بيانات — ثقة: 🟡 متوسط — `extension keyword`
- **إنتروبي منخفض — نص/كود غير مضغوط** — إنتروبي 3.90 منخفض يشير لملف غير مشفر/غير مضغوط — ثقة: 🟡 متوسط — `shannon`
- **سلوك محتمل: عمليات شبكة** — تم العثور على ['connect'] مطابقة للنمط \b(socket|connect|bind|listen|accept|send|recv)\b — ثقة: 🟡 متوسط — `regex \b(socket|connect|bind|listen|accept|send|recv)\b`
- **سلوك محتمل: عمليات ملفات** — تم العثور على ['fwrite', 'fopen', 'open'] مطابقة للنمط \b(open|read|write|fopen|fwrite|fread|creat)\b — ثقة: 🟡 متوسط — `regex \b(open|read|write|fopen|fwrite|fread|creat)\b`
- **سلوك محتمل: إنشاء عمليات** — تم العثور على ['system'] مطابقة للنمط \b(execve|execvp|system|popen|fork|clone)\b — ثقة: 🟡 متوسط — `regex \b(execve|execvp|system|popen|fork|clone)\b`
- **تلميحات واجهة سطر الأوامر** — سلاسل تشبه خيارات CLI — ثقة: 🟠 منخفض — `lines starting with -`
- **توافق عدم وجود شبكة** — لا يوجد دليل شبكة في الثابت ولا الديناميكي — ثقة: 🔵 عالي — `negative both`

### ❓ غير محددة / تعذر تحديدها

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

- SHA256: SHA256 للعينة = 10a158d7ca71d3b204fbf852145987952c560a02b0c2fc139e4a60d8bfb15761
- حجم الملف: حجم الملف 24640 بايت
- طوابع زمنية لنظام الملفات: mtime/ctime من نظام الملفات (قد لا تعكس وقت البناء)
- Magic bytes: أول 16 بايت hex: 7f454c46020101000000000000000000
- صيغة الملف / المنصة: الصيغة المكتشفة: ELF | المعمارية: x86-64 | البت: 64
- ELF header: Entry: 0x1480 | OSABI: SystemV
- Sections / Segments: قائمة sections و segments كما أظهرها readelf
- ملخص السلاسل: إجمالي 241 سلسلة ascii (+ 0 utf16)
- URLs مكتشفة: عناوين URL مستخرجة من السلاسل
- الرموز المستوردة: عدد 14 رمز مستورد (عينة 100 أولى محفوظة)
- ثوابت تشفير معروفة: تم العثور على ثوابت/علامات تشفير
- Disassembly عبر objdump: تم تفكيك 557 سطر، 28 دالة محتملة
- قيود الاستعادة: لا يمكن استعادة المصدر الأصلي حرفيًا من binary؛ ما نستعيده هو سلوك مكافئ عبر الملاحظة والتفكيك. Decompilation الحقيقي يتطلب Ghidra/IDA غير مضمنة هنا.
- رمز الخروج: exit code = 0
- مخرجات stdout: [DEBUG] debug enabled, config=./config.ini output=/tmp/demo_output.txt
[DEBUG] token=demo-secret-token-12345
=== demo_app v1.2.3 ===
Platform: Linux x86-64 (ELF)
[*] Config not found at ./config.ini, using defaults
[*] Wrote output to /tmp/demo_output.txt
[DEBUG] b64 alphabet: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
[*] Done. Exit 0.

- مخرجات stderr: (لا يوجد stderr)
- strace غير متوفر: لا يمكن تتبع syscalls بدون strace
- قيود التحليل الديناميكي: السلوك المرصود يعتمد على المدخلات المقدمة والبيئة المعزولة؛ قد يختلف بمدخلات أخرى. لا يشمل كل المسارات.
- توافق عدم وجود شبكة: لا يوجد دليل شبكة في الثابت ولا الديناميكي
- منهجية المقارنة: المقارنة تزيد الثقة عند التوافق وتخفضها عند التعارض؛ كل تعارض يجب التحقيق بمدخلات إضافية.

**الواجهات التي يجب إعادة تنفيذها:**
- تلميحات واجهة سطر الأوامر — سلاسل تشبه خيارات CLI — data: `{"cli_hints": ["-h, --help       Show help", "--help", "--version", "--connect", "--debug", "-v, --version    Show version"]}` 

**الاعتمادات الإلزامية:**
- عدد 14 رمز مستورد (عينة 100 أولى محفوظة) — `{'imports_sample': ['__libc_start_main@GLIBC_2.34', 'access@GLIBC_2.2.5', 'fclose@GLIBC_2.2.5', 'fgets@GLIBC_2.2.5', 'fopen@GLIBC_2.2.5', 'fprintf@GLIBC_2.2.5', 'fwrite@GLIBC_2.2.5', 'perror@GLIBC_2.2.5', 'printf@GLIBC_2.2.5', 'puts@GLIBC_2.2.5', 'strcmp@GLIBC_2.2.5', 'strcspn@GLIBC_2.2.5', 'strstr@GLIBC_2.2.5', 'system@GLIBC_2.2.5'], 'total': 14}`

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
- `evidence/structure/` — 2 findings — status ok
- `evidence/strings/` — 5 findings — status ok
- `evidence/imports_exports/` — 2 findings — status ok
- `evidence/resources/` — 2 findings — status ok
- `evidence/crypto/` — 2 findings — status ok
- `evidence/disasm/` — 2 findings — status ok
- `evidence/behavior/` — 4 findings — status ok
- `evidence/dynamic/` — 5 findings — status ok
- `evidence/compare/` — 2 findings — status ok

### B) كيفية إعادة الإنتاج

```bash
# إعادة تشغيل التحليل بنفس البيئة
revspec analyze "/home/user/sss/samples/demo_app/demo_app" --output ./runs --enable-dynamic

# التحقق من الـhash
sha256sum "/home/user/sss/samples/demo_app/demo_app"
# يجب أن يطابق 10a158d7ca71d3b204fbf852145987952c560a02b0c2fc139e4a60d8bfb15761

# التحقق من المخطط
python -m jsonschema -i report.json schemas/report.schema.json
```

### C) الترخيص والأخلاق

هذا التحليل أُجري على عينة يملكها المحلل أو لديه تصريح بها. لا تستخدم هذه المنهجية على برامج لا تملكها.

---

*تم إنشاء هذا التقرير بواسطة RevSpec v1.0.0 — 2026-09-25T15:41:09.163170Z*