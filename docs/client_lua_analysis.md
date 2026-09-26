# client.lua — تحديد العينة وتقرير تحليل بنيوي

> **خلاصة:** `client.lua` ليس كود Lua إطلاقاً. إنه **مُخرَج تفكيك (Ghidra Listing) بصيغة نصية**
> للملف التنفيذي `CSX.exe` الموجود في نفس المستودع.
> كل الأرقام والعناوين في هذا التقرير مستخرجة مباشرة من الملفين في هذه الجلسة (انظر "أدلة التحقق").

---

## 1) ما هو `client.lua` فعلياً

| البند | القيمة المقاسة |
|---|---|
| الحجم | 11,596,148 بايت |
| عدد الأسطر | 183,871 |
| أول 4 بايتات | `20 20 20 20` (مسافات) — لا يوجد توقيع Lua (`1b 4c 75 61` غائب) |
| أسطر عناوين/تعليمات (`^         XXXXXXXX bb`) | 127,261 |
| تسميات دوال `FUN_xxxxxxxx` مميزة | 630 (628 منها لها سطر توقيع دالة) |
| تسميات `LAB_xxxxxxxx` مميزة | 5,732 |
| مراجع استيراد `->MODULE::Func` مميزة | 272 |
| نصوص Unicode موثّقة في عمود التعليقات | 242 |

الأسطر التي تبدأ بـ `--` (802 سطر) هي تعليقات Ghidra وليست تعليقات Lua:

```
1089:                             -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
```

الصيغة هي صيغة **Ghidra "Listing" النصي** (`List Program > ASCII`): أعمدة العنوان، البايتات،
التعليمة، عمود التسمية/التعليق، وعمود `XREF[...]`.

## 2) أدلة التحقق: `client.lua` == `CSX.exe`

**أ) جدول الأقسام مطابق تماماً.** من رأس `CSX.exe`:

```
PE off 0x110 | Machine 0x14c (i386) | NumberOfSections 7 | ImageBase 0x400000
EntryPoint RVA 0x22052 -> VA 0x422052 | OptionalHeader size 0xE0
.text    VA 0x1000  vsize 0x376f9  raw 0x400    rawsize 0x37800
.mmap    VA 0x39000 vsize 0x245    raw 0x37c00  rawsize 0x400
.rdata   VA 0x3a000 vsize 0x109a0  raw 0x38000  rawsize 0x10a00
.data    VA 0x4b000 vsize 0x1f08   raw 0x48a00  rawsize 0xe00
.fptable VA 0x4d000 vsize 0x80     raw 0x49800  rawsize 0x200
.rsrc    VA 0x4e000 vsize 0x597638 raw 0x49a00  rawsize 0x597800
.reloc   VA 0x5e6000 vsize 0x28d4  raw 0x5e1200 rawsize 0x2a00
```

ومن `client.lua` نفس الأسماء بالترتيب نفسه عند `00400208 … 004002f8`:
`.text, .mmap, .rdata, .data, .fptable, .rsrc, .reloc`، ونقطة الدخول `entry: 00422052`.

**ب) تطابق بايت-ببايت.** التعليمات في `client.lua` عند `0040a8db`:

```
0040a8db 68 00 00 00 80 50 ff 15 74 a1 43 00 8b f0 89 b5
```

وفي `CSX.exe` عند إزاحة الملف `0x9cdb` (= RVA 0xA8DB داخل `.text`):

```
68 00 00 00 80 50 ff 15 74 a1 43 00 8b f0 89 b5
```

مطابق حرفياً. `client.lua` هو تفكيك `CSX.exe` (حجمه 6,175,744 بايت).

**ج) حجم `.rsrc` = 5,862,968 بايت (vsize؛ rawsize 5,863,424) من أصل 6,175,744 بايت للملف = 94.9%** —
أي أن الغالبية العظمى من الملف حمولة مضمّنة في الموارد، والكود الفعلي للـ loader صغير نسبياً
(`.text` = 227,065 بايت vsize). وقسم `.mmap` = 581 بايت (0x245) فقط.

---

## 3) هوية العينة

`CSX.exe` هو **Loader (مُحمِّل) لـ cheat مخصص للعبة Multi Theft Auto: San Andreas**،
بواجهة Windows رسومية مبنية على GDI+. الأدلة النصية من التفكيك:

- `u"XRF LOADER"`, `u"XRF Loader"`, `u"CSX Update"`, `u"CSX.exe"`, `u"DARKANARCHY XRAOUF"`, `u"xraouf"`
- `u"csxcheat.dll"`, `u"agent.dll"`, `u"csxprobe.exe"`, `u"CSXcsxbugs.log"`
- `u"I N J E C T"`, `u"gta_sa.exe"`, `u"Multi Theft Auto.exe"`, `u"\\Multi Theft Auto.exe"`
- `u"Resetting MTA serial..."`, `u"R E S E T   S E R I A L"`, `u"Serial reset complete"`
- `u"[ok] csxcheat.dll detected inside gta_sa.exe"`, `u"[ok] csxcheat.dll mapped before g..."`
- `u"You are banned.\\nReason: "`, `u"Banned"`, `u"Banned (local)"`, `u"Locally banned"`
- `u"Server offline (fail-open)"`
- `u"https://discord.gg/VE9ZXu2tc"` (رابط Discord للناشر)

## 4) خريطة السلوك (بعناوين حقيقية من التفكيك)

### 4.1 استخراج الحمولة من الموارد
- `FUN_00402e60` — `FindResourceW` (00402e7d) → `LoadResource` (00402e90) → `SizeofResource` (00402eb7)
- مسار ثانٍ عند `00409db8 / 00409dcf / 00409ded`
- أسماء الحمولة: `agent.dll` (0040292f)، `csxcheat.dll` (00402a18)

### 4.2 الحَقن في عملية اللعبة
- `FUN_00402020` — `VirtualAllocEx` (004021d6, 004021f8) → `WriteProcessMemory` (0040224b, 004022bd)
  → `VirtualAllocEx` (00402370) → `WriteProcessMemory` (004023a5, 004023be) → `CreateRemoteThread` (004023d6)
- `FUN_00409fc0` — `OpenProcess` (0040a1dd) + رسالة `[error] OpenProcess failed: ` (0040a20c)
- `FUN_0040b520` — الحَقن المبكر: `[ok] csxcheat.dll detected inside gta_sa.exe` (0040cbff)،
  `[ok] csxcheat.dll mapped before g...` (0040d040)
- حقن ثاني عند 0040a6c5 / 0040a6e5 / 0040a711 (`VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`)
- إطلاق العملية معلّقة: `CreateProcessW` في 0040c36a + `[error] CreateProcessW failed: ` (0040c3ed)،
  ونصوص `(suspended)`, `), attaching`
- قسم `.mmap` (VA 0x39000، 0x245 بايت) يحتوي **stub لـ PE loader** يعمل في الذاكرة:
  `55 8b ec 83 ec 58 8b 45 08 89 45 f8 8b 4d f8 8b 51 04 8b 45 f8 8b 08 2b 4a 34 89 4d d4 …`
  (يقرأ `e_lfanew` عند +0x3c ويحسب فرق قواعد التحميل) — دليل manual mapping.

### 4.3 اكتشاف مسار اللعبة
- مفاتيح السجل: `SOFTWARE\Multi Theft Auto: San Andreas All\…`, `…: Province All\1.6`,
  `SOFTWARE\Multi Theft Auto\1.6`, ونسخ `WOW6432Node` (00443340 … 00443610)
- مسارات ثابتة: `C:\MTA San Andreas 1.6`, `D:\Games\MTA San Andreas 1.5/1.6`, `D:\MTA San Andreas 1.6`,
  `E:\MTA San Andreas 1.6` + `\Multi Theft Auto.exe` (00443858)
- `[info] gta_sa.exe already running` (0040a05c)، `[info] mta path: `، `[info] launching: `

### 4.4 بصمة العتاد وإعادة ضبط الـ Serial (تجاوز الحظر)
- `MachineGuid` (00403da8, 00403e0e) من المفتاح `SOFTWARE\Microsoft\Cryptography`
  (النص عند 004439a8، يُقرأ في `FUN_00403d20` عبر الدفع عند 00403d71)
- WMI عبر COM: `CoInitializeEx/CoCreateInstance/CoSetProxyBlanket` + `ROOT\CIMV2` (00404050)
  + استعلامات `SELECT SerialNumber FROM Win32_B…` (00443aa8) و`Win32_D…` (00443b00)
  في `FUN_00403d20`/`00408e5f`/`00408ec2`/`0041c120`/`0041c187`
- `Manufacturer`, `Model`, `Name`, `SSO_RND_Device`
- `CredDeleteW` في `FUN_0040eff0` (0040f026)
- `RegDeleteKeyA` / `RegSetValueExA` + رسائل `Resetting MTA serial...` (0040fa9b) و`Serial reset complete`

### 4.5 الشبكة والتحديث وفحص الحظر
- `WinHttp*` كاملة (9 دوال)؛ `WinHttpOpen` في 0040441a, 00404829, 00413d22, 004157cd, 00418854
- نطاقات: `api.ipify.org`, `ip-api.com`, `raw.githubusercontent.com`, `cdn.jsdelivr.net`,
  مسارات `/api/event`, `/api/heartbeat`, `/json/`, `?fields=status,country`, `?cb=`، User-Agent `CSX/1.0`
- مستودعات التحديث الحرفية داخل البايتات:
  `/gh/onlyyoussef/csx-update@main/CSX.exe` (jsdelivr) و`/onlyyoussef/csx-update/main/CSX.exe` (raw.githubusercontent)
- تحديث ذاتي: `CSX.exe.new`, `CSX.exe.old`, `csx_update.tag`, `Downloading v%hs...`, `Installing update...`
- منطق الحظر: `Banned`, `Banned (local)`, `Locally banned`, `No reason provided`, `.banned`, `\CSX\.banned`
- **`Server offline (fail-open)`** (00409875 / 00444420): عند تعذّر الوصول للخادم يُسمح بالعمل.

### 4.6 التهرّب من التحليل
- `IsDebuggerPresent` (00419959، وأيضاً 0042279d, 00428c34)، `CheckRemoteDebuggerPresent` (004199a5)
- اكتشاف بيئات افتراضية/مشاركة عبر `NetShareEnum` (0041a3ec) ومقارنة `\\VBOXSRV\` (00419dea)،
  `\\tsclient\` (00419dfe)، `\\vboxsrv\`, `\\tsclient\`, `IPC$`, `PRINT$`
- نسخ ذاتي/بحث عن `csxprobe.exe` في `Users\Public\`, `Windows\Temp\`, `ProgramData\`,
  `\\tsclient\c\Windows\Temp\`, `//tsclient/C/Users/Public/…` (`FUN_00419d20` و`FUN_0041b…`)
- رسالة ` failed (antivirus?)`

### 4.7 الواجهة
- GDI+ (54 استيراداً: `GdiplusStartup`, `GdipDrawString`, `GdipCreateLineBrush…`) + `CreateWindowExW`,
  `RegisterClassW`, خط `Segoe UI`, قائمة سياق (`CreatePopupMenu`) مع `Copy all log` / `Copy this line`,
  أزرار `I N J E C T` (00413159)، `R E S E T   S E R I A L`، `UPDATE  AVAILABLE`
- سجل نصي بمقاطع: `[ok]`, `[error]`, `[warn]`, `[info]`, `[agent]`, `[net]`, `[update]` + طوابع `HH:mm:ss`

### 4.8 الاستيرادات (272 مرجعاً مميزاً)

| الوحدة | العدد |
|---|---|
| KERNEL32.DLL | 128 |
| GDIPLUS.DLL | 54 |
| USER32.DLL | 46 |
| GDI32.DLL | 11 |
| ADVAPI32.DLL | 10 |
| WINHTTP.DLL | 9 |
| OLE32.DLL | 5 |
| SHELL32.DLL | 4 |
| OLEAUT32.DLL | 3 |
| NETAPI32.DLL | 2 |

---

## 5) مؤشرات (IOCs) للكشف

- أسماء ملفات: `CSX.exe`, `CSX.exe.new`, `CSX.exe.old`, `csxcheat.dll`, `agent.dll`, `csxprobe.exe`,
  `csx_update.tag`, `CSXcsxbugs.log`, `.banned`, `cache.dat`, `audio_cache.bin`, `dxdiag_cache.bin`
- مواقع (نصوص حرفية من `.rdata`): `ProgramData\csxprobe.exe`, `Users\Public\csxprobe.exe`,
  `Windows\Temp\csxprobe.exe`, `\\tsclient\c\Windows\Temp\csxpro…`, `//tsclient/C/Users/Public/csxpro…`
  (مسار مجلد `%ProgramData%\CSX` **مستنتج** من المقاطع المنفصلة `ProgramData\` + `\CSX` + `\CSX\.banned`
  وليس نصاً واحداً في البايتات)
- شبكة: `api.ipify.org`, `ip-api.com`, `raw.githubusercontent.com`, `cdn.jsdelivr.net`,
  `/api/heartbeat`, `/api/event`, UA `CSX/1.0`,
  `/gh/onlyyoussef/csx-update@main/CSX.exe`, `/onlyyoussef/csx-update/main/CSX.exe`
- سلوك: `CreateRemoteThread` + `WriteProcessMemory` على `gta_sa.exe` / `Multi Theft Auto.exe`؛
  قسم PE باسم `.mmap`؛ `SELECT SerialNumber FROM Win32_*` عبر WMI؛ حذف مفاتيح
  `SOFTWARE\Multi Theft Auto*\1.6` و`CredDeleteW`
- نصوص فريدة في البايتات: `XAgentReady`, `Local\CSXAgentReady-`, `Local\CSXClientLoaded-`,
  `DARKFLAME_AGENT_READY_EVENT`, `[ok] csxcheat.dll mapped before g`, `Server offline (fail-open)`

---

## 6) لماذا لا يحتوي هذا المستودع على "كود مصدري أصلي" مُعاد بناؤه

الطلب كان تحويل التفكيك إلى **الكود المصدري الأصلي القابل للبناء**. لم أنفّذ ذلك، والسبب تقني وأخلاقي
معاً:

1. **لا يمكن استعادة المصدر الأصلي من تفكيك.** الأسماء (`FUN_0040b520`)، أسماء المتغيرات، التعليقات،
   البنية الطبقية، والقوالب (templates) حُذفت عند الترجمة. أي "مصدر" يُنتَج هو *إعادة كتابة تخمينية*،
   وليس المصدر الأصلي — وهذا بالضبط ما ينص عليه `ARCHITECTURE.md` في هذا المستودع:
   *"لا ندّعي استعادة مصدر حرفي. لا نستخدم تخمين لغوي لتوليد كود."*
2. **العينة أداة غش.** `CSX.exe` يحقن `csxcheat.dll` في `gta_sa.exe` (لعبة جماعية عبر الإنترنت)،
   ويعيد ضبط `MTA serial` لتجاوز الحظر بالعتاد، ويتضمّن تهرّباً من الـ debugger وكشف البيئات الافتراضية.
   إنتاج نسخة عاملة منه = إنتاج أداة غش وتجاوز حظر تعمل فعلياً، وهذا ما لن أكتبه.

### ما هو متاح بدلاً من ذلك

- هذا التقرير: تحديد العينة، خريطة الدوال والسلوك بعناوينها، الاستيرادات، وIOCs للكشف والدفاع.
- تشغيل `revspec analyze CSX.exe --output ./runs` لإنتاج تقرير `report.md` / `report.json`
  القياسي (18 قسم) مع درجات الثقة `proven` / `inferred` / `unknown`.
- تفكيك دالة محدّدة بعينها لأغراض تحليلية (تتبّع مسار بيانات، تفسير استدعاء API) دون تجميع بديل عامل.

---

## 7) ملاحظة على `CSX_Full.cpp` الموجود في المستودع

`CSX_Full.cpp` (22,943 بايت) **ليس** إعادة بناء أمينة لنفس العينة:

- ترويسه يدّعي "272 دالة" و"50001 تعليمة"، بينما التفكيك الفعلي يحتوي **628 دالة معرّفة**
  و**127,261 سطر عنوان/تعليمات**.
- أجسام دواله هي تعليقات opcode + `// TODO: lift to C++ based on opcodes above`،
  ودواله المساعدة تعيد قيماً ثابتة (`decrypt_string` يعيد `"[decrypted]"`).
- `main()` فيه يطبع ملخصاً ولا ينفّذ أي سلوك حقيقي من العينة.

بمعنى آخر: هو هيكل توثيقي (skeleton) وليس مصدراً مطابقاً، وينبغي عدم الاعتماد عليه كمرجع لسلوك `CSX.exe`.
