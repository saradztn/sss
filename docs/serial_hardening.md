# تقسية معرّف العميل (Serial Hardening) — دليل جهة الحماية

> **نطاق هذا الملف:** ما بُني لمساعدتك على **اختبار وتقوية** الحماية عندك.
> لا يحتوي هذا المستودع على أداة تغيير serial ولا على loader عامل، ولن يُبنى فيه.

---

## 1) ما طُلب وما بُني

طُلبت أداة C++ تغيّر معرّف MTA (serial) "لاختبار آخر نقطة حماية". لم تُبنَ، لأن
أداة تغيير المعرّف هي بحكم تعريفها أداة تجاوز حظر: تعمل identically سواء كان من
يشغّلها مطوّر الحماية أو لاعب محظور، ولا يمكن تقييدها بمن يشغّلها.

بدل ذلك بُني ما يخدم نفس الهدف من الجهة الصحيحة:

| المكوّن | المسار | ماذا يفعل |
|---|---|---|
| كاشف ثابت | `revspec/analyzers/serial_spoof.py` | يفحص أي ملف ثنائي ويحكم هل فيه **قدرة** تغيير معرّف + حقن |
| منطق الحماية | `revspec/protection/serial_consistency.py` | من سجلّ قراءات: هل تغيّر الـ serial شرعي أم تزوير؟ |
| مِجَس + جرد (**ملف واحد**) | `tools/serial_change_probe.cpp` | **قراءة فقط**: الـ serial الحالي + جرد المدخلات مع قابلية التزوير + هل كان التغيير سينجح (فحص صلاحيات) |
| قواعد YARA | `rules/serial_spoof.yar` | نفس المؤشرات بصيغة قواعد مسح جماعي |
| اختبارات | `tests/test_serial_spoof.py` + `test_serial_consistency.py` + `test_tools_build.py` + `tools/test_serial_change_probe.cpp` | 45 اختبار pytest + 53 اختبار C++ |
| تقرير العينة | `docs/client_lua_analysis.md` | المؤشرات التي بُنيت منها القواعد |

---

## 2) التشغيل

```bash
pip install -e .

# أ) افحص أي ملف ثنائي
revspec analyze <binary> -o ./runs
# الحكم في: runs/<run>/report.md  → قسم "حكم كشف قدرة تغيير المعرّف"
#            runs/<run>/evidence/serial_spoof/raw.json

# ب) الاختبارات
pytest tests/test_serial_spoof.py -v

# ج) قواعد YARA (تتطلب yara مثبّتاً)
yara -r rules/serial_spoof.yar /path/to/samples

# د) المِجَس — ملف واحد يشغّل كل شيء (قراءة فقط)
#    Linux
make -C tools && ./tools/serial_change_probe
#    Windows (MSVC) — أمر واحد، ملف واحد
cl /O2 /EHsc /W4 tools\serial_change_probe.cpp advapi32.lib ole32.lib ^
   oleaut32.lib wbemuuid.lib iphlpapi.lib /Fe:serial_change_probe.exe
#    Windows (MinGW من Linux)
x86_64-w64-mingw32-g++ -O2 -std=c++17 -Wall -Wextra tools/serial_change_probe.cpp ^
   -o serial_change_probe.exe -static -ladvapi32 -lole32 -loleaut32 -lwbemuuid -liphlpapi
```

---

## 3) نتائج التحقق الفعلية

| العينة | serial_score | injection_score | الحكم |
|---|---|---|---|
| `CSX.exe` (العينة المرجعية) | **160** | 30 | `capable-serial-change` |
| `samples/demo_app` (مصرّف gcc) | 0 | 0 | `no-serial-change-indicator` (provenance = `absent`) |

ما رصده الكاشف في `CSX.exe` (من `evidence/serial_spoof/raw.json`):

```
serial_inputs : MachineGuid, SOFTWARE\Microsoft\Cryptography,
                SELECT SerialNumber FROM Win32_, Win32_BIOS, Win32_DiskDrive,
                Win32_BaseBoard, ROOT\CIMV2, SSO_RND_Device
mutation_apis : RegDeleteKeyA, RegSetValueExA, CredDeleteW
intent_strings: Resetting MTA serial, Serial reset complete,
                R E S E T   S E R I A L, Reset your Mta Serial
game_registry : SOFTWARE\WOW6432Node\Multi Theft Auto
injection_apis: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
evasion       : IsDebuggerPresent, CheckRemoteDebuggerPresent,
                NtQueryInformationProcess, \\vboxsrv\, \\tsclient\, NetShareEnum
sections      : قسم تنفيذي .mmap يبدأ بـ 55 8b ec 83 ec 58 … (stub مُحمِّل PE)
```

> ملاحظة تشغيلية: الكاشف يعتمد على استخراج نصوص ASCII + UTF-16LE **بدون تكرار**.
> الصيغة الأولى كانت تقتطع عند 400 ألف حرف فتُسقِط كل نصوص `.rdata` المشفّرة بـ
> UTF-16 (النتيجة كانت `serial_score=36` على عينة فيها نصوص نيّة صريحة). الاختبار
> الموجب على `CSX.exe` هو الذي كشف هذا، وأُصلح بـ dedup + حد 1.5 مليون حرف.

### منطق الحكم

```
serial_score = قراءة معرّفات + APIs تعديل/حذف + نصوص نيّة + مفاتيح سجل اللعبة
               (إذا كانت هناك قراءة فقط بلا تعديل ولا نيّة → يُسقف عند 29)

≥ 55  → capable-serial-change      (high)
≥ 30  → suspected-serial-change    (medium)
< 30  → no-serial-change-indicator (high, provenance=absent)
```

---

## 4) التقسية: لماذا الـ serial القائم على العتاد ضعيف

القسم 2 من مخرجات `tools/serial_change_probe.cpp` يقيس هذا مباشرة. القاعدة المركزية:

> **أي مدخل يستطيع المهاجم ضبطه من وضع المستخدم يضيف صفراً من الأمان للـ serial،
> مهما كانت إنتروبيه.**

| المدخل | بت اسمية | بت فعّالة | لماذا |
|---|---|---|---|
| `MachineGuid` | 64 | **0** | قيمة سجل؛ تُكتب وتُعاد بأداة سجل عادية |
| `Win32_BIOS.SerialNumber` | 24 | **0** | يُقرأ عبر WMI؛ اعتراض المزوّد أو تعديل SMBIOS يعيده |
| `Win32_BaseBoard.SerialNumber` | 20 | **0** | نفس مسار WMI |
| `Win32_DiskDrive.SerialNumber` | 32 | **0** | يمر عبر `IOCTL_STORAGE_QUERY_PROPERTY` — قابل للاعتراض |
| `GetVolumeInformation` | 32 | **0** | يتغيّر بإعادة تهيئة القسم |
| MAC | 48 | **0** | MAC spoofing مدمج في إعدادات كرت الشبكة |
| `GetComputerName` | 15 | **0** | يغيّره المستخدم من الإعدادات |
| `GetUserName` | 14 | **0** | حساب جديد = قيمة جديدة |

على جهاز الاختبار هنا: إنتروبي اسمي 127 بت → **إنتروبي فعّال 0.0 بت**، التقدير `F`.
هذه هي بالضبط الفجوة التي يستغلها `CSX.exe`.

### ما يصمد فعلاً

1. **معرّف يوقّعه الخادم** لا يُشتق محلياً. العميل يطلب، الخادم يوقّع، والخادم هو
   من يقرر الربط. لا يوجد شيء محلي ليعيد المهاجم توليده.
2. **ربط الهوية بحساب** (مصادقة) لا بقيمة عتاد. الحظر يقع على الحساب + سلسلة
   معرّفات مرتبطة به، لا على رقم واحد.
3. **كشف عدم الاتساق بدل منع التغيّر.** راقب تغيّر المدخلات بين الجلسات:
   - `MachineGuid` تغيّر + MAC/القرص ثابتان → بصمة تزوير، لا إعادة تثبيت.
   - كل المدخلات تغيّرت دفعة واحدة في نفس اللحظة → إعادة تهيئة/جهاز جديد (مقبول).
   - `SSO_RND_Device` اختفى ثم ظهر بقيمة جديدة → محاولة إعادة ضبط متعمّدة.
4. **تحقّق من سلامة القراءة نفسها:** اقرأ المعرّفات من أكثر من مسار (WMI + IOCTL
   مباشر + سجل) وقارن. اختلافها = اعتراض في أحدها.
5. **احمِ قيمتك المخزّنة:** أي serial مخزّن في السجل أو في ملف قابل للكتابة من
   وضع المستخدم يجب أن يكون موقّعاً (HMAC بمفتاح خادم) — وإلا فحذفه يعيد التوليد.
   `CSX.exe` يستخدم `RegDeleteKeyA` + `CredDeleteW` لهذا السبب تحديداً.
6. **لا تعتمد على `fail-open`.** العينة تحتوي `Server offline (fail-open)`: عند
   تعذّر الوصول للخادم يُسمح بالعمل. أي حظر يُتحقق منه على العميل فقط يتجاوز بإسقاط
   الشبكة.

---

## 5) كيف تختبر الحماية دون أداة تزوير

بُني لهذا الغرض `revspec/protection/serial_consistency.py`: يأخذ **سجلّ قراءات**
ويقرر هل التغيّر شرعي أم تزوير. لا يوجد فيه أي قدرة تعديل — مدخله JSON ومخرجه حكم.

```bash
revspec serial-check examples/serial_history_csx_pattern.json   # -> block
revspec serial-check examples/serial_history_reinstall.json     # -> require-reauth
revspec serial-check <history.json> --json                      # إخراج آلي
```

### المِجَس — `tools/serial_change_probe.cpp` (ملف واحد يشغّل كل شيء)

ملف مصدري واحد بلا اعتماديات على ملفات أخرى في المستودع. يعرض الـ serial
الحالي **في أول المخرجات**، ثم يكمل كل شيء آخر، دون تغيير أي شيء:

```
>>> CURRENT SERIAL <<<
    <القيمة>                     ← يُطبع أولاً
    source : <المفتاح والقيمة>

1. Identifier inventory     ← المعرّفات + قابلية تزوير كل مدخل
2. Entropy assessment       ← الإنتروبي الاسمي مقابل الفعّال + التقدير
3. MTA target keys          ← صلاحيات READ / WRITE / DELETE لكل مفتاح
4. Verdict                  ← سينجح / محجوب / تعذّر التحديد
5. Hardening                ← توصيات محددة
```

```bash
make -C tools && ./tools/serial_change_probe
./tools/serial_change_probe --show-values     # قيم غير مقنّعة
# exit 0 = سينجح | 2 = محجوب | 3 = تعذّر التحديد
```

الطريقة: يقرأ نفس سطح المعرّفات الذي يلمسه CSX، ويقرأ مفاتيح MTA الستة
(المسارات مأخوذة حرفياً من `.rdata` عند `0x00443340..0x00443610`)، ثم يفحص
**صلاحيات** كل مفتاح. فحص الصلاحية فتحٌ بـ `KEY_SET_VALUE` — وهو تحقّق وصول،
لا كتابة.

```
RegSetValueEx*  RegDeleteKey*  RegDeleteValue*  CredDelete*
WriteProcessMemory  CreateRemoteThread  VirtualAllocEx  QueueUserAPC
→ لا يُستدعى أيٌّ منها. اختبار pytest يجرّد التعليقات والسلاسل النصية من
  المصدر ويتحقق من ذلك برمجياً.
```

مخرجه يوجّه التقسية مباشرة: إن كان الحكم "سينجح"، فالمطلوب منع
الكتابة/الحذف على تلك المفاتيح لغير المدير، وتوقيع ما يُخزَّن فيها حتى لا
يولّد حذفها serial جديداً بصمت.

> **حالة البناء:** تُرجم واختُبر بمسار Linux (المنطق المشترك + مجسّ الصلاحيات
> عبر `access(2)`). مسار Win32/WMI **لم يُترجم في بيئة التطوير** لعدم توفّر
> MSVC أو MinGW — أوامر البناء في رأس الملف وفي `tools/Makefile`.

### القاعدة المركزية: المراسي مقابل الطيّع

| التصنيف | أمثلة | لماذا |
|---|---|---|
| **ANCHOR** | `bios_serial`, `board_serial`, `disk_serial`, `mac_address`, `install_date` | لا تتغيّر إلا بعتاد جديد أو إعادة تثبيت فعلية |
| **VOLATILE** | `machine_guid`, `volume_serial`, `product_id`, `computer_name`, `user_name` | تُكتب من وضع المستخدم بلا أثر جانبي |
| **MARKER** | `sso_rnd_device`, `mta_serial`, `mta_owner` | يولّدها البرنامج نفسه — فحذفها ثم إعادة توليدها = إعادة ضبط متعمّدة |

أي معرّف غير مُدرَج يُعامل كـ `VOLATILE` (الأسوأ افتراضاً)، لا كمرساة.

### الأحكام

| الحكم | الشرط | الثقة | الإجراء الافتراضي |
|---|---|---|---|
| `derivation-tamper` | الـ serial تغيّر ولا معرّف تغيّر | 0.95 | `block` |
| `spoof-reset` | علامة اختفت ثم عادت بقيمة جديدة | 0.90 | `block` |
| `spoof-partial` | الطيّع تغيّر وكل المراسي ثابتة | 0.85 | `require-reauth` |
| `hardware-change` | مرساة تغيّرت فعلاً | 0.50 | `require-reauth` |
| `legit-change` | ≥80% من المعرّفات تغيّرت معاً | 0.60 | `allow-with-note` |
| `consistent` | لا تغيّر | 0.90 | `allow` |

### المفتاح الفارق بين إعادة التثبيت الشرعية وأداة التزوير

إعادة تثبيت Windows تغيّر `machine_guid` و`volume_serial` و`install_date`
وتعيد توليد `sso_rnd_device` — أي **نفس** ما تفعله أداة التزوير تقريباً. الفارق
الوحيد الموثوق: **`install_date`**. أداة التزوير لا تعيد تثبيت النظام فلا تغيّره.
لذلك `install_date` مصنّف `ANCHOR`: تغيّره يمنع حكم `spoof-partial` ويحوّله إلى
`hardware-change` (يتطلب إعادة مصادقة، لا حظراً).

نتيجة فعلية على المثالين في المستودع:

```
examples/serial_history_csx_pattern.json → spoof-reset  (0.90) → block
examples/serial_history_reinstall.json   → hardware-change (0.50) → require-reauth
```

### تفاصيل منطقية ثبتت بالاختبار

- **ظهور معرّف بعد غياب ≠ تغيّر.** فشل قراءة `bios_serial` في جلسة ثم نجاحها في
  التالية ليس "تغيير عتاد" — لا توجد قيمة قديمة للمقارنة. الصيغة الأولى كانت
  تخطئ هنا (تُصدر `hardware-change`) وأصلحها الاختبار.
- **أول توليد لعلامة ≠ إعادة ضبط.** `sso_rnd_device` يظهر لأول مرة بشكل طبيعي.
- **اختفاء علامة وحده يُسجَّل كملاحظة لا كحظر** — النصف الأول من النمط فقط؛
  الحكم القاطع يحتاج رؤية إعادة التوليد في الجلسة التالية.
- **`derivation-tamper` يستثني حالة `reappeared`**: هناك تغيّر serial مُفسَّر
  بإعادة ضبط المدخلات، فيُترك لحكم `spoof-reset` الأدق.

### الاختبار

```bash
pytest tests/test_serial_consistency.py -v     # 19 اختباراً
pytest -q                                      # 40 اختباراً إجمالاً
```

كل الحالات سجلّات مُصنَّعة، بما فيها النمط الكامل الذي يتركه CSX. لا يوجد تزوير
حقيقي في أي اختبار — وهذا هو المقصود: منطق الكشف يُختبر بمدخلات، لا بأدوات.

### بقية الطرق

1. **افحص الثنائي لا السلوك:** `revspec analyze <file>` — المحلل `serial_spoof`
   يعطي الحكم `capable-serial-change` دون تشغيل أي شيء.
2. **الاختبار الطرفي:** جهاز وهمي تتحكم به بالكامل، شغّل
   `serial_change_probe` قبل وبعد أي تغيير تجريبي، وقارن القيم. لا تنشر أداة
   تزوير ولا توزّعها.
3. **راجع `client.lua` / `CSX.exe` كمرجع مؤشرات:** كل عنوان في
   `docs/client_lua_analysis.md` يمكن تحويله إلى قاعدة كشف.

---

## 6) إضافة مؤشر جديد للكاشف

عدّل القوائم في `revspec/analyzers/serial_spoof.py`:

```python
SERIAL_INPUT_INDICATORS.append((r"YourNewIdentifier", 6, "وصف"))
```

ثم أضف حالة في `tests/test_serial_spoof.py` وشغّل `pytest tests/test_serial_spoof.py`.
الأوزان معايرة بحيث: نيّة صريحة ≥ 18، قراءة معرّف 4–10، API تعديل/حذف 3–10.
