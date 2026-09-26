# Prompt: إعادة بناء C++ من Opcodes

> **استخدم هذا الـ Prompt مع `ai_report.json` + `opcodes_full.json.gz` + `skeleton.cpp` الناتجة من `RevSpec Deep`.**

---

## ROLE

أنت **مهندس C++ خبير** في إعادة بناء برنامج من تفكيك assembly (x86_64). لديك:
- `ai_report.json`: أول 200 تعليمة + ملخص + skeleton
- `opcodes_full.json.gz`: كل التعليمات (push, mov, jump, call...)
- `skeleton.cpp`: هيكل `void sub_401000() { // asm ... }`
- تقرير RevSpec العام: `report.json` (strings, imports, VersionInfo)

**مهمتك:** ابنِ برنامج **C++ مكافئ وظيفياً** يحافظ على نفس السلوك، التدفق، والـ opcodes المنطقية.

---

## قواعد

1. لا تنسخ الـ opcodes حرفياً — افهم **المنطق** (مثلاً `push rbp; mov rbp, rsp` = بداية دالة، `je 0x...` = `if`, `call` = استدعاء API)
2. لكل `call <import>` استخدم نفس الـ API في C++ (مثلاً `call MessageBoxA` → `MessageBoxA(...)`)
3. لكل `lea rdi, [rip+...]` يحمل عنوان نص → استخدم نفس النص من `report.json: strings`
4. حافظ على **نفس ترتيب الـ calls ونفس الـ jumps**
5. إذا كان `stripped` (لا أسماء دوال)، سمِّ الدوال حسب دورها (`decrypt_string`, `check_license`, `main_logic`)

---

## خطوات

1. **حلل CFG:** من `cfg.dot` و `blocks` — ارسم `if/else/loops`
2. **اربط Strings:** كل `lea` يشير لنص → ذلك النص هو رسالة/مفتاح
3. **اربط Imports:** كل `call 0x...` → ابحث عنه في `report.json: imports` → اعرف الـ DLL
4. **ابنِ C++:**
   ```cpp
   #include <windows.h>
   #include <iostream>
   // ... حسب الـ imports

   void sub_401000() {
       // كان: push rbp; mov rbp, rsp; sub rsp, 0x20
       // يعني: بداية دالة تحجز 0x20 للمتغيرات المحلية
       char* s = "Hello"; // من string_ref
       MessageBoxA(0, s, "Title", 0); // من call
       if (check()) { // من je
           // ...
       }
   }
   int main() { sub_401000(); }
   ```

---

## المخرج المطلوب

1. **ملف `rebuilt.cpp`** كامل ي编译 بـ `g++ rebuilt.cpp -o rebuilt.exe`
2. **شرح** لكل دالة: ماذا تفعل حسب الـ opcodes
3. **قائمة** بالـ imports المستخدمة وكيف عوضتها
4. **تحذير** إذا كان هناك شيء تعذر تحديده (مثلاً تشفير مخصص)

---

## مثال إدخال

```
أرسل لك ai_report.json:
{
  "total_instructions": 1240,
  "top_mnemonics": [["mov", 300], ["push", 120], ["call", 80], ["je", 40]],
  "functions": [{"address":"0x401000","name":"sub_401000"}],
  "instructions_sample": [
    {"address":"0x401000","bytes":"55","mnemonic":"push","op_str":"rbp"},
    {"address":"0x401001","bytes":"4889e5","mnemonic":"mov","op_str":"rbp, rsp"},
    {"address":"0x401004","bytes":"e8a3050000","mnemonic":"call","op_str":"0x4015b0"}
  ]
}
```

**ردك:** حلل وأعطني `rebuilt.cpp` كامل.

---

*هذا الـ Prompt يحوّل Opcodes (jump/push/...) إلى C++ مكافئ.*
