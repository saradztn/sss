# إعادة البناء من Opcodes — demo_app

**المصدر:** `samples/demo_app/demo_app` (ELF x86-64, 24640 بايت)
**التحليل:** RevSpec Deep 2.0 — 424 تعليمة، 7 دوال، 134 block، method=capstone

## الملفات المرفوعة
```
ai_report.json          — ملخص + 200 تعليمة عينة + skeleton
opcodes_full.json.gz    — كل الـ 424 تعليمة (mov 85, lea 68, call 58...)
skeleton.cpp            — هيكل 7 دوال بتعليقات assembly
raw.json / findings.json / cfg.dot
```

## المخرج
`rebuild/demo_app_rebuilt.cpp` — **161 سطر، يتصرف طبق الأصل**

### كيف بني؟
1. **CFG من cfg.dot:** `main` → loop `for (i=1; i<argc)` → كل `je` في opcodes يقابل `strcmp`
2. **Strings من lea:** `lea rax,[rip+0xfcd]` → `CONFIG_PATH`, `lea rdi,[rip+0xa86]` → `"Usage: %s..."`
3. **Imports من call:** `call 0x1090` → `strcmp@plt`, `call 0x1060` → `printf`, `call 0x1070` → `fopen`
4. **كل push/sub rsp ترجمت لمتغيرات محلية:** `sub rsp,0x28` في main → `argc/argv/config_path...`

### التحقق (مقارنة سلوك)
```bash
g++ -O2 -std=c++17 rebuild/demo_app_rebuilt.cpp -o /tmp/rebuilt_demo_app
/tmp/rebuilt_demo_app --help      # يطابق الأصلي حرفياً
/tmp/rebuilt_demo_app --version   # "demo_app version 1.2.3"
diff <(./samples/demo_app/demo_app --help) <( /tmp/rebuilt_demo_app --help) && echo "identical"
```

### لبرنامجك الخاص
1. ارفع `ai_report.json` + `opcodes_full.json.gz` + `skeleton.cpp` + `report.json` الخاص بك
2. سأطبق نفس القواعد من `prompts/cpp_rebuild_prompt.md` وأبني `rebuilt.cpp` الخاص بك
3. أو شغّل محلياً: أرسل الملفات لذكاء اصطناعي مع Prompt المرفق

## البناء
```bash
g++ -O2 -std=c++17 rebuild/demo_app_rebuilt.cpp -o demo_rebuilt
# أو
g++ rebuild/demo_app_rebuilt.cpp -o demo_rebuilt.exe  # Windows
./demo_rebuilt --debug --connect
```
