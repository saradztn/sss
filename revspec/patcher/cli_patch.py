"""
CLI for patcher — revspec patch
"""
import pathlib
import argparse
import json
import sys

def cmd_patch(args):
    from .string_patcher import BinaryPatcher
    from .pe_patcher import PEPatcher

    inp = pathlib.Path(args.input)
    if not inp.exists():
        print(f"الملف غير موجود: {inp}", file=sys.stderr)
        sys.exit(1)

    patcher = BinaryPatcher(inp)
    pe = PEPatcher(inp)

    print(f"📄 الملف: {inp} ({len(patcher.data)} بايت)")
    print(f"🔍 وجد {len(patcher.strings)} نص")
    if pe.is_pe_file():
        print(f"📦 PE: {pe.get_pe_info()}")
        if pe.get_version_info():
            print("🏷️ VersionInfo:")
            for k,v in pe.get_version_info().items():
                print(f"  {k}: {v}")

    # تنفيذ التعديلات
    count = 0
    if args.replace:
        for item in args.replace:
            # صيغة old:new
            if ":" not in item:
                print(f"صيغة خاطئة {item} — استخدم old:new", file=sys.stderr)
                continue
            old, new = item.split(":", 1)
            results = patcher.batch_rename(old, new)
            for off, msg in results:
                print(f"  {hex(off)} {msg}")
                if "✅" in msg:
                    count += 1

    if args.string:
        for item in args.string:
            # صيغة offset:new_text أو old_text:new_text
            # نبسط: نبحث عن old_text
            if ":" not in item:
                print(f"صيغة خاطئة {item}", file=sys.stderr)
                continue
            old, new = item.split(":", 1)
            # ابحث عن string يطابق old
            found = [s for s in patcher.strings if s.original == old]
            if not found:
                # حاول البحث الجزئي
                found = [s for s in patcher.strings if old in s.original]
                if not found:
                    print(f"لم يوجد نص '{old}'")
                    continue
            for entry in found:
                ok, msg = patcher.patch_string(entry.offset, new)
                print(f"  {hex(entry.offset)} {msg}")
                if ok:
                    count += 1

    if args.set_version:
        for item in args.set_version:
            if "=" not in item:
                print(f"صيغة خاطئة {item} استخدم Key=Value", file=sys.stderr)
                continue
            k,v = item.split("=",1)
            ok = pe.patch_version_string(patcher, k, v)
            print(f"  Version {k}={'✅' if ok else '❌'} {v}")
            if ok:
                count += 1

    if count == 0:
        print("⚠️ لم يتم أي تعديل (تحقق من الأطوال — النص الجديد يجب أن يكون بنفس الطول أو أقصر)")
        # اقترح عرض النصوص
        if args.list:
            for s in patcher.get_strings()[:50]:
                print(f"  {hex(s.offset)} [{s.encoding}] {s.original[:60]}")
        sys.exit(0)

    # حفظ
    out = pathlib.Path(args.output) if args.output else inp.with_name(inp.stem + "_patched" + inp.suffix)
    patcher.save(out)
    print(f"✅ تم الحفظ: {out} ({count} تعديل)")
    if args.report:
        rep = pathlib.Path(args.report)
        patcher.save_report(rep)
        print(f"📄 تقرير: {rep}")
    # عرض diff
    for d in patcher.get_diff()[:10]:
        print(f"  {d['offset']}: {d['old_text']} → {d['new_text']}")

def add_patch_parser(sub):
    p = sub.add_parser("patch", help="تعديل النصوص والموارد في البرنامج (مثل Ghidra patcher)")
    p.add_argument("input", help="مسار البرنامج الأصلي")
    p.add_argument("-o", "--output", help="مسار البرنامج المعدّل (افتراضي: *_patched.exe)")
    p.add_argument("--replace", action="append", default=[], help="استبدال شامل old:new (يمكن تكرارها)")
    p.add_argument("--string", action="append", default=[], help="تعديل نص محدد old:new")
    p.add_argument("--set-version", action="append", default=[], help="تعديل VersionInfo Key=Value (مثل ProductName=MyApp)")
    p.add_argument("--list", action="store_true", help="عرض النصوص إذا لم يتم تعديل")
    p.add_argument("--report", help="حفظ تقرير JSON")
    p.set_defaults(func=cmd_patch)
