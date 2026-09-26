#!/usr/bin/env python3
from __future__ import annotations
import argparse
import pathlib
import sys
import json

from .core.pipeline import Pipeline

DISCLAIMER = """
⚠️  تنبيه أخلاقي وقانوني:
هذا المشروع مخصص فقط لتحليل البرامج التي تملكها أو لديك تصريح كتابي بتحليلها.
المطورون غير مسؤولين عن أي استخدام غير قانوني.
"""

def print_disclaimer():
    print(DISCLAIMER, file=sys.stderr)

def cmd_analyze(args):
    print_disclaimer()
    sample = pathlib.Path(args.sample)
    out_base = pathlib.Path(args.output)
    opts = {
        "enable_dynamic": args.enable_dynamic,
        "dynamic_timeout": args.dynamic_timeout,
        "dynamic_args": args.dynamic_args,
        "analyzers": args.analyzers.split(",") if args.analyzers else None,
        "deep": args.deep,
    }
    pipeline = Pipeline(include_deep=args.deep)
    result = pipeline.run(sample, out_base, opts)

    # exports
    run_dir = result.host and pipeline  # placeholder
    # Find latest run dir: we stored in EvidenceStore; retrieve from pipeline run
    # We need to locate run_dir via output_base: the Pipeline created a subdir; we can find newest
    # Hack: search result store path via pipeline's last store? Instead, pipeline returns result but store path is not in result.
    # Let's find newest directory under out_base
    dirs = sorted([d for d in out_base.iterdir() if d.is_dir()], key=lambda p: p.stat().st_mtime, reverse=True)
    if dirs:
        run_dir = dirs[0]
    else:
        run_dir = out_base

    # Export JSON/YAML/MD
    from .export.json_export import export_json, export_yaml
    from .export.markdown_report import render_markdown
    import pathlib as pl
    template = pl.Path(__file__).parent.parent / "templates" / "report.md.j2"
    if not template.exists():
        # fallback to package templates
        template = pl.Path(__file__).parent / "templates" / "report.md.j2"
        if not template.exists():
            # create minimal inline
            pass

    json_path = run_dir / "report.json"
    yaml_path = run_dir / "report.yaml"
    md_path = run_dir / "report.md"

    export_json(result, json_path)
    try:
        export_yaml(result, yaml_path)
    except Exception as e:
        print(f"YAML export failed: {e}", file=sys.stderr)

    # Render markdown if template exists, else generate simple
    if template.exists():
        render_markdown(result.to_dict(), template, md_path)
    else:
        # fallback simple markdown
        md_path.write_text(f"# RevSpec Report\n\nSample: {result.sample.filename}\nSHA256: {result.sample.sha256}\n\nFindings: {len(result.findings)}\n", encoding="utf-8")

    print(f"✅ اكتمل التحليل")
    print(f"📁 Run dir: {run_dir}")
    print(f"📄 Markdown: {md_path}")
    print(f"📄 JSON: {json_path}")
    print(f"📄 YAML: {yaml_path}")
    # also copy to requested output if needed
    # Print summary
    print(json.dumps(result.summary, ensure_ascii=False, indent=2))

def cmd_list_analyzers(args):
    from .core.pipeline import default_analyzers
    for a in default_analyzers():
        print(f"{a.name:20} {a.description} (v{a.version})")


def cmd_serial_check(args):
    """
    يفحص سجلّ قراءات معرّفات ويقرر هل التغيّر شرعي أم تزوير.
    قراءة فقط — لا يعدّل أي معرّف.
    """
    from .protection import load_history, analyze_history

    readings = load_history(args.history)
    report = analyze_history(readings)

    if args.json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        return

    print(f"سجلّ القراءات: {args.history}")
    print(f"عدد القراءات : {report.readings}")
    print(f"عدد الانتقالات: {len(report.transitions)}")
    print()
    for t in report.transitions:
        print(f"  {t.from_session} → {t.to_session} : {t.verdict.value} "
              f"(ثقة {t.confidence:.2f})")
        if t.changed:
            print(f"      تغيّر قيمة فعلي : {', '.join(t.changed)}")
        if t.anchors_changed:
            print(f"      مراسي تغيّرت    : {', '.join(t.anchors_changed)}")
        if t.volatiles_changed:
            print(f"      طيّعة تغيّرت    : {', '.join(t.volatiles_changed)}")
        if t.reappeared_changed:
            print(f"      حُذفت ثم عادت   : {', '.join(t.reappeared_changed)}")
        if t.serial_changed:
            print("      client_serial تغيّر")
        for r in t.reasons:
            print(f"      - {r}")
        print()
    print(f"الحكم الأسوأ : {report.worst_verdict.value} "
          f"(ثقة {report.worst_confidence:.2f})")
    print(f"الإجراء المقترح: {report.action}")
    print()
    print("ملاحظة: هذا حكم على نمط التغيّر، لا تنفيذ. "
          "عدّل _action_for() في revspec/protection/serial_consistency.py "
          "لملاءمة سياسة الحظر عندك.")

def _preprocess_dynamic_args(argv):
    """Allow --dynamic-args value starting with '-' (e.g. --debug) without requiring =.
    We manually extract '--dynamic-args <value>' before argparse sees it."""
    out = []
    dynamic_val = None
    i = 0
    while i < len(argv):
        if argv[i] == "--dynamic-args" and i + 1 < len(argv):
            # capture next token even if it starts with -
            dynamic_val = argv[i+1]
            i += 2
            continue
        if argv[i].startswith("--dynamic-args="):
            dynamic_val = argv[i].split("=",1)[1]
            i += 1
            continue
        out.append(argv[i])
        i += 1
    return out, dynamic_val

def main():
    # Pre-process to allow --dynamic-args --debug
    raw_argv = sys.argv[1:]
    cleaned_argv, dynamic_val = _preprocess_dynamic_args(raw_argv)

    parser = argparse.ArgumentParser(prog="revspec", description="RevSpec — منصة هندسة عكسية معيارية (للبرامج المملوكة فقط)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_an = sub.add_parser("analyze", help="تحليل عينة")
    p_an.add_argument("sample", help="مسار الملف التنفيذي/العينة")
    p_an.add_argument("-o","--output", default="./runs", help="مجلد الإخراج (default ./runs)")
    p_an.add_argument("--enable-dynamic", action="store_true", help="تفعيل التحليل الديناميكي (معزول)")
    p_an.add_argument("--dynamic-timeout", type=int, default=8, help="مهلة الديناميكي بالثواني")
    p_an.add_argument("--dynamic-args", default="", help="وسائط تُمرر للعينة عند التشغيل الديناميكي (استخدم --dynamic-args=\"--debug\" إذا كانت الوسائط تبدأ بـ -)")
    p_an.add_argument("--analyzers", default=None, help="قائمة محللات مفصولة بفواصل (افتراضي الكل)")
    p_an.add_argument("--deep", action="store_true", help="تفكيك عميق — opcodes كاملة (jump/push/mov) + CFG + skeleton C++ لإعادة البناء")
    p_an.set_defaults(func=cmd_analyze)

    # deep standalone
    p_deep = sub.add_parser("deep", help="تفكيك عميق فقط — opcodes")
    p_deep.add_argument("sample", help="مسار البرنامج")
    p_deep.add_argument("-o","--output", default="./runs", help="مجلد الإخراج")
    p_deep.set_defaults(func=lambda args: cmd_analyze(argparse.Namespace(sample=args.sample, output=args.output, enable_dynamic=False, dynamic_timeout=8, dynamic_args="", analyzers=None, deep=True)))

    p_ls = sub.add_parser("list-analyzers", help="عرض المحللات المتاحة")
    p_ls.set_defaults(func=cmd_list_analyzers)

    p_sc = sub.add_parser("serial-check",
                          help="فحص سجلّ قراءات المعرّفات: تغيّر شرعي أم تزوير (قراءة فقط)")
    p_sc.add_argument("history", help="ملف JSON يحتوي سجلّ القراءات")
    p_sc.add_argument("--json", action="store_true", help="إخراج JSON بدل نص مقروء")
    p_sc.set_defaults(func=cmd_serial_check)

    p_ver = sub.add_parser("version", help="الإصدار")
    p_ver.set_defaults(func=lambda a: print("RevSpec 1.0.0"))

    # patch command
    try:
        from .patcher.cli_patch import add_patch_parser
        add_patch_parser(sub)
    except Exception as e:
        pass

    args = parser.parse_args(cleaned_argv)
    # inject dynamic_val if we captured it
    if hasattr(args, "dynamic_args") and dynamic_val is not None:
        args.dynamic_args = dynamic_val
    args.func(args)

if __name__ == "__main__":
    main()
