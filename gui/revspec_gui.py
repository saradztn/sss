#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RevSpec GUI — واجهة رسومية بسيطة لـ Windows
اختار مسار البرنامج وهو يفعل الباقي.

يعمل بـ Tkinter (مدمج مع Python) — لا يحتاج تثبيت إضافي.
دبل كليك على RevSpec_GUI.bat أو شغّل:
    python gui/revspec_gui.py
    أو
    python -m gui.revspec_gui
"""
import sys
import os
import pathlib
import threading
import queue
import webbrowser
import json
import traceback

# === طلب تشغيل كمسؤول تلقائياً (Windows) ===
def _ensure_admin_and_exit_if_not():
    if sys.platform != "win32":
        return
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if not is_admin:
            params = " ".join([f'"{a}"' for a in sys.argv])
            ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
            if ret > 32:
                sys.exit(0)
            else:
                print("تم إلغاء التشغيل كمسؤول.")
                sys.exit(0)
    except SystemExit:
        raise
    except Exception as e:
        print(f"تحقق المسؤول فشل: {e}")
        pass

_ensure_admin_and_exit_if_not()
# === نهاية طلب المسؤول ===

# إصلاح الـ import عند التشغيل المباشر
ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    TK_AVAILABLE = True
except ImportError:
    tk = None
    ttk = None
    filedialog = None
    messagebox = None
    TK_AVAILABLE = False

# محاولة استيراد RevSpec
try:
    from revspec.core.pipeline import Pipeline
    from revspec.export.json_export import export_json, export_yaml
    from revspec.export.markdown_report import render_markdown
    REVSPEC_AVAILABLE = True
except Exception as e:
    REVSPEC_AVAILABLE = False
    IMPORT_ERROR = e

APP_TITLE = "RevSpec — هندسة عكسية (للبرامج التي تملكها فقط)"
APP_VERSION = "1.0.0"

class RevSpecGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_TITLE} v{APP_VERSION}")
        self.root.geometry("860x680")
        self.root.minsize(800, 620)
        # أيقونة إن وجدت
        try:
            self.root.iconbitmap(default="")
        except:
            pass

        self.sample_path = tk.StringVar()
        self.output_path = tk.StringVar(value=str(ROOT / "runs"))
        self.enable_dynamic = tk.BooleanVar(value=False)
        self.dynamic_args = tk.StringVar(value="")
        self.deep_var = tk.BooleanVar(value=False)
        self.status_text = tk.StringVar(value="جاهز — اختر برنامجك")

        self.last_run_dir = None
        self.is_running = False

        self._build_ui()
        self._check_revspec()

    def _check_revspec(self):
        if not REVSPEC_AVAILABLE:
            messagebox.showerror("خطأ", f"فشل تحميل RevSpec:\n{IMPORT_ERROR}\n\nتأكد من تثبيت المشروع:\npip install -e .")
            self.status_text.set("خطأ في التثبيت")

    def _build_ui(self):
        # Style
        style = ttk.Style()
        try:
            style.theme_use("vista")  # Windows native
        except:
            try:
                style.theme_use("clam")
            except:
                pass

        # ===== أعلى: تحذير أخلاقي =====
        warn = ttk.Frame(self.root, padding=8)
        warn.pack(fill="x")
        lbl = ttk.Label(warn, text="⚠️ للاستخدام فقط على البرامج التي تملكها أو لديك تصريح بتحليلها", foreground="#b45309", font=("Segoe UI", 9, "bold"))
        lbl.pack()
        ttk.Separator(self.root).pack(fill="x", pady=2)

        # ===== اختيار البرنامج (كبير) =====
        main = ttk.Frame(self.root, padding=12)
        main.pack(fill="both", expand=True)

        # زر كبير لاختيار البرنامج
        big_frame = ttk.LabelFrame(main, text=" 1) اختر برنامجك ", padding=12)
        big_frame.pack(fill="x", pady=(0,10))

        ttk.Label(big_frame, text="مسار البرنامج (.exe, .dll, .py, .bin ...):", font=("Segoe UI", 9)).pack(anchor="w")
        row1 = ttk.Frame(big_frame)
        row1.pack(fill="x", pady=6)
        ent1 = ttk.Entry(row1, textvariable=self.sample_path, font=("Consolas", 10))
        ent1.pack(side="left", fill="x", expand=True, padx=(0,6))
        ttk.Button(row1, text="📁 استعراض...", command=self.browse_sample).pack(side="left")
        ttk.Button(row1, text="📂 سحب وإفلات؟", command=lambda: messagebox.showinfo("سحب وإفلات", "يمكنك سحب الملف وإفلاته على نافذة البرنامج (اسحب الملف إلى حقل المسار) أو استخدم زر استعراض.")).pack(side="left", padx=4)

        # زر ضخم
        btn_big = tk.Button(big_frame, text="🚀 اختر البرنامج وحلّل تلقائياً", font=("Segoe UI", 13, "bold"), bg="#2563eb", fg="white", activebackground="#1d4ed8", activeforeground="white", relief="flat", padx=20, pady=10, cursor="hand2", command=self.quick_analyze)
        btn_big.pack(fill="x", pady=(10,4))
        # hover
        def on_enter(e): btn_big.config(bg="#1d4ed8")
        def on_leave(e): btn_big.config(bg="#2563eb")
        btn_big.bind("<Enter>", on_enter)
        btn_big.bind("<Leave>", on_leave)

        ttk.Label(big_frame, text="سيُنشئ تقرير كامل (Markdown + JSON + YAML) في مجلد runs", foreground="#64748b", font=("Segoe UI", 8)).pack(anchor="w")

        # ===== إعدادات =====
        opts = ttk.LabelFrame(main, text=" 2) الإعدادات (اختياري) ", padding=12)
        opts.pack(fill="x", pady=(0,10))

        # output
        ttk.Label(opts, text="مجلد الإخراج:").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(opts, textvariable=self.output_path, width=50).grid(row=0, column=1, sticky="ew", padx=6, pady=4)
        ttk.Button(opts, text="📁", width=4, command=self.browse_output).grid(row=0, column=2, padx=2)

        # dynamic
        chk = ttk.Checkbutton(opts, text="تفعيل التحليل الديناميكي (يشغّل البرنامج معزولاً — للبرامج الموثوقة فقط)", variable=self.enable_dynamic, command=self.toggle_dynamic)
        chk.grid(row=1, column=0, columnspan=3, sticky="w", pady=4)

        ttk.Label(opts, text="وسائط الديناميكي:").grid(row=2, column=0, sticky="w", pady=4)
        self.dynamic_entry = ttk.Entry(opts, textvariable=self.dynamic_args, width=50)
        self.dynamic_entry.grid(row=2, column=1, sticky="ew", padx=6, pady=4)
        ttk.Label(opts, text='مثال: --help  أو  --debug').grid(row=2, column=2, sticky="w")
        self.dynamic_entry.config(state="disabled")

        # deep
        chk_deep = ttk.Checkbutton(opts, text="🔬 تفكيك عميق — Opcodes كاملة (jump/push/mov) + C++ skeleton لإعادة البناء (قوي جداً)", variable=self.deep_var)
        chk_deep.grid(row=3, column=0, columnspan=3, sticky="w", pady=4)
        ttk.Label(opts, text="      يولّد opcodes_full.json.gz + ai_report.json + skeleton.cpp — أرسلها للذكاء الاصطناعي ليبني C++", foreground="#64748b", font=("Segoe UI", 8)).grid(row=4, column=0, columnspan=3, sticky="w", padx=(20,0))

        # زر تحليل عادي
        row2 = ttk.Frame(opts)
        row2.grid(row=5, column=0, columnspan=3, sticky="ew", pady=(10,0))
        ttk.Button(row2, text="🔍 حلّل الآن (يدوي)", command=self.start_analyze).pack(side="left", padx=4)
        ttk.Button(row2, text="🧹 مسح", command=self.clear).pack(side="left", padx=4)
        ttk.Button(row2, text="✏️ محرر النصوص (مثل Ghidra)", command=self.open_patcher).pack(side="left", padx=8)
        ttk.Button(row2, text="📖 دليل Windows", command=self.open_windows_doc).pack(side="right", padx=4)

        opts.columnconfigure(1, weight=1)

        # ===== شغّل وراقب — المراقبة الحية =====
        mon = ttk.LabelFrame(main, text=" 3) شغّل وراقب (مراقبة حية) ", padding=12)
        mon.pack(fill="x", pady=(0,10))

        ttk.Label(mon, text="اختر البرنامج أعلاه ثم اضغط تشغيل — سيُشغّل البرنامج ويراقب كل ما يفعله ويحفظه في ملف", foreground="#64748b", font=("Segoe UI", 8)).pack(anchor="w", pady=(0,6))

        row_mon = ttk.Frame(mon)
        row_mon.pack(fill="x")

        self.monitor_args_var = tk.StringVar(value="")
        ttk.Label(row_mon, text="وسائط:").pack(side="left")
        ttk.Entry(row_mon, textvariable=self.monitor_args_var, width=30).pack(side="left", padx=6, fill="x", expand=True)
        ttk.Label(row_mon, text="مهلة (ث):").pack(side="left", padx=(8,2))
        self.monitor_timeout_var = tk.StringVar(value="10")
        ttk.Spinbox(row_mon, from_=3, to=60, textvariable=self.monitor_timeout_var, width=4).pack(side="left", padx=4)

        btn_mon = tk.Button(mon, text="▶️ شغّل وراقب واحفظ", font=("Segoe UI", 11, "bold"), bg="#0ea5e9", fg="white", activebackground="#0284c7", relief="flat", padx=16, pady=6, cursor="hand2", command=self.start_monitor)
        btn_mon.pack(fill="x", pady=(8,0))
        def on_enter_m(e): btn_mon.config(bg="#0284c7")
        def on_leave_m(e): btn_mon.config(bg="#0ea5e9")
        btn_mon.bind("<Enter>", on_enter_m)
        btn_mon.bind("<Leave>", on_leave_m)

        ttk.Label(mon, text="يحفظ: stdout/stderr + exit code + ملفات أنشأها + سجل كامل في runs/monitor_*/trace.json", foreground="#64748b", font=("Segoe UI", 7)).pack(anchor="w", pady=(4,0))

        # ===== التقدم والسجل =====
        prog_frame = ttk.LabelFrame(main, text=" 3) التقدم والسجل ", padding=8)
        prog_frame.pack(fill="both", expand=True)

        self.progress = ttk.Progressbar(prog_frame, mode="indeterminate")
        self.progress.pack(fill="x", pady=(0,6))

        self.log = tk.Text(prog_frame, height=12, font=("Consolas", 9), wrap="word", bg="#f8fafc", fg="#0f172a")
        self.log.pack(fill="both", expand=True, side="left")
        scroll = ttk.Scrollbar(prog_frame, command=self.log.yview)
        scroll.pack(side="right", fill="y")
        self.log.config(yscrollcommand=scroll.set)
        self.log_insert("مرحباً! اختر برنامجك ثم اضغط 'حلّل تلقائياً'.\n")
        self.log_insert("التقارير ستُحفظ في runs/<تاريخ>_<hash>/\n")

        # ===== شريط الحالة + أزرار النتائج =====
        bottom = ttk.Frame(self.root, padding=8)
        bottom.pack(fill="x")
        ttk.Label(bottom, textvariable=self.status_text, foreground="#334155", font=("Segoe UI", 9)).pack(side="left")

        self.btn_deep = ttk.Button(bottom, text="🔬 Opcodes", command=self.open_deep, state="disabled")
        self.btn_deep.pack(side="right", padx=4)
        self.btn_open_folder = ttk.Button(bottom, text="📂 فتح مجلد النتائج", command=self.open_last_run, state="disabled")
        self.btn_open_folder.pack(side="right", padx=4)
        self.btn_open_report = ttk.Button(bottom, text="📄 فتح التقرير", command=self.open_report, state="disabled")
        self.btn_open_report.pack(side="right", padx=4)
        self.btn_open_json = ttk.Button(bottom, text="{} JSON", command=self.open_json, state="disabled")
        self.btn_open_json.pack(side="right", padx=4)

        # دعم سحب وإفلات (Windows) — محاولة بسيطة
        try:
            self.root.drop_target_register = lambda *a, **k: None
        except:
            pass
        # ربط Ctrl+V للصق مسار
        self.root.bind("<Control-v>", lambda e: self.paste_path())
        # Enter لتشغيل
        self.root.bind("<Return>", lambda e: self.start_analyze())

    def log_insert(self, text):
        self.log.insert("end", text)
        self.log.see("end")
        self.root.update_idletasks()

    def clear_log(self):
        self.log.delete("1.0", "end")

    def paste_path(self):
        try:
            clip = self.root.clipboard_get()
            if clip and pathlib.Path(clip.strip('"')).exists():
                self.sample_path.set(clip.strip('"').strip())
        except:
            pass

    def browse_sample(self):
        p = filedialog.askopenfilename(
            title="اختر البرنامج",
            filetypes=[
                ("All files", "*.*"),
                ("Executable", "*.exe;*.dll;*.so;*.bin"),
                ("Python", "*.py;*.pyw"),
                ("ELF/PE", "*.exe;*.dll;*.so;*.elf;*.bin"),
            ]
        )
        if p:
            self.sample_path.set(p)

    def browse_output(self):
        p = filedialog.askdirectory(title="اختر مجلد الإخراج")
        if p:
            self.output_path.set(p)

    def toggle_dynamic(self):
        if self.enable_dynamic.get():
            self.dynamic_entry.config(state="normal")
            if not self.dynamic_args.get():
                self.dynamic_args.set("--help")
        else:
            self.dynamic_entry.config(state="disabled")

    def clear(self):
        self.sample_path.set("")
        self.enable_dynamic.set(False)
        self.toggle_dynamic()
        self.clear_log()
        self.log_insert("تم المسح.\n")
        self.status_text.set("جاهز")

    def open_patcher(self):
        try:
            # حاول فتح محرر النصوص في نافذة جديدة
            import subprocess
            import sys
            # شغّل patcher_gui كعملية منفصلة
            subprocess.Popen([sys.executable, str(ROOT / "gui" / "patcher_gui.py")])
        except Exception as e:
            messagebox.showinfo("المحرر", f"افتح يدوياً:\npython gui/patcher_gui.py\nأو دبل كليك Patcher_GUI.bat\n\n{e}")

    def open_windows_doc(self):
        doc = ROOT / "docs" / "WINDOWS.md"
        if doc.exists():
            try:
                os.startfile(str(doc))  # Windows
            except:
                webbrowser.open(str(doc))
        else:
            messagebox.showinfo("دليل", "افتح docs/WINDOWS.md")

    def quick_analyze(self):
        """زر واحد: اختر وحلّل"""
        if not self.sample_path.get():
            self.browse_sample()
            if not self.sample_path.get():
                return
        self.start_analyze()

    def start_monitor(self):
        if self.is_running:
            messagebox.showinfo("انتظر", "التحليل جارٍ...")
            return
        if not self.validate():
            return
        sample = pathlib.Path(self.sample_path.get().strip('"').strip()).resolve()
        output = pathlib.Path(self.output_path.get().strip('"').strip() or str(ROOT / "runs")).resolve()
        args = self.monitor_args_var.get().strip()
        try:
            timeout = int(self.monitor_timeout_var.get().strip() or "10")
        except:
            timeout = 10
        # تحذير
        if not messagebox.askyesno("تأكيد", f"سيتم تشغيل:\n{sample} {args}\n\nالبرنامج سيُشغّل فعلياً (معزول قدر الإمكان) وستُراقب كل أفعاله.\nهل أنت متأكد أنه موثوق وتملكه؟"):
            return
        self.is_running = True
        self.progress.start(10)
        self.status_text.set("▶️ جاري التشغيل والمراقبة...")
        self.clear_log()
        self.log_insert(f"▶️ تشغيل ومراقبة: {sample} {args}\n")
        self.log_insert(f"مهلة: {timeout}s\n")
        self.log_insert("-"*60 + "\n")
        self.btn_open_report.config(state="disabled")
        self.btn_open_folder.config(state="disabled")
        self.btn_open_json.config(state="disabled")
        if hasattr(self, 'btn_deep'):
            self.btn_deep.config(state="disabled")

        def worker():
            try:
                import subprocess, time, json, hashlib, shlex
                import datetime
                start_ts = datetime.datetime.now().isoformat()
                start_time = time.time()
                # مجلد المراقبة
                ts = datetime.datetime.now().strftime("%Y%m%dT%H%M%SZ")
                h = hashlib.md5(str(sample).encode()).hexdigest()[:8]
                mon_dir = output / f"monitor_{ts}_{h}"
                mon_dir.mkdir(parents=True, exist_ok=True)
                trace_path = mon_dir / "trace.json"
                log_path = mon_dir / "run.log"

                # سجل ملفات قبل التشغيل (للكشف عن ملفات جديدة)
                before_files = set()
                try:
                    for base in [pathlib.Path.cwd(), pathlib.Path("/tmp") if pathlib.Path("/tmp").exists() else output]:
                        if base.exists():
                            for f in base.rglob("*"):
                                if f.is_file():
                                    before_files.add(str(f))
                except: pass

                # بناء الأمر
                cmd = [str(sample)] + (shlex.split(args) if args else [])
                # للـ .py استخدم python
                if sample.suffix.lower() in (".py", ".pyw"):
                    cmd = [sys.executable, str(sample)] + (shlex.split(args) if args else [])

                self.log_insert(f"$ {' '.join(cmd)}\n")

                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="ignore", cwd=str(mon_dir))
                try:
                    out, err = proc.communicate(timeout=timeout)
                    code = proc.returncode
                    timed_out = False
                except subprocess.TimeoutExpired:
                    proc.kill()
                    try:
                        out, err = proc.communicate(timeout=2)
                    except:
                        out, err = "", ""
                    code = proc.returncode
                    timed_out = True
                    out += "\n[timeout after %ds]" % timeout

                elapsed = round(time.time() - start_time, 2)

                # ملفات جديدة
                after_files = set()
                try:
                    for base in [mon_dir, pathlib.Path.cwd(), pathlib.Path("/tmp") if pathlib.Path("/tmp").exists() else output]:
                        if base.exists():
                            for f in base.rglob("*"):
                                if f.is_file() and str(f) not in before_files:
                                    after_files.add(str(f))
                except: pass

                # حفظ
                trace = {
                    "sample": str(sample),
                    "args": args,
                    "cmd": cmd,
                    "start": start_ts,
                    "elapsed_sec": elapsed,
                    "exit_code": code,
                    "timed_out": timed_out,
                    "timeout": timeout,
                    "stdout": out[:20000],
                    "stderr": err[:20000],
                    "stdout_len": len(out),
                    "stderr_len": len(err),
                    "new_files": sorted(list(after_files))[:50],
                    "monitor_dir": str(mon_dir),
                }
                trace_path.write_text(json.dumps(trace, ensure_ascii=False, indent=2), encoding="utf-8")
                log_path.write_text(f"STDOUT:\n{out}\n\nSTDERR:\n{err}\n", encoding="utf-8", errors="ignore")

                # نسخ الـ trace للـ runs أيضاً كـ report
                self.last_run_dir = mon_dir
                self.root.after(0, lambda trace=trace, mon_dir=mon_dir: self.on_monitor_success(trace, mon_dir))

            except OSError as e:
                # WinError 740 = يحتاج Admin
                if getattr(e, 'winerror', None) == 740:
                    tb = traceback.format_exc()
                    msg = f"البرنامج يحتاج صلاحيات مسؤول (Admin):\n{e}\n\nالحل: كليك يمين على RevSpec_GUI.bat → تشغيل كمسؤول (Run as administrator)\nثم اختر نفس البرنامج وشغّل المراقبة مرة أخرى."
                    self.root.after(0, lambda msg=msg, tb=tb: self.on_error(OSError(msg), tb))
                else:
                    tb = traceback.format_exc()
                    self.root.after(0, lambda e=e, tb=tb: self.on_error(e, tb))
            except Exception as e:
                tb = traceback.format_exc()
                self.root.after(0, lambda e=e, tb=tb: self.on_error(e, tb))

        threading.Thread(target=worker, daemon=True).start()

    def on_monitor_success(self, trace, mon_dir):
        self.is_running = False
        self.progress.stop()
        self.status_text.set(f"✅ انتهت المراقبة — كود {trace['exit_code']} في {trace['elapsed_sec']}s")
        self.log_insert(f"\n✅ انتهى\n")
        self.log_insert(f"كود الخروج: {trace['exit_code']}  {'(timeout)' if trace['timed_out'] else ''}\n")
        self.log_insert(f"الوقت: {trace['elapsed_sec']}s\n")
        self.log_insert(f"STDOUT ({trace['stdout_len']} حرف):\n{trace['stdout'][:1500]}\n")
        if trace['stderr']:
            self.log_insert(f"\nSTDERR:\n{trace['stderr'][:800]}\n")
        if trace['new_files']:
            self.log_insert(f"\n📁 ملفات جديدة ({len(trace['new_files'])}):\n" + "\n".join(trace['new_files'][:10]) + "\n")
        self.log_insert(f"\n💾 حفظ كامل في: {mon_dir / 'trace.json'}\n")
        self.log_insert(f"💾 السجل: {mon_dir / 'run.log'}\n")
        self.btn_open_folder.config(state="normal")
        self.btn_open_report.config(state="disabled")
        self.btn_open_json.config(state="normal")
        # رسالة
        if messagebox.askyesno("تمت المراقبة", f"انتهت المراقبة!\n\nكود: {trace['exit_code']}\nوقت: {trace['elapsed_sec']}s\nمجلد: {mon_dir}\n\nهل تريد فتح المجلد الآن؟"):
            self.open_last_run()

    def validate(self):
        if not self.sample_path.get():
            messagebox.showwarning("تنبيه", "اختر مسار البرنامج أولاً")
            return False
        p = pathlib.Path(self.sample_path.get().strip('"').strip())
        if not p.exists():
            messagebox.showerror("خطأ", f"الملف غير موجود:\n{p}")
            return False
        if p.stat().st_size == 0:
            messagebox.showerror("خطأ", "الملف فارغ")
            return False
        # output
        out = pathlib.Path(self.output_path.get().strip('"').strip() or str(ROOT / "runs"))
        try:
            out.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            messagebox.showerror("خطأ", f"لا يمكن إنشاء مجلد الإخراج:\n{e}")
            return False
        return True

    def start_analyze(self):
        if self.is_running:
            messagebox.showinfo("انتظر", "التحليل جارٍ...")
            return
        if not self.validate():
            return
        if not REVSPEC_AVAILABLE:
            messagebox.showerror("خطأ", "RevSpec غير مثبت")
            return

        sample = pathlib.Path(self.sample_path.get().strip('"').strip()).resolve()
        output = pathlib.Path(self.output_path.get().strip('"').strip()).resolve()
        enable_dynamic = self.enable_dynamic.get()
        dynamic_args = self.dynamic_args.get().strip()
        deep = self.deep_var.get()

        # تأكيد ديناميكي
        if enable_dynamic:
            if not messagebox.askyesno("تأكيد", "التحليل الديناميكي سيشغّل البرنامج فعلياً (معزول قدر الإمكان).\n\nهل أنت متأكد أن البرنامج موثوق وتملكه؟"):
                return

        # فحص capstone إذا كان deep مفعّل
        if deep:
            try:
                import capstone
            except ImportError:
                if not messagebox.askyesno("capstone مفقود",
                    "التفكيك العميق يحتاج مكتبة capstone غير مثبتة.\n\n"
                    "ثبّت عبر:\n  pip install capstone pefile\n\n"
                    "بدونها سيظهر 'تعذر التفكيك — WinError 2'.\n\n"
                    "هل تريد المتابعة بدون تفكيك عميق؟"):
                    return
                else:
                    self.log_insert("⚠️ capstone غير مثبت — سيتم التحليل بدون deep\n")
                    deep = False

        self.is_running = True
        self.progress.start(10)
        if deep:
            self.status_text.set("جاري التحليل العميق ... قد يستغرق 20-40 ثانية (opcodes)")
        else:
            self.status_text.set("جاري التحليل ... قد يستغرق 10-30 ثانية")
        self.clear_log()
        self.log_insert(f"🚀 بدء التحليل{' العميق' if deep else ''}\n")
        self.log_insert(f"📄 البرنامج: {sample}\n")
        self.log_insert(f"📁 الإخراج: {output}\n")
        self.log_insert(f"⚙️ ديناميكي: {'نعم ' + dynamic_args if enable_dynamic else 'لا'}\n")
        self.log_insert(f"🔬 عميق: {'نعم' if deep else 'لا'}\n")
        self.log_insert("-"*60 + "\n")

        # تعطيل الأزرار
        self.btn_open_report.config(state="disabled")
        self.btn_open_folder.config(state="disabled")
        self.btn_open_json.config(state="disabled")
        if hasattr(self, 'btn_deep'):
            self.btn_deep.config(state="disabled")

        # تشغيل في thread
        def worker():
            try:
                pipeline = Pipeline(include_deep=deep)
                opts = {
                    "enable_dynamic": enable_dynamic,
                    "dynamic_timeout": 8,
                    "dynamic_args": dynamic_args,
                    "deep": deep,
                }
                result = pipeline.run(sample, output, opts)

                # تصدير
                # إيجاد مجلد الـ run الأحدث
                dirs = sorted([d for d in output.iterdir() if d.is_dir()], key=lambda p: p.stat().st_mtime, reverse=True)
                run_dir = dirs[0] if dirs else output

                from pathlib import Path as P
                template = ROOT / "templates" / "report.md.j2"
                json_path = run_dir / "report.json"
                yaml_path = run_dir / "report.yaml"
                md_path = run_dir / "report.md"

                export_json(result, json_path)
                try:
                    export_yaml(result, yaml_path)
                except Exception as e:
                    self.log_insert(f"[تحذير] YAML فشل: {e}\n")

                if template.exists():
                    render_markdown(result.to_dict(), template, md_path)
                else:
                    md_path.write_text(f"# Report\nSample: {result.sample.filename}\n", encoding="utf-8")

                self.last_run_dir = run_dir

                # نجاح
                self.root.after(0, lambda result=result, run_dir=run_dir: self.on_success(result, run_dir))

            except OSError as e:
                if getattr(e, 'winerror', None) == 740:
                    tb = traceback.format_exc()
                    msg = f"التحليل الديناميكي يحتاج Admin لهذا البرنامج:\n{e}\n\nالحل: شغّل RevSpec كمسؤول (كليك يمين → Run as administrator)"
                    self.root.after(0, lambda msg=msg, tb=tb: self.on_error(OSError(msg), tb))
                else:
                    tb = traceback.format_exc()
                    self.root.after(0, lambda e=e, tb=tb: self.on_error(e, tb))
            except Exception as e:
                tb = traceback.format_exc()
                self.root.after(0, lambda e=e, tb=tb: self.on_error(e, tb))

        threading.Thread(target=worker, daemon=True).start()

    def on_success(self, result, run_dir):
        self.is_running = False
        self.progress.stop()
        self.status_text.set(f"✅ اكتمل — {result.summary['total_findings']} نتيجة")
        self.log_insert("\n✅ اكتمل التحليل!\n")
        self.log_insert(f"📁 Run dir: {run_dir}\n")
        self.log_insert(f"📄 Markdown: {run_dir / 'report.md'}\n")
        self.log_insert(f"📄 JSON: {run_dir / 'report.json'}\n")
        self.log_insert(f"📄 YAML: {run_dir / 'report.yaml'}\n")
        self.log_insert("\nملخص:\n")
        self.log_insert(json.dumps(result.summary, ensure_ascii=False, indent=2) + "\n")
        self.log_insert("\nيمكنك الآن فتح التقرير أو مجلد النتائج.\n")

        self.btn_open_folder.config(state="normal")
        self.btn_open_report.config(state="normal")
        self.btn_open_json.config(state="normal")
        # deep
        deep_dir = pathlib.Path(run_dir) / "evidence" / "deep_opcode"
        if deep_dir.exists():
            self.btn_deep.config(state="normal")
            self.log_insert(f"🔬 Opcodes: {deep_dir / 'opcodes_full.json.gz'}\n")
            self.log_insert(f"🔬 Skeleton: {deep_dir / 'skeleton.cpp'}\n")
            self.log_insert(f"🔬 AI report: {deep_dir / 'ai_report.json'}\n")
            self.log_insert("\n📤 أرسل هذه الملفات + prompts/cpp_rebuild_prompt.md للذكاء الاصطناعي ليبني C++\n")

        # رسالة
        if messagebox.askyesno("تم", f"اكتمل التحليل!\n\n{result.summary['total_findings']} نتيجة\nمجلد: {run_dir}\n\nهل تريد فتح التقرير الآن؟"):
            self.open_report()

    def on_error(self, e, tb):
        self.is_running = False
        self.progress.stop()
        self.status_text.set("❌ فشل")
        self.log_insert(f"\n❌ خطأ: {e}\n")
        self.log_insert(tb + "\n")
        # رسالة خاصة لـ WinError 740
        if "740" in str(e) or "elevation" in str(e).lower():
            # اقترح تشغيل كمسؤول
            if messagebox.askyesno("يحتاج مسؤول", f"{e}\n\nالبرنامج يحتاج صلاحيات مسؤول (Admin).\nهل تريد محاولة التشغيل كمسؤول الآن؟\n\n(سيطلب ويندوز تأكيد UAC)"):
                try:
                    import ctypes, sys
                    # إعادة تشغيل الـ GUI كمسؤول
                    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{__file__}"', None, 1)
                except Exception as ex:
                    messagebox.showinfo("تشغيل كمسؤول", f"لم أستطع إعادة التشغيل تلقائياً:\n{ex}\n\nالحل اليدوي: كليك يمين على RevSpec_GUI.bat → تشغيل كمسؤول")
            return
        messagebox.showerror("خطأ", f"فشل التحليل:\n{e}\n\nراجع السجل.")

    def open_deep(self):
        if self.last_run_dir:
            deep = pathlib.Path(self.last_run_dir) / "evidence" / "deep_opcode"
            if deep.exists():
                # حاول فتح skeleton.cpp
                skel = deep / "skeleton.cpp"
                if skel.exists():
                    try:
                        import os
                        os.startfile(str(skel))
                        return
                    except:
                        pass
                    try:
                        os.system(f'notepad "{skel}"')
                        return
                    except:
                        pass
                try:
                    import os
                    os.startfile(str(deep))
                    return
                except:
                    import webbrowser
                    webbrowser.open(str(deep))
                    return
            else:
                import pathlib
                # لا يوجد deep، اعرض رسالة
                from tkinter import messagebox
                messagebox.showinfo("عميق", "لم يتم تفعيل التفكيك العميق.\nفعّل ✅ تفكيك عميق قبل التحليل.")
                return
        from tkinter import messagebox
        messagebox.showwarning("تنبيه", "لم يتم التحليل بعد")

    def open_last_run(self):
        if self.last_run_dir and pathlib.Path(self.last_run_dir).exists():
            try:
                os.startfile(str(self.last_run_dir))  # Windows
            except:
                try:
                    import subprocess
                    subprocess.Popen(["xdg-open", str(self.last_run_dir)])
                except:
                    webbrowser.open(str(self.last_run_dir))
        else:
            # افتح مجلد الإخراج
            p = pathlib.Path(self.output_path.get())
            try:
                os.startfile(str(p))
            except:
                messagebox.showinfo("مجلد", str(p))

    def open_report(self):
        if self.last_run_dir:
            md = pathlib.Path(self.last_run_dir) / "report.md"
            if md.exists():
                try:
                    os.startfile(str(md))
                    return
                except:
                    pass
                # fallback notepad
                try:
                    os.system(f'notepad "{md}"')
                    return
                except:
                    pass
            messagebox.showinfo("تقرير", str(md))
        else:
            messagebox.showwarning("تنبيه", "لم يتم التحليل بعد")

    def open_json(self):
        if self.last_run_dir:
            # للمراقبة trace.json، للتحليل report.json
            js = pathlib.Path(self.last_run_dir) / "report.json"
            if not js.exists():
                js = pathlib.Path(self.last_run_dir) / "trace.json"
            if js.exists():
                try:
                    os.startfile(str(js))
                    return
                except:
                    pass
                try:
                    os.system(f'notepad "{js}"')
                    return
                except:
                    pass
            messagebox.showinfo("JSON", str(js))

def main():
    if not TK_AVAILABLE:
        print("Tkinter غير متوفر على هذا النظام.", file=sys.stderr)
        print("على Linux ثبّت: sudo apt install python3-tk", file=sys.stderr)
        print("على Windows هو مدمج مع Python.", file=sys.stderr)
        print("بديل CLI: python -m revspec.cli --help", file=sys.stderr)
        sys.exit(1)
    # تحقق من Tkinter
    try:
        root = tk.Tk()
    except Exception as e:
        print(f"Tkinter غير متوفر: {e}", file=sys.stderr)
        print("ثبّت Python مع Tkinter أو شغّل عبر CLI: python -m revspec.cli --help", file=sys.stderr)
        sys.exit(1)

    # خط جميل على Windows
    try:
        root.tk.call("tk", "scaling", 1.2)
    except:
        pass

    app = RevSpecGUI(root)
    # دعم سحب ملف على النافذة (Windows: عبر tkdnd إن توفر)
    # بدون مكتبات إضافية نستخدم binding بسيط
    def on_drop(event):
        # محاولة قراءة المسار المسحوب
        try:
            data = event.data if hasattr(event, 'data') else ""
            if data:
                p = data.strip("{}").strip('"')
                if pathlib.Path(p).exists():
                    app.sample_path.set(p)
        except:
            pass
    # لا نعتمد على tkdnd، نترك الاستعراض
    root.mainloop()

if __name__ == "__main__":
    main()
