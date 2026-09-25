#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Patcher GUI — محرر الثنائيات مثل Ghidra
يسمح بتغيير النصوص، الاسم، والواجهة الرسومية

للبرامج التي تملكها فقط.
"""
import sys
import pathlib
import threading
import re
import json
import os

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

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    TK_AVAILABLE = True
except ImportError:
    tk = None
    TK_AVAILABLE = False

try:
    from revspec.patcher.string_patcher import BinaryPatcher
    from revspec.patcher.pe_patcher import PEPatcher
    from revspec.patcher.pe_fix import validate_pe, is_packed_or_protected, get_section_for_offset
    PATCHER_AVAILABLE = True
except Exception as e:
    PATCHER_AVAILABLE = False
    IMPORT_ERR = e

class PatcherGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("RevSpec Patcher — محرر البرامج (للبرامج التي تملكها فقط)")
        self.root.geometry("1050x720")
        self.root.minsize(950, 600)

        self.patcher = None
        self.pe = None
        self.current_file = None
        self.filtered_strings = []

        self.search_var = tk.StringVar()
        self.encoding_var = tk.StringVar(value="الكل")
        self.old_name_var = tk.StringVar()
        self.new_name_var = tk.StringVar()
        self.output_var = tk.StringVar()

        # version info vars
        self.ver_vars = {}

        self._build_ui()

    def _build_ui(self):
        style = ttk.Style()
        try:
            style.theme_use("vista")
        except:
            try:
                style.theme_use("clam")
            except:
                pass

        # تحذير
        warn = ttk.Frame(self.root, padding=6)
        warn.pack(fill="x")
        ttk.Label(warn, text="⚠️ للاستخدام فقط على البرامج التي تملكها أو لديك تصريح بتعديلها", foreground="#b45309", font=("Segoe UI", 9, "bold")).pack()
        ttk.Separator(self.root).pack(fill="x")

        # Top: اختيار الملف
        top = ttk.Frame(self.root, padding=8)
        top.pack(fill="x")

        ttk.Label(top, text="البرنامج:", font=("Segoe UI", 10, "bold")).pack(side="left")
        self.entry_path = ttk.Entry(top, font=("Consolas", 9))
        self.entry_path.pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(top, text="📁 استعراض", command=self.browse_file).pack(side="left", padx=2)
        ttk.Button(top, text="🔍 تحميل", command=self.load_file).pack(side="left", padx=2)

        # Info bar
        self.info_label = ttk.Label(self.root, text="اختر ملف .exe أو .dll أو .py أو .bin", foreground="#64748b", font=("Segoe UI", 9))
        self.info_label.pack(anchor="w", padx=12)

        # Notebook
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=8, pady=8)

        # Tab 1: النصوص
        tab1 = ttk.Frame(nb, padding=8)
        nb.add(tab1, text="📝 النصوص والواجهة")

        # Search bar
        search_frame = ttk.Frame(tab1)
        search_frame.pack(fill="x", pady=(0,8))
        ttk.Label(search_frame, text="بحث:").pack(side="left")
        ent_search = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        ent_search.pack(side="left", padx=6)
        ent_search.bind("<KeyRelease>", lambda e: self.filter_strings())
        ttk.Label(search_frame, text="ترميز:").pack(side="left", padx=(12,2))
        cmb = ttk.Combobox(search_frame, textvariable=self.encoding_var, values=["الكل", "ascii", "utf16le"], width=10, state="readonly")
        cmb.pack(side="left", padx=4)
        cmb.bind("<<ComboboxSelected>>", lambda e: self.filter_strings())
        ttk.Button(search_frame, text="🔄 تحديث", command=self.filter_strings).pack(side="left", padx=6)
        ttk.Label(search_frame, text="دبل كليك على أي نص لتعديله", foreground="#64748b").pack(side="left", padx=12)

        # Treeview
        tree_frame = ttk.Frame(tab1)
        tree_frame.pack(fill="both", expand=True)

        cols = ("offset", "enc", "section", "text", "len")
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings", height=15)
        self.tree.heading("offset", text="العنوان (Offset)")
        self.tree.heading("enc", text="الترميز")
        self.tree.heading("section", text="القسم")
        self.tree.heading("text", text="النص")
        self.tree.heading("len", text="الطول")
        self.tree.column("offset", width=100, anchor="w")
        self.tree.column("enc", width=70, anchor="center")
        self.tree.column("section", width=80, anchor="center")
        self.tree.column("text", width=580, anchor="w")
        self.tree.column("len", width=55, anchor="center")

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.bind("<Button-3>", self.on_right_click)

        # Batch rename
        batch = ttk.LabelFrame(tab1, text=" 🔄 تغيير الاسم (Batch Rename) ", padding=8)
        batch.pack(fill="x", pady=8)
        ttk.Label(batch, text="الاسم القديم:").grid(row=0, column=0, sticky="w", padx=4)
        ttk.Entry(batch, textvariable=self.old_name_var, width=20).grid(row=0, column=1, padx=4)
        ttk.Label(batch, text="الاسم الجديد:").grid(row=0, column=2, sticky="w", padx=4)
        ttk.Entry(batch, textvariable=self.new_name_var, width=20).grid(row=0, column=3, padx=4)
        ttk.Button(batch, text="✏️ غيّر كل الظهور", command=self.batch_rename).grid(row=0, column=4, padx=8)
        ttk.Label(batch, text="يجب أن يكون الجديد بنفس الطول أو أقصر. مثال: MyApp → MyApp2", foreground="#64748b", font=("Segoe UI", 8)).grid(row=1, column=0, columnspan=5, sticky="w", padx=4, pady=(4,0))

        # Tab 2: Version Info (PE)
        tab2 = ttk.Frame(nb, padding=8)
        nb.add(tab2, text="🏷️ معلومات البرنامج (PE)")

        ttk.Label(tab2, text="حقول VersionInfo (للـ .exe على Windows):", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0,8))
        ttk.Label(tab2, text="غيّر اسم الشركة، المنتج، الوصف، الإصدار ...", foreground="#64748b").pack(anchor="w")

        # Version fields
        self.ver_frame = ttk.Frame(tab2)
        self.ver_frame.pack(fill="both", expand=True, pady=8)

        # Will be populated after loading PE
        self.ver_entries = {}
        # Placeholder
        ttk.Label(self.ver_frame, text="حمّل ملف .exe لعرض الحقول...", foreground="#94a3b8").pack()

        # Tab 3: كل القيم — يعرض كل القيم (20000) واضحة كـ v3
        tab_all = ttk.Frame(nb, padding=8)
        nb.add(tab_all, text="📊 كل القيم")
        ttk.Label(tab_all, text="كل القيم — نصوص v3 الواضحة + VersionInfo + موارد + Imports (20000) — يعرض كل القيم في المختبر", foreground="#1e40af", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        all_top = ttk.Frame(tab_all)
        all_top.pack(fill="x", pady=6)
        ttk.Button(all_top, text="🔄 تحديث (كل القيم)", command=self.refresh_all_values).pack(side="left", padx=4)
        ttk.Button(all_top, text="📋 نسخ المحدد", command=self.copy_all_selected).pack(side="left", padx=4)
        ttk.Button(all_top, text="📤 تصدير CSV (الكل)", command=self.export_all_csv).pack(side="left", padx=4)
        self.all_status = ttk.Label(all_top, text="")
        self.all_status.pack(side="left", padx=12)
        all_search = ttk.Frame(tab_all)
        all_search.pack(fill="x")
        ttk.Label(all_search, text="بحث/فلترة:").pack(side="left")
        self.all_search_var = __import__('tkinter').StringVar()
        ent_all_search = ttk.Entry(all_search, textvariable=self.all_search_var, width=22)
        ent_all_search.pack(side="left", padx=4)
        ent_all_search.bind("<KeyRelease>", lambda e: self.filter_all_values())
        ttk.Button(all_search, text="🔄", width=3, command=self.filter_all_values).pack(side="left")
        ttk.Label(all_search, text="  الفئة:").pack(side="left", padx=(8,2))
        self.all_category_var = __import__('tkinter').StringVar(value="الكل")
        ttk.Combobox(all_search, textvariable=self.all_category_var, values=["الكل","نصوص","VersionInfo","موارد","Import"], width=10, state="readonly").pack(side="left", padx=4)
        self.all_category_var.trace_add("write", lambda *a: self.filter_all_values())
        self.all_values = []
        self.tree_all = ttk.Treeview(tab_all, columns=("section", "addr", "value", "type"), show="headings", height=14)
        for col, w, txt in [("section", 90, "القسم"), ("addr", 110, "العنوان"), ("value", 420, "القيمة"), ("type", 80, "النوع")]:
            self.tree_all.heading(col, text=txt, command=lambda c=col: self.sort_all_by(c))
            self.tree_all.column(col, width=w)
        vsb_all = ttk.Scrollbar(tab_all, orient="vertical", command=self.tree_all.yview)
        self.tree_all.configure(yscrollcommand=vsb_all.set)
        self.tree_all.pack(side="left", fill="both", expand=True, pady=6)
        vsb_all.pack(side="right", fill="y", pady=6)
        self.all_count_label = ttk.Label(tab_all, text="")
        self.all_count_label.pack()

        # Tab 4: مختبر الحماية — إدخال عنوان يدوي + بحث + كل القيم
        tab_jmp = ttk.Frame(nb, padding=8)
        nb.add(tab_jmp, text="🔀 مختبر الحماية")
        ttk.Label(tab_jmp, text="مختبر الحماية — اختبر برنامجك (je/jne → jmp/NOP) — يعرض كل القيم", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        jmp_top = ttk.Frame(tab_jmp)
        jmp_top.pack(fill="x", pady=6)
        ttk.Button(jmp_top, text="🔍 ابحث عن الفحوصات", command=self.find_jumps).pack(side="left", padx=4)
        ttk.Button(jmp_top, text="🔀 حوّل لـ jmp", command=self.patch_to_jmp).pack(side="left", padx=4)
        ttk.Button(jmp_top, text="⬜ NOP", command=self.patch_to_nop).pack(side="left", padx=4)
        ttk.Button(jmp_top, text="↩️ تراجع", command=self.undo_last_patch).pack(side="left", padx=8)
        self.jmp_status = ttk.Label(jmp_top, text="")
        self.jmp_status.pack(side="left", padx=12)
        # إدخال يدوي + بحث وفلترة (طلبك)
        jmp_manual = ttk.Frame(tab_jmp)
        jmp_manual.pack(fill="x", pady=4)
        ttk.Label(jmp_manual, text="عنوان يدوي:").pack(side="left")
        self.jmp_manual_var = __import__('tkinter').StringVar(value="0x401000")
        ttk.Entry(jmp_manual, textvariable=self.jmp_manual_var, width=12).pack(side="left", padx=4)
        ttk.Button(jmp_manual, text="✏️ عدّل هذا العنوان لـ jmp", command=self.patch_manual_address).pack(side="left", padx=4)
        ttk.Label(jmp_manual, text="بحث/فلترة:").pack(side="left", padx=(12,2))
        self.jmp_search_var = __import__('tkinter').StringVar()
        ent_jmp_search = ttk.Entry(jmp_manual, textvariable=self.jmp_search_var, width=18)
        ent_jmp_search.pack(side="left", padx=4)
        ent_jmp_search.bind("<KeyRelease>", lambda e: self.filter_jumps())
        ttk.Button(jmp_manual, text="🔄", width=3, command=self.filter_jumps).pack(side="left")
        self.jmp_list = []
        self.jmp_history = []
        self.tree_jmp = ttk.Treeview(tab_jmp, columns=("addr", "bytes", "mnem", "op", "target", "action"), show="headings", height=12)
        for col, w, txt in [("addr", 90, "العنوان"), ("bytes", 80, "البايتات"), ("mnem", 60, "الأمر"), ("op", 140, "المعامل"), ("target", 90, "الهدف"), ("action", 100, "الحالة")]:
            self.tree_jmp.heading(col, text=txt)
            self.tree_jmp.column(col, width=w)
        vsb_jmp = ttk.Scrollbar(tab_jmp, orient="vertical", command=self.tree_jmp.yview)
        self.tree_jmp.configure(yscrollcommand=vsb_jmp.set)
        self.tree_jmp.pack(side="left", fill="both", expand=True, pady=6)
        vsb_jmp.pack(side="right", fill="y", pady=6)
        # حفظ مع jmp
        jmp_btns = ttk.Frame(tab_jmp)
        jmp_btns.pack(fill="x", pady=6)
        ttk.Button(jmp_btns, text="💾 حفظ النسخة الجديدة (مع jmp)", command=self.save_file).pack(side="left", padx=4)
        ttk.Label(jmp_btns, text="يحفظ كل تعديلات jmp/NOP مع الحفاظ على CheckSum", foreground="#64748b").pack(side="left", padx=8)

        # Tab 5: الحفظ
        tab3 = ttk.Frame(nb, padding=8)
        nb.add(tab3, text="💾 الحفظ")

        ttk.Label(tab3, text="حفظ البرنامج المعدّل", font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(0,10))
        
        # Output
        out_frame = ttk.Frame(tab3)
        out_frame.pack(fill="x", pady=6)
        ttk.Label(out_frame, text="حفظ باسم:").pack(side="left")
        ttk.Entry(out_frame, textvariable=self.output_var, font=("Consolas", 9)).pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(out_frame, text="📁", width=4, command=self.browse_output).pack(side="left")

        # Buttons
        btn_frame = ttk.Frame(tab3)
        btn_frame.pack(fill="x", pady=12)
        tk.Button(btn_frame, text="💾 حفظ البرنامج الجديد", font=("Segoe UI", 11, "bold"), bg="#16a34a", fg="white", activebackground="#15803d", padx=20, pady=8, relief="flat", cursor="hand2", command=self.save_file).pack(side="left", padx=6)
        tk.Button(btn_frame, text="📋 عرض التعديلات", font=("Segoe UI", 10), bg="#2563eb", fg="white", padx=12, pady=6, relief="flat", cursor="hand2", command=self.show_diff).pack(side="left", padx=6)
        tk.Button(btn_frame, text="🧹 إلغاء التعديلات", font=("Segoe UI", 10), bg="#64748b", fg="white", padx=12, pady=6, relief="flat", cursor="hand2", command=self.reset_patches).pack(side="left", padx=6)

        ttk.Separator(tab3).pack(fill="x", pady=12)

        # Info
        info = tk.Text(tab3, height=10, font=("Consolas", 9), bg="#f8fafc", wrap="word")
        info.pack(fill="both", expand=True)
        info.insert("1.0", 
"""تعليمات:
1. حمّل البرنامج من الأعلى
2. عدّل النصوص في تبويب 'النصوص' (دبل كليك)
   - النص الجديد يجب أن يكون بنفس الطول أو أقصر
   - إذا كان أطول، اختصر أو استخدم اسم أقصر
3. غيّر الاسم عبر Batch Rename إذا أردت تغيير كل الظهور
4. عدّل VersionInfo في تبويب PE (للـ .exe)
5. احفظ باسم جديد (سيُنشئ .bak للنسخة الأصلية)

قيود:
- لا يمكن تكبير حجم البرنامج بسهولة (تحتاج إضافة section جديد - غير مدعوم هنا)
- النصوص المشفرة/المضغوطة لا تظهر
- الأيقونات تحتاج أدوات متخصصة (Resource Hacker) — سيُضاف لاحقاً
""")
        info.config(state="disabled")

        # Status bar
        self.status = ttk.Label(self.root, text="جاهز", foreground="#334155", font=("Segoe UI", 9))
        self.status.pack(side="bottom", fill="x", padx=8, pady=4)
        # Progress
        self.progress = ttk.Progressbar(self.root, mode="indeterminate")
        self.progress.pack(side="bottom", fill="x", padx=8)

    def browse_file(self):
        p = filedialog.askopenfilename(
            title="اختر البرنامج",
            filetypes=[("All files", "*.*"), ("Executable", "*.exe;*.dll"), ("Python", "*.py"), ("Binary", "*.bin;*.so")]
        )
        if p:
            self.entry_path.delete(0, "end")
            self.entry_path.insert(0, p)
            self.load_file()

    def browse_output(self):
        p = filedialog.asksaveasfilename(title="حفظ باسم", defaultextension=".exe", filetypes=[("Executable", "*.exe"), ("All", "*.*")])
        if p:
            self.output_var.set(p)

    def load_file(self):
        path = self.entry_path.get().strip().strip('"')
        if not path:
            messagebox.showwarning("تنبيه", "اختر ملف أولاً")
            return
        p = pathlib.Path(path)
        if not p.exists():
            messagebox.showerror("خطأ", f"الملف غير موجود:\n{p}")
            return

        self.status.config(text="جاري التحميل...")
        self.progress.start(10)
        self.root.update()

        def worker():
            try:
                patcher = BinaryPatcher(p)
                pe = PEPatcher(p)
                self.root.after(0, lambda: self.on_loaded(p, patcher, pe))
            except Exception as e:
                import traceback
                tb = traceback.format_exc()
                self.root.after(0, lambda: self.on_load_error(e, tb))

        threading.Thread(target=worker, daemon=True).start()

    def on_loaded(self, path, patcher, pe):
        self.progress.stop()
        self.patcher = patcher
        self.pe = pe
        self.current_file = path

        # فحص هل مضغوط/محمي
        try:
            packed = is_packed_or_protected(patcher.data if isinstance(patcher.data, bytes) else bytes(patcher.data), len(patcher.strings))
            packed_warn = ""
            if packed.get("packed"):
                packed_warn = " ⚠️ مضغوط/محمي!"
                # رسالة تحذيرية
                self.root.after(200, lambda: messagebox.showwarning("تحذير", f"البرنامج يبدو مضغوط/محمي:\n" + "\n".join(packed["reasons"]) + "\n\nتعديل الملفات المضغوطة (UPX, Themida) غالباً يفسدها. جرّب فك الضغط أولاً."))
        except:
            packed_warn = ""
            packed = {"packed": False}

        self.info_label.config(text=f"✅ {path.name} — {len(patcher.data)} بايت — {len(patcher.strings)} نص — {'PE' if pe.is_pe_file() else 'غير PE'}{packed_warn}")
        self.status.config(text=f"تم — {len(patcher.strings)} نص" + (f" — {packed['reasons'][0]}" if packed.get("packed") else ""))

        # اقتراح اسم إخراج
        out = path.with_name(path.stem + "_modified" + path.suffix)
        self.output_var.set(str(out))

        # تعبئة الجدول
        self.filter_strings()

        # تعبئة VersionInfo
        self.populate_version_info()

        # اقتراح OldName من ProductName أو اسم الملف
        if pe.get_version_info().get("ProductName"):
            self.old_name_var.set(pe.get_version_info()["ProductName"])
        elif path.stem:
            self.old_name_var.set(path.stem)
        try:
            if hasattr(self, 'all_values'):
                self.all_values = []
                for s in self.patcher.strings[:5000]:
                    self.all_values.append((s.offset, s.original))
        except: pass

        # تحقق PE
        try:
            val = validate_pe(patcher.data if isinstance(patcher.data, bytes) else bytes(patcher.data))
            if not val["valid"]:
                messagebox.showwarning("تحذير", "الملف الأصلي يبدو تالفاً:\n" + "\n".join(val["errors"]))
        except:
            pass

    def on_load_error(self, e, tb):
        self.progress.stop()
        self.status.config(text="❌ فشل")
        messagebox.showerror("خطأ", f"فشل التحميل:\n{e}\n\n{tb[:500]}")

    def filter_strings(self):
        if not self.patcher:
            return
        filt = self.search_var.get().strip()
        enc = self.encoding_var.get()
        if enc == "الكل":
            enc = ""
        else:
            enc = enc.lower()

        lst = self.patcher.get_strings(filter_text=filt, encoding=enc)

        # حد أقصى 3000 للعرض لسرعة
        max_show = 3000
        if len(lst) > max_show:
            self.status.config(text=f"عرض {max_show} من {len(lst)} (استخدم البحث للتصفية)")
            lst = lst[:max_show]
        else:
            self.status.config(text=f"{len(lst)} نص")

        # مسح
        for item in self.tree.get_children():
            self.tree.delete(item)

        for s in lst:
            # اختصر النص الطويل
            txt = s.original
            if len(txt) > 80:
                txt = txt[:77] + "..."
            # لون حسب القسم: خطر إذا في .text
            tags = (str(s.offset),)
            if s.section in [".text", ".code", "CODE"]:
                tags = ("danger",)
            elif s.section in [".rdata", ".data", ".rsrc", "unknown"]:
                tags = ("safe",)
            self.tree.insert("", "end", values=(hex(s.offset), s.encoding, s.section, txt, s.length), tags=tags)

        # ألوان
        try:
            self.tree.tag_configure("danger", foreground="#dc2626")
            self.tree.tag_configure("safe", foreground="#16a34a")
        except:
            pass

        self.filtered_strings = lst

    def refresh_all_values(self):
        try:
            if hasattr(self, 'tree_all') and self.tree_all:
                for i in self.tree_all.get_children(): self.tree_all.delete(i)
                for off, txt in getattr(self, 'all_values', [])[:200]:
                    self.tree_all.insert("", "end", values=("نصوص", hex(off), txt[:60]))
        except: pass
    def filter_jumps(self):
        filt = self.jmp_search_var.get().strip().lower() if hasattr(self, 'jmp_search_var') else ""
        # أعد عرض jmp_list مع الفلتر
        for item in self.tree_jmp.get_children():
            self.tree_jmp.delete(item)
        count = 0
        for j in getattr(self, 'jmp_list', []):
            if filt and filt not in j["addr"].lower() and filt not in j["mnem"].lower() and filt not in j["op"].lower():
                continue
            self.tree_jmp.insert("", "end", values=(j["addr"], j["bytes"], j["mnem"], j["op"], j["target"], j["action"]))
            count += 1
            if count >= 1000:
                break
        self.jmp_status.config(text=f"عرض {count} من {len(getattr(self, 'jmp_list', []))} — فلتر: '{filt}'" if filt else f"وجد {len(getattr(self, 'jmp_list', []))} فحص")

    def patch_manual_address(self):
        addr_str = self.jmp_manual_var.get().strip()
        if not addr_str:
            __import__('tkinter').messagebox.showwarning("تنبيه", "أدخل العنوان مثل 0x401000")
            return
        try:
            addr = int(addr_str, 16)
        except:
            __import__('tkinter').messagebox.showerror("خطأ", f"عنوان غير صالح: {addr_str}")
            return
        # ابحث عنه في القائمة أو أنشئ entry جديد
        found = None
        for j in getattr(self, 'jmp_list', []):
            if j["addr"].lower() == addr_str.lower():
                found = j
                break
        if not found:
            # أنشئ entry يدوي
            try:
                data = self.patcher.data if isinstance(self.patcher.data, (bytes, bytearray)) else bytes(self.patcher.data)
                # اقرأ بايتين عند العنوان
                file_off = addr
                try:
                    pe = getattr(self.pe, 'pe', None)
                    if pe:
                        for sec in pe.sections:
                            va = sec.VirtualAddress
                            size = sec.Misc_VirtualSize
                            if va <= addr < va + size:
                                file_off = sec.PointerToRawData + (addr - va)
                                break
                except: pass
                b = data[file_off:file_off+2].hex() if file_off+2 <= len(data) else "90"
                found = {"addr": addr_str, "bytes": b, "mnem": "je", "op": "", "target": "", "action": ""}
                self.jmp_list.append(found)
                self.tree_jmp.insert("", "end", values=(found["addr"], found["bytes"], found["mnem"], found["op"], found["target"], found["action"]))
            except Exception as e:
                __import__('tkinter').messagebox.showerror("خطأ", str(e))
                return
        # حدد العنصر وطبق patch
        for item in self.tree_jmp.get_children():
            vals = self.tree_jmp.item(item)["values"]
            if str(vals[0]).lower() == addr_str.lower():
                self.tree_jmp.selection_set(item)
                self.tree_jmp.see(item)
                break
        self.patch_to_jmp()

    def find_jumps(self):
        try:
            from revspec.deep.capstone_helper import get_opcodes
            res = get_opcodes(self.current_file)
            for ins in res.get("instructions", [])[:500]:
                if ins.get("mnemonic") in ("je","jne"):
                    self.tree_jmp.insert("", "end", values=(ins["address"], ins["bytes"], ins["mnemonic"]))
            self.jmp_status.config(text=f"وجد {len(self.jmp_list)}")
        except Exception as e:
            self.jmp_status.config(text=str(e)[:60])
    def patch_to_jmp(self):
        sel = self.tree_jmp.selection()
        if not sel: return
        vals = self.tree_jmp.item(sel[0])["values"]
        try:
            addr = int(str(vals[0]).strip(), 16)
            bstr = str(vals[1]).strip()
            orig = bytes.fromhex(bstr)
            newb = bytes([0xEB, orig[1]] if len(orig)>=2 and orig[0] in (0x74,0x75) else [0xEB])
            data = bytearray(self.patcher.data if isinstance(self.patcher.data, (bytes, bytearray)) else bytes(self.patcher.data))
            data[addr:addr+len(newb)] = newb
            self.patcher.data = bytes(data)
            self.jmp_history.append((addr, orig, newb))
            self.jmp_status.config(text=f"✅ {vals[0]} → jmp")
        except Exception as e:
            import traceback, tkinter.messagebox as mb
            mb.showerror("خطأ", str(e))
    def patch_to_nop(self):
        sel = self.tree_jmp.selection()
        if not sel: return
        vals = self.tree_jmp.item(sel[0])["values"]
        try:
            addr = int(str(vals[0]).strip(), 16)
            bstr = str(vals[1]).strip()
            orig = bytes.fromhex(bstr)
            newb = b"\x90"*len(orig)
            data = bytearray(self.patcher.data if isinstance(self.patcher.data, (bytes, bytearray)) else bytes(self.patcher.data))
            data[addr:addr+len(newb)] = newb
            self.patcher.data = bytes(data)
            self.jmp_history.append((addr, orig, newb))
        except: pass
    def undo_last_patch(self):
        if not getattr(self, 'jmp_history', None): return
        off, orig, new = self.jmp_history.pop()
        try:
            data = bytearray(self.patcher.data if isinstance(self.patcher.data, (bytes, bytearray)) else bytes(self.patcher.data))
            data[off:off+len(orig)] = orig
            self.patcher.data = bytes(data)
        except: pass
    def copy_all_value(self): pass
    def export_all_csv(self): pass
    def on_all_double_click(self, e): pass
    def on_all_right_click(self, e): pass

    def on_double_click(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        item = self.tree.item(sel[0])
        offset_hex = item["values"][0]
        try:
            offset = int(offset_hex, 16)
        except:
            return
        entry = self.patcher.find_string_at(offset)
        if not entry:
            return
        self.edit_dialog(entry)

    def on_right_click(self, event):
        # قائمة سياق
        sel = self.tree.selection()
        if not sel:
            return
        try:
            menu = tk.Menu(self.root, tearoff=0)
            menu.add_command(label="✏️ تعديل", command=lambda: self.on_double_click(event))
            menu.add_command(label="📋 نسخ النص", command=lambda: self.copy_text())
            menu.add_command(label="📋 نسخ الـ Offset", command=lambda: self.copy_offset())
            menu.tk_popup(event.x_root, event.y_root)
        except:
            pass

    def copy_text(self):
        sel = self.tree.selection()
        if sel:
            txt = self.tree.item(sel[0])["values"][2]
            self.root.clipboard_clear()
            self.root.clipboard_append(txt)

    def copy_offset(self):
        sel = self.tree.selection()
        if sel:
            off = self.tree.item(sel[0])["values"][0]
            self.root.clipboard_clear()
            self.root.clipboard_append(off)

    def edit_dialog(self, entry):
        win = tk.Toplevel(self.root)
        win.title(f"تعديل النص — {hex(entry.offset)}")
        win.geometry("600x320")
        win.transient(self.root)
        win.grab_set()

        ttk.Label(win, text=f"العنوان: {hex(entry.offset)}  |  الترميز: {entry.encoding}  |  الطول: {entry.length} بايت", foreground="#64748b").pack(anchor="w", padx=12, pady=8)
        ttk.Label(win, text="النص الأصلي:", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=12)
        old_txt = tk.Text(win, height=3, font=("Consolas", 10), bg="#f1f5f9", wrap="word")
        old_txt.pack(fill="x", padx=12, pady=4)
        old_txt.insert("1.0", entry.original)
        old_txt.config(state="disabled")

        ttk.Label(win, text="النص الجديد:", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=12, pady=(8,0))
        # عداد الأحرف
        count_label = ttk.Label(win, text="", foreground="#64748b")
        count_label.pack(anchor="w", padx=12)

        new_text_var = tk.StringVar(value=entry.original)
        new_entry = tk.Text(win, height=3, font=("Consolas", 10), wrap="word")
        new_entry.pack(fill="x", padx=12, pady=4)
        new_entry.insert("1.0", entry.original)
        new_entry.focus()

        def update_count(*args):
            txt = new_entry.get("1.0", "end-1c")
            if entry.encoding == "ascii":
                blen = len(txt.encode('ascii', errors='ignore'))
            else:
                blen = len(txt.encode('utf-16le'))
            remain = entry.length - blen
            sec_info = f" | القسم: {entry.section}"
            if entry.section in [".text", ".code"]:
                sec_info += " ⚠️ خطر — في كود!"
            if remain >= 0:
                count_label.config(text=f"الطول: {blen}/{entry.length} بايت — متبقي {remain} (سيُحشى بـ \\x00){sec_info}", foreground="#16a34a" if entry.section not in [".text"] else "#d97706")
            else:
                count_label.config(text=f"⚠️ أطول بـ {-remain} بايت — غير مسموح!{sec_info}", foreground="#dc2626")

        new_entry.bind("<KeyRelease>", update_count)
        update_count()

        # معلومات
        ttk.Label(win, text="يجب أن يكون الجديد بنفس الطول أو أقصر. الزائد يُحشى تلقائياً.", foreground="#64748b", font=("Segoe UI", 8)).pack(anchor="w", padx=12, pady=4)

        def do_save():
            new_txt = new_entry.get("1.0", "end-1c")
            ok, msg = self.patcher.can_patch(entry, new_txt)
            if not ok:
                messagebox.showwarning("تنبيه", msg, parent=win)
                return
            ok2, msg2 = self.patcher.patch_string(entry.offset, new_txt)
            if ok2:
                messagebox.showinfo("تم", msg2, parent=win)
                win.destroy()
                self.filter_strings()
                self.status.config(text=f"✅ تم تعديل {hex(entry.offset)}")
            else:
                messagebox.showerror("خطأ", msg2, parent=win)

        btn_frame = ttk.Frame(win)
        btn_frame.pack(fill="x", padx=12, pady=12)
        tk.Button(btn_frame, text="💾 حفظ التعديل", bg="#2563eb", fg="white", font=("Segoe UI", 10, "bold"), padx=16, pady=6, relief="flat", command=do_save).pack(side="right", padx=4)
        ttk.Button(btn_frame, text="إلغاء", command=win.destroy).pack(side="right", padx=4)

    def batch_rename(self):
        if not self.patcher:
            messagebox.showwarning("تنبيه", "حمّل ملف أولاً")
            return
        old = self.old_name_var.get().strip()
        new = self.new_name_var.get().strip()
        if not old or not new:
            messagebox.showwarning("تنبيه", "أدخل الاسم القديم والجديد")
            return
        if old == new:
            messagebox.showinfo("تنبيه", "الاسمان متطابقان")
            return

        results = self.patcher.batch_rename(old, new)
        if not results:
            messagebox.showinfo("نتيجة", f"لم يوجد أي ظهور لـ '{old}'")
            return

        # عرض النتائج
        ok_count = sum(1 for _, msg in results if "✅" in msg)
        fail_count = len(results) - ok_count
        detail = "\n".join([f"{hex(off)} {msg}" for off, msg in results[:20]])
        if len(results) > 20:
            detail += f"\n... و {len(results)-20} أخرى"

        messagebox.showinfo("نتيجة Batch Rename", f"تم: {ok_count}  فشل: {fail_count}\n\n{detail}")
        self.filter_strings()
        self.status.config(text=f"Batch: {ok_count} تم، {fail_count} فشل")

    def populate_version_info(self):
        # مسح
        for w in self.ver_frame.winfo_children():
            w.destroy()
        self.ver_entries.clear()

        info = self.pe.get_pe_info() if self.pe else {}
        ver = self.pe.get_version_info() if self.pe else {}

        # PE info
        ttk.Label(self.ver_frame, text=f"PE Info: {info.get('machine','')} | Sections: {info.get('num_sections','')} | Entry: {info.get('entry_point','')}", foreground="#334155", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0,8))

        if not ver:
            ttk.Label(self.ver_frame, text="لم يتم العثور على VersionInfo (قد يكون البرنامج غير PE أو stripped). يمكنك البحث عن النصوص في تبويب النصوص وتعديلها يدوياً.", foreground="#64748b", wraplength=800).pack(anchor="w", pady=8)
            # اقترح حقول شائعة فارغة لإضافتها
            ver = {k: "" for k in ["CompanyName", "FileDescription", "FileVersion", "ProductName", "ProductVersion", "LegalCopyright", "OriginalFilename"]}

        # إنشاء حقول
        for key, val in ver.items():
            row = ttk.Frame(self.ver_frame)
            row.pack(fill="x", pady=3)
            ttk.Label(row, text=f"{key}:", width=18, anchor="w", font=("Segoe UI", 9, "bold")).pack(side="left")
            var = tk.StringVar(value=val)
            ent = ttk.Entry(row, textvariable=var, font=("Consolas", 9))
            ent.pack(side="left", fill="x", expand=True, padx=6)
            # زر تعديل
            def make_patch(k=key, v=var):
                txt = v.get().strip()
                if not self.patcher:
                    return
                # حاول تعديل
                old = self.pe.get_version_info().get(k, "")
                # إذا كان فارغ، نبحث عنkey نفسه?
                # نستخدم patcher للبحث عن old value
                if old:
                    # ابحث عن entry
                    for entry in self.patcher.strings:
                        if entry.original == old:
                            ok, msg = self.patcher.can_patch(entry, txt)
                            if not ok:
                                messagebox.showwarning("تنبيه", msg)
                                return
                            ok2, msg2 = self.patcher.patch_string(entry.offset, txt)
                            if ok2:
                                messagebox.showinfo("تم", f"{k}: {msg2}")
                                self.pe.version_info[k] = txt
                                self.filter_strings()
                            else:
                                messagebox.showerror("خطأ", msg2)
                            return
                    messagebox.showwarning("تنبيه", f"لم يوجد نص '{old}' في الجدول — عدّله من تبويب النصوص.")
                else:
                    # حاول البحث عن القيمة المدخلة كـ old?
                    messagebox.showinfo("معلومة", "هذا الحقل لم يكن موجوداً أصلاً. عدّل النصوص يدوياً من تبويب النصوص إذا كان يظهر هناك.")

            ttk.Button(row, text="✏️ تعديل", width=8, command=make_patch).pack(side="left", padx=2)
            self.ver_entries[key] = var

        # زر حفظ الكل
        ttk.Button(self.ver_frame, text="💾 حفظ كل حقول VersionInfo", command=self.save_all_version).pack(anchor="w", pady=10)

        # تحذير
        ttk.Label(self.ver_frame, text="ملاحظة: تغيير VersionInfo يغيّر ما يظهر في خصائص الملف (Properties) وقائمة البرامج.", foreground="#64748b", font=("Segoe UI", 8)).pack(anchor="w")

    def save_all_version(self):
        if not self.patcher:
            return
        count = 0
        for k, var in self.ver_entries.items():
            new_val = var.get().strip()
            old_val = self.pe.get_version_info().get(k, "")
            if new_val and new_val != old_val:
                # حاول
                for entry in self.patcher.strings:
                    if entry.original == old_val and old_val:
                        ok, msg = self.patcher.can_patch(entry, new_val)
                        if ok:
                            self.patcher.patch_string(entry.offset, new_val)
                            self.pe.version_info[k] = new_val
                            count += 1
                            break
        messagebox.showinfo("تم", f"تم تعديل {count} حقل")
        self.filter_strings()

    def save_file(self):
        has_jmp = hasattr(self, 'jmp_history') and self.jmp_history
        has_patches = self.patcher and self.patcher.patches
        if not has_patches and not has_jmp:
            messagebox.showwarning("تنبيه", "لم تقم بأي تعديل بعد")
            return
        out = self.output_var.get().strip().strip('"')
        if not out:
            messagebox.showwarning("تنبيه", "اختر مسار الحفظ")
            return
        out_path = pathlib.Path(out)

        # تحقق من تعديلات خطرة
        dangerous = [p for p in self.patcher.patches if any(self.patcher.find_string_at(off) and self.patcher.find_string_at(off).section in [".text", ".code"] for off in [p[0]])]
        if dangerous:
            if not messagebox.askyesno("تحذير", f"لديك {len(dangerous)} تعديل في قسم الكود (.text) — قد يمنع البرنامج من العمل!\n\nالأفضل تعديل نصوص في .rdata/.data/.rsrc فقط (تظهر باللون الأخضر).\n\nهل تريد المتابعة؟"):
                return

        # إذا كان المسار في Program Files بدون Admin، اقترح Desktop
        try:
            # تحقق من الكتابة
            if not os.access(str(out_path.parent), os.W_OK):
                # اقترح Desktop
                desktop = pathlib.Path.home() / "Desktop"
                if desktop.exists():
                    alt = desktop / out_path.name
                    if messagebox.askyesno("صلاحيات", f"لا يمكن الكتابة في:\n{out_path.parent}\n\nتحتاج Admin.\n\nهل تريد الحفظ على سطح المكتب بدلاً؟\n{alt}"):
                        out_path = alt
                        self.output_var.set(str(out_path))
            saved = self.patcher.save(out_path, fix_checksum=True)
            # تقرير
            rep = out_path.with_suffix(".patch_report.json")
            self.patcher.save_report(rep)

            # تحقق بعد الحفظ
            val = self.patcher.validate_patched()
            msg = f"✅ تم الحفظ:\n{saved}\n\nتقرير: {rep}\n\nعدد التعديلات: {len(self.patcher.patches)}\n"
            if val.get("pe_valid") == False:
                msg += f"\n⚠️ تحذير PE: {val['pe_errors']}"
            if val.get("packed", {}).get("packed"):
                msg += f"\n⚠️ مضغوط: {val['packed']['reasons']}"
            if val.get("dangerous_patches"):
                msg += f"\n⚠️ تعديلات خطرة: {val['dangerous_patches'][:2]}"

            msg += "\n\nتم إصلاح PE CheckSum تلقائياً."

            # عرض تشخيص
            messagebox.showinfo("تم", msg)
            self.status.config(text=f"✅ حُفظ {saved.name} — تم إصلاح CheckSum")

            # اختبار تشغيل سريع
            if messagebox.askyesno("اختبار", "هل تريد تجربة تشغيل البرنامج المعدّل الآن (اختبار سريع 3 ثواني)؟\nإذا كان لا يعمل سيظهر السبب."):
                self.test_run(saved)

            if messagebox.askyesno("فتح", "هل تريد فتح مجلد الملف الجديد؟"):
                try:
                    os.startfile(str(out_path.parent))
                except:
                    pass
        except PermissionError as e:
            messagebox.showerror("صلاحيات", f"ممنوع الكتابة هنا (تحتاج Admin):\n{e}\n\nالحل:\n1. احفظ على سطح المكتب\n2. أو كليك يمين على Patcher_GUI.bat → تشغيل كمسؤول")
        except Exception as e:
            import traceback
            messagebox.showerror("خطأ", f"فشل الحفظ:\n{e}\n\n{traceback.format_exc()}")

    def test_run(self, path):
        """يجرب تشغيل البرنامج المعدّل 3 ثواني ويعرض النتيجة"""
        import subprocess
        win = tk.Toplevel(self.root)
        win.title("اختبار التشغيل")
        win.geometry("700x400")
        txt = tk.Text(win, font=("Consolas", 9), bg="#f8fafc")
        txt.pack(fill="both", expand=True, padx=8, pady=8)
        txt.insert("1.0", f"تجربة تشغيل: {path}\n{'='*60}\n")
        win.update()

        def worker():
            try:
                # جرب تشغيل مع timeout 3 ثواني
                # للـ .py استخدم python، للـ .exe مباشرة
                if path.suffix.lower() in [".py", ".pyw"]:
                    cmd = [sys.executable, str(path), "--help"]
                else:
                    cmd = [str(path), "--help"]

                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    out, err = proc.communicate(timeout=3)
                    code = proc.returncode
                    txt.insert("end", f"Exit code: {code}\n")
                    txt.insert("end", f"STDOUT:\n{out[:1000]}\n")
                    txt.insert("end", f"STDERR:\n{err[:1000]}\n")
                    if code == 0:
                        txt.insert("end", "\n✅ البرنامج بدأ بنجاح (exit 0) — يبدو سليماً!\n")
                    else:
                        txt.insert("end", f"\n⚠️ خرج بكود {code} — قد يكون خطأ أو يحتاج وسائط مختلفة.\n")
                        txt.insert("end", "جرب تشغيله يدوياً من PowerShell لرؤية الخطأ الكامل.\n")
                except subprocess.TimeoutExpired:
                    proc.kill()
                    txt.insert("end", "⏱️ البرنامج اشتغل ولم ينته خلال 3 ثواني — تم إيقافه.\n")
                    txt.insert("end", "هذا طبيعي للبرامج التي تفتح نافذة — يعني أنه يعمل!\n")
                    txt.insert("end", "✅ الاختبار ناجح.\n")
            except FileNotFoundError as e:
                txt.insert("end", f"❌ فشل التشغيل: {e}\n")
                txt.insert("end", "قد يحتاج ملفات DLL بجانبه.\n")
            except Exception as e:
                txt.insert("end", f"❌ خطأ: {e}\n{traceback.format_exc()}\n")

            txt.insert("end", "\n" + "="*60 + "\n")
            txt.insert("end", "إذا كان البرنامج لا يشتغل بدون خطأ:\n")
            txt.insert("end", "1. جرب تعديل نص واحد فقط بنفس الطول تماماً\n")
            txt.insert("end", "2. تجنب نصوص في .text (حمراء) — عدّل الخضراء فقط (.rdata/.rsrc)\n")
            txt.insert("end", "3. تأكد أن البرنامج غير مضغوط (UPX)\n")
            txt.insert("end", "4. شغّله من PowerShell: .\\program_modified.exe  وشاهد الخطأ\n")

        threading.Thread(target=worker, daemon=True).start()

    def show_diff(self):
        if not self.patcher or not self.patcher.patches:
            messagebox.showinfo("معلومة", "لا توجد تعديلات")
            return
        win = tk.Toplevel(self.root)
        win.title("التعديلات")
        win.geometry("700x400")
        txt = tk.Text(win, font=("Consolas", 9), bg="#f8fafc")
        txt.pack(fill="both", expand=True, padx=8, pady=8)
        for d in self.patcher.get_diff():
            txt.insert("end", f"{d['offset']}: {d['old_text']} → {d['new_text']}\n")
            txt.insert("end", f"  old hex: {d['old_hex']}\n")
            txt.insert("end", f"  new hex: {d['new_hex']}\n\n")
        txt.config(state="disabled")

    def reset_patches(self):
        if not self.patcher:
            return
        if not self.patcher.patches:
            messagebox.showinfo("معلومة", "لا توجد تعديلات لإلغائها")
            return
        if messagebox.askyesno("تأكيد", f"إلغاء {len(self.patcher.patches)} تعديل والعودة للنسخة الأصلية؟"):
            # إعادة تحميل
            self.load_file()

def main():
    if not TK_AVAILABLE:
        print("Tkinter غير متوفر", file=sys.stderr)
        print("sudo apt install python3-tk  (Linux)", file=sys.stderr)
        sys.exit(1)
    if not PATCHER_AVAILABLE:
        print(f"فشل تحميل Patcher: {IMPORT_ERR}", file=sys.stderr)
        sys.exit(1)
    root = tk.Tk()
    try:
        root.tk.call("tk", "scaling", 1.1)
    except:
        pass
    app = PatcherGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
