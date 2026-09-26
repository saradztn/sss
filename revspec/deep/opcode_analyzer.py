#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Deep Opcode Analyzer — تفكيك عميق مثل Ghidra

يستخرج:
- كل الـ opcodes (push, mov, jump, call, etc.)
- Basic blocks و Control Flow Graph
- Functions (عبر symbols أو heuristics)
- Imports / Strings references
- تقرير كامل لإعادة البناء في C++
"""
import pathlib
import re
import json
import hashlib
from collections import Counter, defaultdict
from typing import List, Dict

from ..analyzers.base import BaseAnalyzer
from ..core.types import AnalyzerResult, Finding
from ..core.confidence import Confidence, Provenance
from ..core.context import AnalysisContext

class DeepOpcodeAnalyzer(BaseAnalyzer):
    name = "deep_opcode"
    description = "تفكيك عميق — opcodes, CFG, functions لإعادة البناء في C++"
    version = "2.0.0"
    requires_tools = []  # يعمل حتى بدون capstone (يستخدم objdump)

    def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        res = self._result_shell()
        p = ctx.sample_path
        raw = {}

        # 1) Disassemble
        from .capstone_helper import get_opcodes, get_text_section_data
        import subprocess

        try:
            op_result = get_opcodes(p)
            insns = op_result.get("instructions", [])
            method = op_result.get("method", "unknown")
            raw["method"] = method
            raw["total_instructions"] = len(insns)
        except Exception as e:
            res.status = "failed"
            res.errors.append(str(e))
            raw["error"] = str(e)
            insns = []
            method = "failed"

        if not insns or (insns and "error" in insns[0]):
            err = insns[0].get('error') if insns else 'لا يوجد .text — قد يكون الملف ليس PE/ELF صالح أو .text فارغ'
            # رسالة أوضح على Windows
            if 'capstone غير مثبت' in str(err):
                desc = f"capstone غير مثبت على Windows. ثبّت عبر:\n  pip install capstone pefile\nثم أعد التحليل. (objdump غير موجود على Windows بشكل افتراضي)"
            elif 'objdump غير موجود' in str(err):
                desc = f"capstone غير مثبت وobjdump غير متوفر على Windows. ثبّت:\n  pip install capstone pefile"
                err = "capstone مفقود + objdump غير موجود على Windows"
            else:
                desc = f"لم يتم التفكيك عبر {method}: {err}. تأكد أن الملف هو .exe/.dll صالح وحاول تثبيت capstone: pip install capstone pefile"
            res.findings.append(Finding(
                id="deep.no_disasm", category="disasm", title="تعذر التفكيك — capstone مفقود" if 'capstone' in str(err) else "تعذر التفكيك",
                description=desc,
                confidence=Confidence.UNKNOWN, provenance=Provenance.UNDETERMINED,
                source="deep:disasm", method=method,
                data={**raw, "error_detail": err, "hint": "pip install capstone pefile"}
            ))
            ctx.store.save_json(f"evidence/{self.name}/raw.json", raw)
            ctx.store.save_json(f"evidence/{self.name}/findings.json", [f.__dict__ for f in res.findings])
            res.raw = raw
            return res

        # حفظ opcodes الخام (مقتطف)
        # نحفظ أول 5000 فقط في evidence لتجنب الملف الضخم، والكامل في ملف منفصل
        ctx.store.save_json(f"evidence/{self.name}/opcodes_sample.json", {"sample": insns[:500], "method": method})
        # حفظ الكامل مضغوط
        try:
            import gzip
            full_path = ctx.store.run_dir / f"evidence/{self.name}/opcodes_full.json.gz"
            full_path.parent.mkdir(parents=True, exist_ok=True)
            with gzip.open(full_path, 'wt', encoding='utf-8') as f:
                json.dump(insns, f, ensure_ascii=False)
            raw["full_gz"] = str(full_path.relative_to(ctx.store.run_dir))
        except:
            pass

        # 2) تحليل إحصائيات opcodes
        mnems = [i["mnemonic"] for i in insns if "mnemonic" in i]
        counter = Counter(mnems)
        top20 = counter.most_common(20)
        raw["top_mnemonics"] = top20
        raw["unique_mnemonics"] = len(counter)

        # تصنيف
        cats = Counter(i.get("category","other") for i in insns)
        raw["categories"] = dict(cats)

        # 3) CFG: basic blocks
        # كل jump/call/ret ينهي block
        blocks = []
        current_block = []
        block_starts = set()
        # ابحث عن أهداف jump/call
        addr_to_idx = {ins["addr_int"]: idx for idx, ins in enumerate(insns) if "addr_int" in ins}

        for idx, ins in enumerate(insns):
            current_block.append(ins)
            mnem = ins.get("mnemonic","")
            # نهاية block إذا كان control flow
            if mnem in ('jmp','je','jne','jg','jl','ja','jb','jae','jbe','jo','jno','js','jns','call','ret','retn','jmpq','jeq','jne','hlt','int','syscall'):
                blocks.append(list(current_block))
                # الهدف كبداية block جديدة
                op = ins.get("op_str","")
                # حاول استخراج العنوان
                m = re.search(r'0x[0-9a-fA-F]+', op)
                if m:
                    try:
                        target = int(m.group(0), 16)
                        block_starts.add(target)
                    except:
                        pass
                current_block = []
            # أيضاً إذا كان التالي هو هدف jump سابق
            if idx+1 < len(insns) and insns[idx+1].get("addr_int") in block_starts:
                if current_block:
                    blocks.append(list(current_block))
                    current_block = []

        if current_block:
            blocks.append(current_block)

        raw["basic_blocks"] = len(blocks)
        raw["avg_block_size"] = round(len(insns)/len(blocks),2) if blocks else 0

        # 4) Functions detection
        # عبر symbols (nm) أو heuristics (push rbp; mov rbp, rsp)
        funcs = []
        # حاول عبر nm
        try:
            out = subprocess.run(['nm', '-S', str(p)], capture_output=True, text=True, encoding='utf-8', errors='ignore', timeout=5)
            if out.returncode == 0:
                for line in out.stdout.splitlines():
                    m = re.match(r'([0-9a-fA-F]+)\s+([0-9a-fA-F]+)?\s+(\w)\s+(.+)', line)
                    if m and m.group(3) in ('T','t','W','w'):
                        addr = int(m.group(1), 16)
                        name = m.group(4).strip()
                        funcs.append({"address": hex(addr), "name": name, "source": "nm"})
        except:
            pass

        # heuristics: ابحث عن prologue شائع (64-bit و 32-bit)
        if not funcs:
            # x86_64: push rbp; mov rbp,rsp  |  x86: push ebp; mov ebp,esp
            for idx, ins in enumerate(insns):
                is_push_rbp = ins.get("mnemonic") == "push" and ins.get("op_str") in ("rbp", "ebp")
                if is_push_rbp:
                    if idx+1 < len(insns):
                        nxt = insns[idx+1]
                        if nxt.get("mnemonic") == "mov" and ("rbp, rsp" in nxt.get("op_str","") or "ebp, esp" in nxt.get("op_str","")):
                            funcs.append({"address": ins["address"], "name": f"sub_{ins['address']}", "source": "heuristic"})
                            continue
                        # 32-bit often: push ebp; mov ebp,esp; push esi / sub esp
                        if nxt.get("mnemonic") in ("push", "sub", "mov", "and"):
                            # تأكيد أنه بداية دالة: بعد push ebp يأتي mov ebp,esp أو مباشرة push esi
                            # نتحقق من وجود mov ebp,esp خلال 3 تعليمات
                            window = insns[idx+1:idx+4]
                            if any(w.get("mnemonic")=="mov" and "ebp, esp" in w.get("op_str","") for w in window):
                                funcs.append({"address": ins["address"], "name": f"sub_{ins['address']}", "source": "heuristic32"})
                            elif nxt.get("mnemonic") == "push":
                                funcs.append({"address": ins["address"], "name": f"sub_{ins['address']}", "source": "heuristic2"})

        # حد أقصى 300 function
        funcs = funcs[:300]
        raw["functions"] = funcs
        raw["functions_count"] = len(funcs)

        # 5) Imports references: أي call إلى عناوين خارج .text (مثلاً PLT)
        # نبحث عن call 0x... حيث الهدف في نطاق imports
        imports = ctx.shared.get("imports", [])
        calls = [i for i in insns if i.get("mnemonic") in ('call','callq')]
        raw["calls_count"] = len(calls)
        # اربط call بآسم import إذا أمكن (عبر العنوان)
        # نحتاج إلى تحليل PLT — نبسط: أول 20 call
        raw["calls_sample"] = calls[:20]

        # 6) Strings references: أي lea/mov يشير إلى عنوان في .rodata
        # نبحث عن lea rdi, [rip + ...] أو mov
        string_refs = []
        for ins in insns:
            op = ins.get("op_str","")
            if "0x" in op and ins.get("mnemonic") in ('lea','mov','movabs','ldr'):
                # احتمال أنه يحمل عنوان string
                string_refs.append(ins)
                if len(string_refs) > 20:
                    break
        raw["string_refs_sample"] = string_refs

        # 7) إنشاء findings
        findings = []

        findings.append(Finding(
            id="deep.opcodes_summary", category="disasm", title=f"Opcodes ({method}) — {len(insns)} تعليمة",
            description=f"تم تفكيك {len(insns)} تعليمة عبر {method}. أهمها: {', '.join([f'{k}:{v}' for k,v in top20[:5]])} | Blocks: {len(blocks)} | Functions: {len(funcs)}",
            confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
            source=f"deep:{method}", method=f"{method} disassembly",
            data={"total": len(insns), "top": top20[:10], "blocks": len(blocks), "funcs": len(funcs), "cats": dict(cats)}
        ))

        findings.append(Finding(
            id="deep.functions", category="structure", title=f"Functions مكتشفة: {len(funcs)}",
            description="دوال عبر symbols أو prologue heuristics (push rbp; mov rbp,rsp)",
            confidence=Confidence.HIGH if any(f["source"]=="nm" for f in funcs) else Confidence.MEDIUM,
            provenance=Provenance.OBSERVED if funcs else Provenance.UNDETERMINED,
            source="deep:nm+heuristic", method="nm -S + prologue pattern",
            data={"functions": funcs[:20], "total": len(funcs)}
        ))

        findings.append(Finding(
            id="deep.cfg", category="behavior", title=f"Control Flow — {len(blocks)} basic blocks",
            description=f"متوسط {raw['avg_block_size']} تعليمة لكل block. Jumps/Calls تحدد التدفق.",
            confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
            source="deep:cfg", method="split on jmp/call/ret",
            data={"blocks": len(blocks), "avg": raw["avg_block_size"]}
        ))

        # تحذير إذا كان stripped
        if not funcs:
            findings.append(Finding(
                id="deep.stripped", category="disasm", title="لا يوجد symbols — stripped",
                description="البرنامج stripped، الدوال مستنتجة heuristics فقط. إعادة البناء ستحتاج تسمية يدوية.",
                confidence=Confidence.HIGH, provenance=Provenance.OBSERVED,
                source="deep:nm empty", method="nm returned empty",
                data={}
            ))

        # حفظ CFG عينة
        # نبني ملف DOT للـ CFG (لـ Graphviz)
        try:
            dot_lines = ["digraph CFG {"]
            for i, block in enumerate(blocks[:30]):  # أول 30 فقط
                label = f"Block{i}\\n{block[0]['address']}" if block else f"Block{i}"
                dot_lines.append(f'  B{i} [label="{label}"];')
                if i+1 < len(blocks[:30]):
                    dot_lines.append(f'  B{i} -> B{i+1};')
            dot_lines.append("}")
            ctx.store.save_text(f"evidence/{self.name}/cfg.dot", "\n".join(dot_lines))
        except:
            pass

        # 8) إنشاء C++ skeleton لكل function (لـ AI)
        cpp_skeleton = []
        for func in funcs[:20]:
            addr = func["address"]
            name = func["name"].replace(" ", "_").replace(".", "_")
            # ابحث عن instructions لهذه الدالة (حتى الدالة التالية)
            start_idx = next((i for i, ins in enumerate(insns) if ins["address"] == addr), 0)
            next_addr = funcs[funcs.index(func)+1]["address"] if funcs.index(func)+1 < len(funcs) else None
            end_idx = next((i for i, ins in enumerate(insns) if ins["address"] == next_addr), len(insns))
            body_insns = insns[start_idx:min(start_idx+50, end_idx)]  # أول 50
            # حول إلى تعليق C++
            asm_comment = "\n".join([f"    // {ins['address']}: {ins['bytes']:12} {ins['mnemonic']:8} {ins['op_str']}" for ins in body_insns[:15]])
            # calls في هذه الدالة فقط
            if next_addr:
                try:
                    nxt = int(next_addr, 16)
                    cur = int(addr, 16)
                    calls_in_func = [c['op_str'] for c in calls if cur <= c.get('addr_int', 0) < nxt][:3]
                except:
                    calls_in_func = []
            else:
                calls_in_func = []
            cpp = f"""
// Function at {addr} — original: {name}
void {name}() {{
{asm_comment}
    // TODO: lift to C++ based on opcodes above
    // calls: {calls_in_func}
}}
"""
            cpp_skeleton.append(cpp)

        raw["cpp_skeleton_preview"] = "\n".join(cpp_skeleton[:2])

        # حفظ skeleton كامل
        ctx.store.save_text(f"evidence/{self.name}/skeleton.cpp", "\n".join(cpp_skeleton))

        # 9) تقرير شامل للـ AI
        ai_report = {
            "summary": {
                "total_instructions": len(insns),
                "method": method,
                "top_mnemonics": top20,
                "categories": dict(cats),
                "blocks": len(blocks),
                "functions": funcs,
                "calls_sample": calls[:10],
            },
            "instructions_sample": insns[:200],  # أول 200 للـ AI
            "skeleton": cpp_skeleton,
        }
        ctx.store.save_json(f"evidence/{self.name}/ai_report.json", ai_report)

        # إضافة finding للـ AI
        findings.append(Finding(
            id="deep.ai_ready", category="disasm", title="تقرير جاهز لإعادة البناء في C++",
            description="يحتوي opcodes_full.json.gz + skeleton.cpp + ai_report.json — يمكن إرسالها لنموذج AI لبناء C++ مكافئ.",
            confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
            source="deep:export", method="capstone + skeleton gen",
            data={"files": ["opcodes_full.json.gz", "skeleton.cpp", "ai_report.json", "cfg.dot"]}
        ))

        # حفظ raw
        ctx.store.save_json(f"evidence/{self.name}/raw.json", raw)
        ctx.shared["deep_raw"] = raw
        ctx.shared["opcodes"] = insns

        res.findings = findings
        res.raw = raw
        res.status = "ok"
        return res