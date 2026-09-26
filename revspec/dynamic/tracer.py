from __future__ import annotations
import re
import pathlib
from typing import Dict, List

from ..analyzers.base import BaseAnalyzer
from ..core.types import AnalyzerResult, Finding
from ..core.confidence import Confidence, Provenance
from ..core.context import AnalysisContext
from ..core.utils import which
from .isolated_runner import IsolatedRunner

class DynamicAnalyzer(BaseAnalyzer):
    name = "dynamic"
    description = "تحليل ديناميكي معزول: تشغيل العينة وتتبع السلوك"
    version = "1.0.0"

    def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        res = self._result_shell()
        # Dynamic analysis is opt-in; if not enabled, skip but explain
        if not ctx.options.get("enable_dynamic", False):
            res.status = "skipped"
            res.warnings.append("Dynamic analysis disabled (enable with --enable-dynamic).")
            res.findings.append(Finding(
                id="dynamic.skipped", category="dynamic", title="تم تخطي التحليل الديناميكي",
                description="التحليل الديناميكي معطل افتراضياً لتجنب تنفيذ كود غير موثوق. فعّله صراحة مع --enable-dynamic بعد التأكد من العزل.",
                confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
                source="dynamic:opt-in", method="ctx.options.enable_dynamic == False",
                data={}
            ))
            return res

        # Safety checks
        p = ctx.sample_path
        # Don't run if file is obviously non-executable script without shebang?
        # We'll attempt anyway but with timeout.

        runner = IsolatedRunner(ctx.store, timeout=int(ctx.options.get("dynamic_timeout", 8)))
        args = ctx.options.get("dynamic_args", [])
        if isinstance(args, str):
            import shlex
            args = shlex.split(args)

        # Check if binary is executable format
        run_result = runner.run(p, args=args, capture_strace=True)

        raw = {
            "returncode": run_result["returncode"],
            "timed_out": run_result["timed_out"],
            "duration": run_result["duration"],
            "cmd": run_result["cmd"],
        }
        findings = []

        # Basic execution finding
        if run_result["timed_out"]:
            findings.append(Finding(
                id="dynamic.timeout", category="dynamic", title="انتهت المهلة أثناء التنفيذ",
                description=f"العملية لم تنته خلال {runner.timeout}s وتم قتلها",
                confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
                source="dynamic:runner", method="subprocess timeout",
                data={"returncode": 124, "duration": run_result["duration"]}
            ))
        else:
            findings.append(Finding(
                id="dynamic.exit_code", category="dynamic", title="رمز الخروج",
                description=f"exit code = {run_result['returncode']}",
                confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
                source="dynamic:runner", method="waitpid",
                data={"returncode": run_result["returncode"], "duration": run_result["duration"]}
            ))

        # stdout/stderr preview
        stdout = run_result.get("stdout","")
        stderr = run_result.get("stderr","")
        raw["stdout_preview"] = stdout[:2000]
        raw["stderr_preview"] = stderr[:2000]
        findings.append(Finding(
            id="dynamic.stdout", category="dynamic", title="مخرجات stdout",
            description=stdout[:500] if stdout else "(لا يوجد stdout)",
            confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
            source="dynamic:runner", method="capture stdout",
            data={"stdout": stdout[:2000]}
        ))
        findings.append(Finding(
            id="dynamic.stderr", category="dynamic", title="مخرجات stderr",
            description=stderr[:500] if stderr else "(لا يوجد stderr)",
            confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
            source="dynamic:runner", method="capture stderr",
            data={"stderr": stderr[:2000]}
        ))

        # Parse strace if available
        strace_path = run_result.get("strace_log")
        if strace_path and pathlib.Path(strace_path).exists():
            try:
                text = pathlib.Path(strace_path).read_text(errors="ignore")
                raw["strace_lines"] = len(text.splitlines())
                raw["strace_preview"] = text[:3000]
                ctx.store.save_text("evidence/dynamic/strace_preview.txt", text[:20000])

                # parse syscalls
                syscalls = re.findall(r"\b([a-z_]+)\(", text)
                from collections import Counter
                cnt = Counter(syscalls)
                raw["syscall_counts"] = dict(cnt.most_common(50))
                # file accesses
                files = re.findall(r'open(?:at)?\([^"]*"([^"]+)"', text)
                files += re.findall(r'stat\([^"]*"([^"]+)"', text)
                uniq_files = list(dict.fromkeys(files))[:100]
                raw["accessed_files"] = uniq_files
                # network
                net = []
                if "socket(" in text: net.append("socket")
                if "connect(" in text: net.append("connect")
                if "bind(" in text: net.append("bind")
                if "listen(" in text: net.append("listen")
                raw["network_syscalls"] = net
                # exec
                execs = re.findall(r'execve\("([^"]+)"', text)
                raw["execve_targets"] = execs

                findings.append(Finding(
                    id="dynamic.syscalls", category="dynamic", title="Syscalls مرصودة",
                    description=f"{len(cnt)} نوع syscall، الأكثر: {', '.join([f'{k}:{v}' for k,v in cnt.most_common(5)])}",
                    confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
                    source="dynamic:strace", method="strace -f -tt",
                    data={"counts": dict(cnt.most_common(20)), "total_lines": len(text.splitlines())}
                ))
                if uniq_files:
                    findings.append(Finding(
                        id="dynamic.file_access", category="dynamic", title="ملفات تم الوصول إليها",
                        description=f"{len(uniq_files)} مسار فريد",
                        confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
                        source="dynamic:strace", method="regex open/stat",
                        data={"files": uniq_files[:50]}
                    ))
                if net:
                    findings.append(Finding(
                        id="dynamic.network", category="dynamic", title="نشاط شبكة",
                        description="تم رصد استدعاءات شبكة",
                        confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
                        source="dynamic:strace", method="socket/connect detection",
                        data={"network_syscalls": net}
                    ))
                else:
                    findings.append(Finding(
                        id="dynamic.no_network", category="dynamic", title="لا يوجد نشاط شبكة مرصود",
                        description="لم يتم رصد socket/connect/bind",
                        confidence=Confidence.HIGH, provenance=Provenance.OBSERVED,
                        source="dynamic:strace", method="negative search",
                        data={}
                    ))
            except Exception as e:
                raw["strace_parse_error"] = str(e)
                findings.append(Finding(
                    id="dynamic.strace_error", category="dynamic", title="خطأ تحليل strace",
                    description=str(e),
                    confidence=Confidence.MEDIUM, provenance=Provenance.OBSERVED,
                    source="dynamic:strace", method="parse",
                    data={}
                ))
        else:
            if which("strace") is None:
                findings.append(Finding(
                    id="dynamic.no_strace", category="dynamic", title="strace غير متوفر",
                    description="لا يمكن تتبع syscalls بدون strace",
                    confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
                    source="dynamic:missing", method="which strace",
                    data={}
                ))
            else:
                findings.append(Finding(
                    id="dynamic.no_strace_log", category="dynamic", title="لم يتم إنشاء سجل strace",
                    description="قد يكون bwrap/firejail منع strace أو فشل التنفيذ",
                    confidence=Confidence.MEDIUM, provenance=Provenance.OBSERVED,
                    source="dynamic:strace", method="check file exists",
                    data={}
                ))

        # Compare expected vs observed behavior guidance
        findings.append(Finding(
            id="dynamic.limitation", category="dynamic", title="قيود التحليل الديناميكي",
            description="السلوك المرصود يعتمد على المدخلات المقدمة والبيئة المعزولة؛ قد يختلف بمدخلات أخرى. لا يشمل كل المسارات.",
            confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
            source="dynamic:disclaimer", method="design",
            data={}
        ))

        ctx.store.save_json(f"evidence/{self.name}/raw.json", raw)
        ctx.shared["dynamic_raw"] = raw
        res.findings = findings
        res.raw = raw
        res.status = "ok"
        return res
