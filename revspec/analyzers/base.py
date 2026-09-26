from __future__ import annotations
import abc
import datetime
import time
from typing import List

from ..core.types import AnalyzerResult, Finding
from ..core.context import AnalysisContext

class BaseAnalyzer(abc.ABC):
    """كل محلل يرث من هذه الفئة. يجب أن يكون id فريدًا."""

    name: str = "base"
    description: str = "Base analyzer"
    version: str = "1.0.0"
    # إذا كان المحلل يتطلب أدوات خارجية غير متوفرة فسيتم تخطيه
    requires_tools: List[str] = []

    def check_prereqs(self, ctx: AnalysisContext) -> tuple[bool, str]:
        from ..core.utils import which
        missing = [t for t in self.requires_tools if not which(t)]
        if missing:
            return False, f"missing tools: {', '.join(missing)}"
        return True, ""

    @abc.abstractmethod
    def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        ...

    # helper to create result shell
    def _result_shell(self) -> AnalyzerResult:
        now = datetime.datetime.utcnow().isoformat() + "Z"
        return AnalyzerResult(
            analyzer=self.name,
            version=self.version,
            started_at=now,
            finished_at=now,
            duration_ms=0,
            status="ok",
        )

    def run(self, ctx: AnalysisContext) -> AnalyzerResult:
        ok, reason = self.check_prereqs(ctx)
        if not ok:
            r = self._result_shell()
            r.status = "skipped"
            r.warnings.append(reason)
            return r
        t0 = time.time()
        started = datetime.datetime.utcnow().isoformat() + "Z"
        try:
            res = self.analyze(ctx)
            res.started_at = started
            res.finished_at = datetime.datetime.utcnow().isoformat() + "Z"
            res.duration_ms = int((time.time()-t0)*1000)
            # ensure analyzer/version correct
            res.analyzer = self.name
            res.version = self.version
            if not res.status:
                res.status = "ok"
            return res
        except Exception as e:
            import traceback
            r = self._result_shell()
            r.started_at = started
            r.finished_at = datetime.datetime.utcnow().isoformat() + "Z"
            r.duration_ms = int((time.time()-t0)*1000)
            r.status = "failed"
            r.errors.append(f"{e}: {traceback.format_exc()}")
            return r
