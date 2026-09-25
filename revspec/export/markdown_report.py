from __future__ import annotations
import pathlib
from typing import Dict, Any
from jinja2 import Environment, FileSystemLoader, select_autoescape

def render_markdown(result: Dict[str,Any], template_path: pathlib.Path, out_path: pathlib.Path, extra: Dict[str,Any]=None):
    env = Environment(
        loader=FileSystemLoader(str(template_path.parent)),
        autoescape=select_autoescape(enabled_extensions=(), default_for_string=False),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    # custom filter for confidence badge
    def badge(conf):
        m = {
            "proven": "✅ مُثبت",
            "high": "🔵 عالي",
            "medium": "🟡 متوسط",
            "low": "🟠 منخفض",
            "speculative": "🔴 تخميني",
            "unknown": "⚪ غير محدد",
        }
        return m.get(conf, conf)
    env.filters["badge"] = badge
    tmpl = env.get_template(template_path.name)
    # group findings by category
    findings = result.get("findings", [])
    by_cat = {}
    for f in findings:
        by_cat.setdefault(f["category"], []).append(f)
    # proven vs inferred
    proven = [f for f in findings if f["provenance"]=="observed"]
    inferred = [f for f in findings if f["provenance"]=="inferred"]
    undetermined = [f for f in findings if f["provenance"] in ("undetermined","absent")]

    rendered = tmpl.render(
        result=result,
        findings=findings,
        by_cat=by_cat,
        proven=proven,
        inferred=inferred,
        undetermined=undetermined,
        extra=extra or {},
    )
    out_path = pathlib.Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered, encoding="utf-8")
    return out_path
