from __future__ import annotations
import json
import pathlib
from ..core.types import PipelineResult

def export_json(result: PipelineResult, out_path: pathlib.Path):
    out_path = pathlib.Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, ensure_ascii=False, indent=2)

def export_yaml(result: PipelineResult, out_path: pathlib.Path):
    import yaml
    out_path = pathlib.Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(result.to_dict(), f, allow_unicode=True, sort_keys=False)
