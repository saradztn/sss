from __future__ import annotations
import shutil
import subprocess
import pathlib
from typing import Optional, Dict

def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)

def run_cmd(cmd: list[str], timeout: int = 30, cwd: Optional[pathlib.Path]=None) -> Dict:
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, cwd=str(cwd) if cwd else None)
        return {"returncode": r.returncode, "stdout": r.stdout.decode(errors="ignore"), "stderr": r.stderr.decode(errors="ignore")}
    except FileNotFoundError as e:
        return {"returncode": 127, "stdout": "", "stderr": str(e)}
    except subprocess.TimeoutExpired as e:
        return {"returncode": 124, "stdout": (e.stdout or b"").decode(errors="ignore") if e.stdout else "", "stderr": "timeout"}

def tool_version(cmd: str, args=None) -> str:
    args = args or ["--version"]
    out = run_cmd([cmd] + args, timeout=5)
    txt = (out.get("stdout") or "") + (out.get("stderr") or "")
    return txt.strip().splitlines()[0] if txt.strip() else "unknown"

def safe_read(path: pathlib.Path, max_bytes=2_000_000) -> bytes:
    try:
        with path.open("rb") as f:
            return f.read(max_bytes)
    except Exception:
        return b""
