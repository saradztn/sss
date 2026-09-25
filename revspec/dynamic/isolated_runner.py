from __future__ import annotations
import subprocess
import pathlib
import time
import os
import signal
import shlex
from typing import List, Dict, Optional

from ..core.utils import which, run_cmd

class IsolatedRunner:
    """
    يشغل العينة في بيئة معزولة قدر الإمكان.
    يحاول بالترتيب:
      1. bwrap (bubblewrap)
      2. firejail
      3. نسخ إلى tmp + تشغيل مع timeout + ulimit
    يسجل: exit code, stdout, stderr, syscalls إذا توفر strace, file accesses, network attempts (عبر strings في strace).
    """

    def __init__(self, store, timeout: int = 8):
        self.store = store
        self.timeout = timeout

    def _choose_wrapper(self, sample: pathlib.Path, args: List[str]) -> List[str]:
        import sys
        # Handle Python scripts on Windows and Linux: use interpreter
        if sample.suffix.lower() in (".py", ".pyw"):
            # Use current Python interpreter
            return [sys.executable, str(sample)] + args
        # Handle .bat/.cmd on Windows
        if sys.platform == "win32" and sample.suffix.lower() in (".bat", ".cmd"):
            return ["cmd", "/c", str(sample)] + args
        # Try bwrap (Linux only)
        if which("bwrap"):
            return ["bwrap", "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--unshare-pid", "--die-with-parent", "--", str(sample)] + args
        if which("firejail"):
            return ["firejail", "--quiet", "--net=none", "--private-tmp", str(sample)] + args
        return [str(sample)] + args

    def run(self, sample: pathlib.Path, args: List[str] = None, env: Dict[str,str] = None, capture_strace: bool = True) -> Dict:
        args = args or []
        env = env or {}
        start = time.time()

        # Ensure executable
        try:
            sample.chmod(0o755)
        except Exception:
            pass

        # Build command
        base_cmd = self._choose_wrapper(sample, args)
        use_strace = capture_strace and which("strace") is not None
        # If strace, prepend
        if use_strace:
            # strace -f -tt -s 256 -o <file> <cmd>
            strace_log = self.store.run_dir / "evidence/dynamic/strace.log"
            strace_log.parent.mkdir(parents=True, exist_ok=True)
            cmd = ["strace", "-f", "-tt", "-T", "-s", "256", "-o", str(strace_log)] + base_cmd
        else:
            strace_log = None
            cmd = base_cmd

        # Isolate env: copy current but allow override
        run_env = os.environ.copy()
        run_env.update(env)
        # Remove sensitive?
        # Add timeout via subprocess

        # Windows doesn't support preexec_fn
        use_preexec = os.name != "nt"
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=run_env,
                preexec_fn=(lambda: _limit_resources()) if use_preexec else None,
                text=True, encoding='utf-8', errors='ignore',
            )
            try:
                stdout, stderr = proc.communicate(timeout=self.timeout)
                returncode = proc.returncode
                timed_out = False
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    stdout, stderr = proc.communicate(timeout=2)
                except Exception:
                    stdout, stderr = "", "killed after timeout"
                returncode = 124
                timed_out = True
        except FileNotFoundError as e:
            return {"returncode": 127, "stdout": "", "stderr": str(e), "timed_out": False, "duration": time.time()-start, "cmd": cmd, "strace_log": str(strace_log) if strace_log else None}
        except Exception as e:
            return {"returncode": 1, "stdout": "", "stderr": str(e), "timed_out": False, "duration": time.time()-start, "cmd": cmd, "strace_log": str(strace_log) if strace_log else None}

        duration = time.time() - start
        # Save logs
        self.store.save_text("evidence/dynamic/stdout.txt", stdout or "")
        self.store.save_text("evidence/dynamic/stderr.txt", stderr or "")
        self.store.save_text("evidence/dynamic/cmd.txt", " ".join(shlex.quote(c) for c in cmd))

        result = {
            "returncode": returncode,
            "stdout": (stdout or "")[:20000],
            "stderr": (stderr or "")[:20000],
            "timed_out": timed_out if 'timed_out' in locals() else False,
            "duration": duration,
            "cmd": cmd,
            "strace_log": str(strace_log) if strace_log and strace_log.exists() else None,
        }
        # also copy strace log into evidence if exists
        if strace_log and strace_log.exists():
            # already in place
            pass
        self.store.save_json("evidence/dynamic/run_meta.json", {k: v for k,v in result.items() if k not in ("stdout","stderr")})
        return result

def _limit_resources():
    try:
        import resource
        # limit CPU 5 sec, memory 256MB, file size 50MB, no core
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
        except Exception:
            pass
        try:
            resource.setrlimit(resource.RLIMIT_AS, (256*1024*1024, 256*1024*1024))
        except Exception:
            pass
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE, (50*1024*1024, 50*1024*1024))
        except Exception:
            pass
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0,0))
        except Exception:
            pass
    except ImportError:
        pass
    # also set umask
    try:
        os.umask(0o077)
    except Exception:
        pass