"""
Builds and runs the C++ tools' unit tests through the project's own runner,
so `pytest` covers the native code too.

Skips cleanly if no C++ compiler is available.
"""
import pathlib
import re
import shutil
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
TOOLS = REPO / "tools"


def _cxx():
    for c in ("g++", "clang++"):
        if shutil.which(c):
            return c
    return None


@pytest.fixture(scope="module")
def compiler():
    c = _cxx()
    if c is None:
        pytest.skip("no C++ compiler available")
    return c


def _build(compiler, source, out, tmp_path):
    exe = tmp_path / out
    r = subprocess.run(
        [compiler, "-O2", "-std=c++17", "-Wall", "-Wextra",
         str(TOOLS / source), "-o", str(exe)],
        capture_output=True, cwd=str(TOOLS),
    )
    assert r.returncode == 0, f"build failed:\n{r.stderr.decode()}"
    assert b"warning" not in r.stderr, f"build produced warnings:\n{r.stderr.decode()}"
    return exe


def test_serial_change_probe_unit_tests(compiler, tmp_path):
    exe = _build(compiler, "test_serial_change_probe.cpp", "test_probe", tmp_path)
    r = subprocess.run([str(exe)], capture_output=True)
    out = r.stdout.decode()
    assert r.returncode == 0, out
    m = re.search(r"(\d+) passed, (\d+) failed", out)
    assert m, f"no summary line in output:\n{out}"
    passed, failed = int(m.group(1)), int(m.group(2))
    assert failed == 0, out
    # guard against a no-op binary reporting success
    assert passed >= 20, f"expected a real test count, got {passed}:\n{out}"


def test_serial_change_probe_runs_read_only(compiler, tmp_path):
    exe = _build(compiler, "serial_change_probe.cpp", "probe", tmp_path)
    r = subprocess.run([str(exe)], capture_output=True)
    out = r.stdout.decode()
    # documented exit codes: 0 succeed, 2 blocked, 3 undetermined
    assert r.returncode in (0, 2, 3), f"unexpected exit {r.returncode}\n{out}"
    assert "ZERO MUTATION" in out
    assert "Mutations performed by this probe: 0" in out
    assert "RESULT:" in out


def test_single_file_covers_every_section(compiler, tmp_path):
    """One source file must produce every section the report promises."""
    exe = _build(compiler, "serial_change_probe.cpp", "probe_all", tmp_path)
    r = subprocess.run([str(exe)], capture_output=True)
    out = r.stdout.decode()
    for section in (">>> CURRENT SERIAL <<<",
                    "1. Identifier inventory",
                    "2. Entropy assessment",
                    "3. MTA target keys",
                    "4. Verdict",
                    "5. Hardening"):
        assert section in out, f"missing section {section!r}:\n{out}"
    # the current serial must be printed before the inventory
    assert out.index("CURRENT SERIAL") < out.index("Identifier inventory"), \
        "current serial must be printed first"


def test_tools_dir_is_a_single_source_file():
    """The user asked for one file: tools/ must hold exactly one .cpp tool."""
    sources = sorted(p.name for p in TOOLS.glob("*.cpp")
                     if not p.name.startswith("test_"))
    assert sources == ["serial_change_probe.cpp"], sources


def test_probe_source_contains_no_mutation_apis():
    """
    The shipped probe must not CALL any mutating API.

    Comments and string literals are stripped first: the header legitimately
    documents which APIs it avoids, and main() prints that list.
    """
    src = (TOOLS / "serial_change_probe.cpp").read_text(encoding="utf-8")

    code = re.sub(r"/\*.*?\*/", " ", src, flags=re.S)      # block comments
    code = re.sub(r"//[^\n]*", " ", code)                  # line comments
    code = re.sub(r'"(?:\\.|[^"\\])*"', '""', code)        # string literals
    code = re.sub(r"'(?:\\.|[^'\\])*'", "''", code)        # char literals

    forbidden = [
        "RegSetValueEx", "RegDeleteKey", "RegDeleteValue", "RegCreateKeyEx",
        "CredDelete", "CredWrite", "WriteProcessMemory", "CreateRemoteThread",
        "VirtualAllocEx", "QueueUserAPC", "SetThreadContext",
    ]
    for f in forbidden:
        hits = [m.start() for m in re.finditer(re.escape(f), code)]
        assert not hits, f"{f} appears in code: {code[hits[0]-60:hits[0]+40]!r}"

    # And it must actually use the read-only registry calls it claims to.
    for required in ("RegOpenKeyExW", "RegEnumValueW", "RegCloseKey"):
        assert required in code, f"{required} missing — probe is not reading anything"
