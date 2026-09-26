"""
اختبارات محلل serial_spoof (جهة الحماية).

المسار الموجب يستخدم العينة الحقيقية CSX.exe الموجودة في جذر المستودع.
المسار السالب يستخدم samples/demo_app/demo.c (ملف نصي عادي).
"""
import pathlib
import pytest

from revspec.core.context import AnalysisContext
from revspec.core.evidence import EvidenceStore
from revspec.core.types import SampleInfo, HostInfo, sha256_file
from revspec.analyzers.serial_spoof import (
    SerialSpoofAnalyzer, _parse_pe_sections, _extract_strings, _scan,
    SERIAL_INPUT_INDICATORS, SERIAL_MUTATION_APIS, INTENT_STRINGS, INJECTION_APIS,
)

REPO = pathlib.Path(__file__).resolve().parent.parent
CSX = REPO / "CSX.exe"


def _ctx(sample: pathlib.Path, tmp_path: pathlib.Path) -> AnalysisContext:
    store = EvidenceStore(tmp_path / "run")
    return AnalysisContext(
        sample_path=sample,
        sample=SampleInfo(path=str(sample), filename=sample.name,
                          size_bytes=sample.stat().st_size,
                          sha256=sha256_file(sample), sha1="x", md5="x"),
        host=HostInfo.collect({}),
        store=store,
        output_dir=store.run_dir,
    )


def _verdict(result):
    for f in result.findings:
        if f.id == "serial_spoof.verdict":
            return f.data["verdict"], f.data
    raise AssertionError("no verdict finding")


# ---------------------------------------------------------------- units ----

def test_parse_pe_sections_reads_table():
    data = CSX.read_bytes() if CSX.exists() else None
    if data is None:
        pytest.skip("CSX.exe not present")
    secs = _parse_pe_sections(data)
    names = [s["name"] for s in secs]
    assert names == [".text", ".mmap", ".rdata", ".data", ".fptable", ".rsrc", ".reloc"]
    mmap = next(s for s in secs if s["name"] == ".mmap")
    assert mmap["executable"] is True
    assert mmap["looks_like_code"] is True


def test_parse_pe_sections_rejects_non_pe():
    assert _parse_pe_sections(b"not a pe file at all") == []


def test_extract_strings_finds_utf16_and_ascii():
    blob = b"AAAA\x00" * 0 + "csxcheat.dll".encode("utf-16-le") + b"\x00\x00" + b"RegDeleteKeyA\x00"
    s = _extract_strings(blob)
    assert "csxcheat.dll" in s
    assert "RegDeleteKeyA" in s


def test_scan_weights_accumulate():
    corpus = "MachineGuid\nSELECT SerialNumber FROM Win32_BIOS\nRegDeleteKeyA\n"
    hits, score = _scan(corpus, SERIAL_INPUT_INDICATORS + SERIAL_MUTATION_APIS)
    assert score > 0
    assert {h["pattern"] for h in hits} >= {r"MachineGuid", r"SELECT\s+SerialNumber\s+FROM\s+Win32_"}


# ------------------------------------------------------- positive (CSX) ----

@pytest.mark.skipif(not CSX.exists(), reason="CSX.exe sample not in repo")
def test_detects_csx_as_serial_changer(tmp_path):
    an = SerialSpoofAnalyzer()
    res = an.run(_ctx(CSX, tmp_path))
    assert res.status == "ok"

    verdict, data = _verdict(res)
    assert verdict == "capable-serial-change", data
    assert data["serial_score"] >= an.SERIAL_STRONG_THRESHOLD
    assert data["injection_score"] >= an.INJECT_THRESHOLD

    ids = {f.id for f in res.findings}
    assert "serial_spoof.explicit_intent" in ids
    assert "serial_spoof.reads_hwid" in ids
    assert "serial_spoof.can_mutate" in ids
    assert "serial_spoof.injection_capability" in ids
    assert "serial_spoof.game_registry" in ids


@pytest.mark.skipif(not CSX.exists(), reason="CSX.exe sample not in repo")
def test_csx_manual_map_section_flagged(tmp_path):
    an = SerialSpoofAnalyzer()
    res = an.run(_ctx(CSX, tmp_path))
    sec = [f for f in res.findings if f.id == "serial_spoof.suspicious_section"]
    assert sec, "expected .mmap section finding"
    assert sec[0].data["name"] == ".mmap"


@pytest.mark.skipif(not CSX.exists(), reason="CSX.exe sample not in repo")
def test_evidence_written(tmp_path):
    an = SerialSpoofAnalyzer()
    ctx = _ctx(CSX, tmp_path)
    an.run(ctx)
    assert (ctx.store.run_dir / "evidence/serial_spoof/raw.json").exists()
    assert (ctx.store.run_dir / "evidence/serial_spoof/corpus.txt").exists()


# ------------------------------------------------------- negative paths ----

def test_benign_source_is_clean(tmp_path):
    demo = REPO / "samples/demo_app/demo.c"
    assert demo.exists()
    an = SerialSpoofAnalyzer()
    res = an.run(_ctx(demo, tmp_path))
    verdict, data = _verdict(res)
    assert verdict == "no-serial-change-indicator", data
    assert data["is_pe"] is False


def test_reads_hwid_without_mutation_is_not_flagged(tmp_path):
    """قراءة معرّفات وحدها (ترخيص/تسجيل دخول) لا يجب أن تُصنَّف كقدرة تغيير."""
    payload = (
        "SOFTWARE\\Microsoft\\Cryptography MachineGuid "
        "SELECT SerialNumber FROM Win32_BIOS ROOT\\CIMV2 Win32_DiskDrive"
    ).encode("utf-16-le")
    fake = tmp_path / "MZ_reader_only.bin"
    fake.write_bytes(b"MZ" + b"\x00" * 0x3a + (0x40).to_bytes(4, "little")
                     + b"PE\x00\x00" + b"\x4c\x01" + b"\x00\x00" + b"\x00" * 200 + payload)
    an = SerialSpoofAnalyzer()
    res = an.run(_ctx(fake, tmp_path))
    verdict, data = _verdict(res)
    assert verdict == "no-serial-change-indicator", data


def test_read_plus_delete_is_flagged(tmp_path):
    """قراءة معرّف + RegDeleteKeyW + نص نيّة = قدرة تغيير."""
    payload = (
        "SOFTWARE\\Microsoft\\Cryptography MachineGuid "
        "SELECT SerialNumber FROM Win32_BIOS "
        "SOFTWARE\\Multi Theft Auto\\1.6 "
        "RegDeleteKeyW CredDeleteW RegSetValueExW "
        "Resetting MTA serial... Serial reset complete"
    ).encode("utf-16-le")
    fake = tmp_path / "MZ_changer.bin"
    fake.write_bytes(b"MZ" + b"\x00" * 0x3a + (0x40).to_bytes(4, "little")
                     + b"PE\x00\x00" + b"\x4c\x01" + b"\x00\x00" + b"\x00" * 200 + payload)
    an = SerialSpoofAnalyzer()
    res = an.run(_ctx(fake, tmp_path))
    verdict, data = _verdict(res)
    assert verdict == "capable-serial-change", data


# ------------------------------------------------------ registration -------

def test_registered_in_default_pipeline():
    from revspec.core.pipeline import default_analyzers
    names = [a.name for a in default_analyzers()]
    assert "serial_spoof" in names
    # يجب أن يأتي بعد المحللات الثابتة وقبل الديناميكي
    assert names.index("serial_spoof") > names.index("behavior")
    assert names.index("serial_spoof") < names.index("dynamic")
