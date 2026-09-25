import pathlib
import struct

def test_elf_detection():
    from revspec.analyzers.platform import detect_elf, detect_pe, detect_macho
    import tempfile, pathlib
    # Create minimal ELF
    with tempfile.NamedTemporaryFile(delete=False) as f:
        # ELF header: 7f 45 4c 46 02 01 01 00 ... e_type 2 (EXEC), e_machine 62 (x86-64)
        hdr = bytearray(64)
        hdr[0:4] = b"\x7fELF"
        hdr[4] = 2  # 64-bit
        hdr[5] = 1  # little
        hdr[6] = 1  # version
        hdr[7] = 0  # SystemV
        struct.pack_into("<H", hdr, 16, 2)  # e_type EXEC
        struct.pack_into("<H", hdr, 18, 62) # e_machine x86-64
        f.write(hdr)
        fname = f.name
    p = pathlib.Path(fname)
    try:
        d = detect_elf(p)
        assert d is not None
        assert d["format"] == "ELF"
        assert d["arch"] == "x86-64"
        assert d["bitness"] == 64
    finally:
        p.unlink(missing_ok=True)

def test_pe_detection_negative():
    from revspec.analyzers.platform import detect_pe
    import tempfile, pathlib
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"not a pe file")
        fname = f.name
    p = pathlib.Path(fname)
    try:
        assert detect_pe(p) is None
    finally:
        p.unlink(missing_ok=True)
