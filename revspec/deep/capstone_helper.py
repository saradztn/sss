#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Helper لاستخدام Capstone مع fallback إلى objdump
"""
import pathlib
import subprocess
import re
import struct
from typing import List, Dict, Optional, Tuple

def get_text_section_data(path: pathlib.Path) -> Tuple[bytes, int]:
    """
    يقرأ .text section مباشرة من PE/ELF
    يعيد (data, virtual_address)
    """
    data = path.read_bytes()
    # Try pefile for PE
    if data[:2] == b'MZ':
        try:
            import pefile
            pe = pefile.PE(data=data, fast_load=True)
            for sec in pe.sections:
                name = sec.Name.decode(errors='ignore').strip('\x00')
                if name == '.text':
                    # Read raw data
                    raw = sec.get_data()
                    va = sec.VirtualAddress
                    # ImageBase needed for absolute addresses
                    base = pe.OPTIONAL_HEADER.ImageBase
                    return raw, base + va
            # fallback: first executable section
            for sec in pe.sections:
                if sec.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                    return sec.get_data(), pe.OPTIONAL_HEADER.ImageBase + sec.VirtualAddress
        except Exception as e:
            pass
        # Fallback via manual parse (without pefile)
        try:
            e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
            num_sec = struct.unpack_from('<H', data, e_lfanew+6)[0]
            opt_size = struct.unpack_from('<H', data, e_lfanew+20)[0]
            sec_start = e_lfanew + 24 + opt_size
            for i in range(num_sec):
                off = sec_start + i*40
                name = data[off:off+8].decode(errors='ignore').strip('\x00')
                if name == '.text':
                    raw_ptr = struct.unpack_from('<I', data, off+20)[0]
                    raw_size = struct.unpack_from('<I', data, off+16)[0]
                    va = struct.unpack_from('<I', data, off+12)[0]
                    # ImageBase
                    img_base = struct.unpack_from('<I', data, e_lfanew+24+28)[0] if len(data) > e_lfanew+24+28+4 else 0x400000
                    return data[raw_ptr:raw_ptr+raw_size], img_base + va
        except:
            pass
        return b'', 0

    # ELF
    if data[:4] == b'\x7fELF':
        try:
            # Use readelf -W to avoid wrapping, one line per section
            out = subprocess.run(['readelf', '-S', '-W', str(path)], capture_output=True, text=True, encoding='utf-8', errors='ignore', timeout=5)
            for line in out.stdout.splitlines():
                if '.text' in line:
                    # Example: [15] .text PROGBITS 0000000000001110 001110 000710
                    m = re.search(r'\.text\s+\w+\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)', line)
                    if m:
                        va = int(m.group(1), 16)
                        off = int(m.group(2), 16)
                        size = int(m.group(3), 16)
                        # sanity: size should be reasonable (<10MB)
                        if 0 < size < 10*1024*1024 and off+size <= len(data):
                            return data[off:off+size], va
            # Fallback: try without -W (two lines)
            out2 = subprocess.run(['readelf', '-S', str(path)], capture_output=True, text=True, encoding='utf-8', errors='ignore', timeout=5)
            lines = out2.stdout.splitlines()
            for i, line in enumerate(lines):
                if '.text' in line and i+1 < len(lines):
                    # Combine two lines
                    combined = line + " " + lines[i+1]
                    m = re.search(r'\.text\s+\w+\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)', combined)
                    if m:
                        va = int(m.group(1), 16)
                        off = int(m.group(2), 16)
                        # size is on next line's first field after off
                        # Next line example: "       0000000000000710  0000000000000000 ..."
                        m2 = re.search(r'^\s+([0-9a-fA-F]+)\s+', lines[i+1])
                        if m2:
                            size = int(m2.group(1), 16)
                            if 0 < size < 10*1024*1024 and off+size <= len(data):
                                return data[off:off+size], va
        except:
            pass
        # Fallback: try via pyelftools if available
        try:
            from elftools.elf.elffile import ELFFile
            with open(path, 'rb') as f:
                elffile = ELFFile(f)
                sec = elffile.get_section_by_name('.text')
                if sec:
                    return sec.data(), sec['sh_addr']
        except:
            pass
        # Last fallback: assume .text at 0x1000, size 0x1000
        return data, 0

    # Unknown: return whole file (for shellcode)
    return data[:50000], 0

def disassemble_capstone(path: pathlib.Path, arch: str = "x86_64") -> List[Dict]:
    """
    يفكك باستخدام Capstone
    يعيد قائمة {address, bytes, mnemonic, op_str, size, group}
    """
    try:
        import capstone
        from capstone import CS_ARCH_X86, CS_MODE_64, CS_MODE_32

        raw, base = get_text_section_data(path)
        if not raw:
            return []

        # حد أقصى 2MB لتجنب التعلق
        raw = raw[:2*1024*1024]

        # Determine arch
        data = path.read_bytes()
        if data[:2] == b'MZ':
            # PE: check 64bit
            try:
                import pefile
                pe = pefile.PE(data=data, fast_load=True)
                is64 = pe.OPTIONAL_HEADER.Magic == 0x20b
                pe.close()
            except:
                is64 = True
        elif data[:4] == b'\x7fELF':
            is64 = data[4] == 2
        else:
            is64 = True

        cs = capstone.Cs(CS_ARCH_X86, CS_MODE_64 if is64 else CS_MODE_32)
        cs.detail = True

        insns = []
        for insn in cs.disasm(raw, base):
            # Group: control flow, stack, etc.
            groups = []
            try:
                for g in insn.groups:
                    groups.append(cs.group_name(g))
            except:
                pass
            # Category
            cat = "other"
            if insn.mnemonic.startswith('j') or insn.mnemonic in ('call','ret','jmp','je','jne','jg','jl','ja','jb','loop'):
                cat = "control"
            elif insn.mnemonic in ('push','pop','mov','lea','xchg'):
                cat = "data"
            elif insn.mnemonic in ('add','sub','mul','div','xor','and','or','shl','shr'):
                cat = "arith"
            elif insn.mnemonic in ('syscall','int','sysenter'):
                cat = "syscall"

            insns.append({
                "address": hex(insn.address),
                "addr_int": insn.address,
                "bytes": insn.bytes.hex(),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "size": insn.size,
                "group": groups,
                "category": cat,
            })
            if len(insns) > 50000:  # حد أقصى
                break
        return insns
    except ImportError as e:
        return [{"error": "capstone غير مثبت — ثبّت عبر: pip install capstone — " + str(e)}]
    except Exception as e:
        return [{"error": str(e)}]

def disassemble_objdump(path: pathlib.Path) -> List[Dict]:
    """
    Fallback عبر objdump -d
    """
    try:
        out = subprocess.run(['objdump', '-d', '-M', 'intel', str(path)], capture_output=True, text=True, encoding='utf-8', errors='ignore', timeout=15)
        if out.returncode != 0:
            return [{"error": f"objdump فشل (code {out.returncode}): {out.stderr[:200]}"}]
        insns = []
        # Parse objdump output: e.g.,  1110:  55                      push   rbp
        for line in out.stdout.splitlines():
            m = re.match(r'\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s)+)\s*(\w+)\s*(.*)', line)
            if m:
                addr = m.group(1)
                bytes_hex = m.group(2).strip().replace(' ', '')
                mnem = m.group(3)
                op = m.group(4).strip()
                insns.append({
                    "address": "0x" + addr,
                    "addr_int": int(addr, 16),
                    "bytes": bytes_hex,
                    "mnemonic": mnem,
                    "op_str": op,
                    "size": len(bytes_hex)//2,
                    "group": [],
                    "category": "other",
                })
                if len(insns) > 50000:
                    break
        return insns
    except FileNotFoundError as e:
        return [{"error": "objdump غير موجود على Windows — ثبّت capstone عبر: pip install capstone (لا يحتاج objdump)"}]
    except Exception as e:
        return [{"error": str(e)}]

def get_opcodes(path: pathlib.Path) -> Dict:
    """
    يحاول Capstone أولاً، ثم objdump
    """
    insns = disassemble_capstone(path)
    method = "capstone"
    # إذا كان capstone غير مثبت، لا تحاول objdump على Windows (سيعطي WinError 2 مربك)
    if insns and len(insns)==1 and "error" in insns[0] and "capstone غير مثبت" in insns[0]["error"]:
        return {"method": "capstone", "instructions": insns, "count": 0, "error": insns[0]["error"]}
    if not insns or (len(insns)==1 and "error" in insns[0]):
        # جرب objdump فقط إذا لم يكن الخطأ هو capstone غير مثبت
        fallback = disassemble_objdump(path)
        # إذا كان fallback أيضاً خطأ وغير مفيد، أبقِ خطأ capstone الأصلي
        if fallback and not (len(fallback)==1 and "error" in fallback[0] and "objdump غير موجود" in fallback[0]["error"]):
            insns = fallback
            method = "objdump"
        elif not insns:
            insns = fallback
            method = "objdump"
    return {"method": method, "instructions": insns, "count": len(insns)}