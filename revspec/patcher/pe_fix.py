#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PE Fix — إصلاح checksum و التحقق بعد التعديل
"""
import pathlib
import struct

def fix_pe_checksum(data: bytearray) -> bool:
    """
    يحسب ويصلح PE CheckSum (OptionalHeader.CheckSum)
    يعيد True إذا تم الإصلاح، False إذا ليس PE أو فشل
    Windows لا يفرضه لمعظم الـ exe لكن بعض البرامج تتحقق منه.
    """
    try:
        if len(data) < 0x40:
            return False
        if data[0:2] != b'MZ':
            return False
        # e_lfanew at 0x3C (4 bytes)
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        if e_lfanew + 6 > len(data):
            return False
        if data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
            return False
        # CheckSum offset: e_lfanew + 4 (PE sig) + 20 (FileHeader) + 64 (offset to CheckSum in OptionalHeader)
        # OptionalHeader starts at e_lfanew+24
        # CheckSum is at offset 64 from start of OptionalHeader
        # So absolute offset = e_lfanew + 24 + 64 = e_lfanew + 88
        checksum_offset = e_lfanew + 88
        # For PE32+ (64bit), same offset (CheckSum is at 64)
        if checksum_offset + 4 > len(data):
            return False

        # احسب checksum حسب خوارزمية Microsoft
        # صيغة: مجموع كل WORD (16-bit) + حجم الملف
        # نستخدم خوارزمية pefile إن توفر، وإلا نحسب مبسط
        try:
            import pefile
            # pefile تحسب بشكل دقيق
            # نحتاج كتابة مؤقتة لحساب checksum
            # نستخدم الطريقة المبسطة هنا لتجنب كتابة ملف
            pass
        except:
            pass

        # حساب مبسط (Microsoft spec):
        # Checksum = sum of all WORDs + file size, with carry handling
        # نضع CheckSum نفسه = 0 أثناء الحساب
        original_checksum = struct.unpack_from('<I', data, checksum_offset)[0]
        # صفر الحقل مؤقتاً
        struct.pack_into('<I', data, checksum_offset, 0)

        checksum = 0
        # حجم الملف
        # نحسب WORD by WORD
        # إذا كان الطول فردي، نضيف بايت أخير كـ WORD
        length = len(data)
        for i in range(0, length, 2):
            if i+1 < length:
                word = data[i] + (data[i+1] << 8)
            else:
                word = data[i]
            checksum = (checksum + word) & 0xFFFFFFFF
            # carry
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        # أضف حجم الملف
        checksum = (checksum + length) & 0xFFFFFFFF

        # اكتب القيمة الجديدة
        struct.pack_into('<I', data, checksum_offset, checksum)
        return True
    except Exception as e:
        print(f"fix_pe_checksum error: {e}")
        return False

def get_section_for_offset(data: bytes, offset: int) -> str:
    """يعيد اسم الـ section الذي يحتوي الـ offset (إن كان PE) — بطيء، يستخدم cache تلقائياً"""
    # استخدم cache لتحسين الأداء
    return get_section_for_offset_cached(data, offset)

# Cache للـ sections
_sections_cache = {}

def get_sections(data: bytes):
    """يعيد قائمة sections مرة واحدة (cached)"""
    # استخدم id + len كـ key بسيط
    key = (len(data), data[0:2], data[0x3C:0x40] if len(data) > 0x40 else b'')
    if key in _sections_cache:
        return _sections_cache[key]

    # حاول عبر pefile
    sections = []
    try:
        if data[0:2] != b'MZ':
            _sections_cache[key] = []
            return []
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
        for sec in pe.sections:
            name = sec.Name.decode(errors='ignore').strip('\x00')
            start = sec.PointerToRawData
            end = start + sec.SizeOfRawData
            sections.append((name, start, end))
        pe.close()
        _sections_cache[key] = sections
        return sections
    except:
        # fallback يدوي
        try:
            if data[0:2] != b'MZ':
                _sections_cache[key] = []
                return []
            import struct
            e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
            num_sections = struct.unpack_from('<H', data, e_lfanew+6)[0]
            opt_size = struct.unpack_from('<H', data, e_lfanew+20)[0]
            section_start = e_lfanew + 24 + opt_size
            for i in range(num_sections):
                off = section_start + i*40
                if off+40 > len(data):
                    break
                name = data[off:off+8].decode(errors='ignore').strip('\x00')
                raw_ptr = struct.unpack_from('<I', data, off+20)[0]
                raw_size = struct.unpack_from('<I', data, off+16)[0]
                sections.append((name, raw_ptr, raw_ptr+raw_size))
        except:
            pass
        _sections_cache[key] = sections
        return sections

def get_section_for_offset_cached(data: bytes, offset: int) -> str:
    """سريع — يستخدم cache"""
    # تحقق سريع: ليس PE
    if len(data) < 2 or data[0:2] != b'MZ':
        return "unknown"
    sections = get_sections(data)
    if not sections:
        # ليس PE أو header
        if offset < 0x1000:
            return "header"
        return "unknown"
    for name, start, end in sections:
        if start <= offset < end:
            return name
    return "header"

def validate_pe(data: bytes) -> dict:
    """يتحقق من صحة PE بعد التعديل"""
    result = {"valid": True, "errors": [], "warnings": []}
    if data[0:2] != b'MZ':
        result["valid"] = False
        result["errors"].append("ليس MZ header")
        return result
    try:
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        if data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
            result["valid"] = False
            result["errors"].append("ليس PE signature")
            return result
        # تحقق من sections
        import pefile
        pe = pefile.PE(data=data, fast_load=False)
        pe.close()
        result["warnings"].append(f"PE صالح: {len(pe.sections)} sections")
    except ImportError:
        result["warnings"].append("pefile غير مثبت — تحقق أساسي فقط")
    except Exception as e:
        result["valid"] = False
        result["errors"].append(f"PE تالف: {e}")
    return result

def is_packed_or_protected(data: bytes, strings_count: int) -> dict:
    """يكشف إذا كان الملف مضغوط/محمي (UPX, etc.)"""
    info = {"packed": False, "reasons": []}
    # تحقق من أسماء sections غريبة
    try:
        if data[0:2] == b'MZ':
            e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
            num_sections = struct.unpack_from('<H', data, e_lfanew+6)[0]
            opt_size = struct.unpack_from('<H', data, e_lfanew+20)[0]
            section_start = e_lfanew + 24 + opt_size
            suspicious = []
            for i in range(num_sections):
                off = section_start + i*40
                name = data[off:off+8].decode(errors='ignore').strip('\x00')
                if name in ["UPX0", "UPX1", ".packed", ".aspack", "Themida", ".petite"]:
                    suspicious.append(name)
                    info["packed"] = True
            if suspicious:
                info["reasons"].append(f"sections مشبوهة: {suspicious}")
    except:
        pass

    # إذا كان عدد النصوص قليل جداً بالنسبة للحجم، قد يكون مضغوط
    if strings_count < 10 and len(data) > 100*1024:
        info["packed"] = True
        info["reasons"].append(f"نصوص قليلة ({strings_count}) لحجم كبير ({len(data)//1024}KB) — احتمال ضغط/تشفير")

    # إنتروبي عالي
    try:
        import collections, math
        freq = collections.Counter(data[:50000])
        ent = -sum((c/len(data[:50000])) * math.log2(c/len(data[:50000])) for c in freq.values())
        if ent > 7.5:
            info["packed"] = True
            info["reasons"].append(f"إنتروبي عالي {ent:.2f} — احتمال تشفير/ضغط")
    except:
        pass

    return info
