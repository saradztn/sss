#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BinaryPatcher — محرك تعديل النصوص في الملفات الثنائية

يدعم:
- ASCII و UTF-16LE (الأكثر شيوعاً في Windows)
- تعديل بنفس الطول أو أقصر (مع padding بـ \\x00)
- تغيير الاسم (batch replace)
- حفظ كنسخة جديدة مع backup

للاستخدام فقط على البرامج التي تملكها.
"""
from __future__ import annotations
import re
import pathlib
import dataclasses
from typing import List, Optional, Tuple

@dataclasses.dataclass
class StringEntry:
    offset: int          # offset في الملف
    encoding: str        # 'ascii' أو 'utf16le'
    original: str        # النص الأصلي
    length: int          # طول البايتات الأصلية
    raw: bytes           # البايتات الأصلية
    context: str = ""    # سياق (50 بايت قبل/بعد hex)
    section: str = ""    # اسم الـ section (مثل .rdata, .text) — للسلامة

    def to_dict(self):
        return {
            "offset": self.offset,
            "encoding": self.encoding,
            "original": self.original,
            "length": self.length,
            "hex_preview": self.raw.hex()[:40],
            "section": self.section,
        }

class BinaryPatcher:
    """
    محرر ثنائيات — يجد النصوص ويسمح بتعديلها.
    """
    def __init__(self, path: pathlib.Path):
        self.path = pathlib.Path(path)
        if not self.path.exists():
            raise FileNotFoundError(path)
        self.data = self.path.read_bytes()
        self.original_data = self.data  # نسخة للمقارنة
        self.strings: List[StringEntry] = []
        self.patches: List[Tuple[int, bytes, bytes]] = []  # (offset, old, new)
        self._find_strings()

    def _find_strings(self, min_len: int = 4):
        """يجد كل النصوص ASCII و UTF-16LE"""
        self.strings.clear()
        data = self.data

        # نحاول تحديد sections للسلامة
        try:
            from .pe_fix import get_section_for_offset
            has_section_info = True
        except:
            has_section_info = False
            get_section_for_offset = lambda d, o: "unknown"

        # ASCII: 4+ حروف قابلة للطباعة
        # نستخدم regex للسرعة
        ascii_re = re.compile(rb'[\x20-\x7E]{%d,}' % min_len)
        for m in ascii_re.finditer(data):
            s = m.group(0)
            try:
                txt = s.decode('ascii')
                # تجاهل النصوص التي تحتوي فقط أرقام أو رموز
                if len(txt.strip()) < min_len:
                    continue
                # فلترة: يجب أن يحتوي حرف أبجدي على الأقل
                if not re.search(r'[A-Za-z\u0600-\u06FF]', txt):
                    continue
                offset = m.start()
                # context
                ctx_start = max(0, offset-20)
                ctx_end = min(len(data), m.end()+20)
                ctx = data[ctx_start:ctx_end].hex()
                section = get_section_for_offset(data, offset) if has_section_info else "unknown"
                self.strings.append(StringEntry(
                    offset=offset,
                    encoding='ascii',
                    original=txt,
                    length=len(s),
                    raw=s,
                    context=ctx,
                    section=section
                ))
            except:
                pass

        # UTF-16LE: كل حرف 2 بايت، الثاني 0x00 لمعظم النصوص اللاتينية/العربية
        # نبحث عن نمط: (char 0x00) متكرر
        # أسرع: نستخدم find manual
        utf16_re = re.compile(rb'(?:[\x20-\x7E\xC0-\xFF]\x00){%d,}' % min_len)
        # أيضاً للعربية: \x06\x00-\x06\xFF ?
        for m in utf16_re.finditer(data):
            raw = m.group(0)
            # raw length must be even
            if len(raw) % 2 != 0:
                continue
            try:
                txt = raw.decode('utf-16le')
                # فلترة
                if len(txt.strip()) < min_len:
                    continue
                # تجنب التكرار مع ASCII (إذا كان النص ASCII أيضاً)
                # نتحقق إذا كان نفس الـ offset قريب من ASCII
                offset = m.start()
                # تجاهل إذا كان داخل ASCII already
                is_duplicate = any(abs(s.offset - offset) < 5 and s.original == txt for s in self.strings)
                if is_duplicate:
                    continue
                ctx_start = max(0, offset-20)
                ctx_end = min(len(data), m.end()+20)
                ctx = data[ctx_start:ctx_end].hex()
                section = get_section_for_offset(data, offset) if has_section_info else "unknown"
                self.strings.append(StringEntry(
                    offset=offset,
                    encoding='utf16le',
                    original=txt,
                    length=len(raw),
                    raw=raw,
                    context=ctx,
                    section=section
                ))
            except:
                pass

        # ترتيب حسب offset
        self.strings.sort(key=lambda x: x.offset)

    def get_strings(self, filter_text: str = "", encoding: str = "") -> List[StringEntry]:
        """إرجاع النصوص مع فلترة اختيارية"""
        result = self.strings
        if filter_text:
            ft = filter_text.lower()
            result = [s for s in result if ft in s.original.lower()]
        if encoding:
            result = [s for s in result if s.encoding == encoding]
        return result

    def find_string_at(self, offset: int) -> Optional[StringEntry]:
        for s in self.strings:
            if s.offset == offset:
                return s
        return None

    def can_patch(self, entry: StringEntry, new_text: str) -> Tuple[bool, str]:
        """هل يمكن تعديل النص؟ يتحقق من الطول"""
        # تحذير إذا كان في قسم الكود
        dangerous_sections = [".text", ".code", "CODE"]
        section_warning = ""
        if entry.section in dangerous_sections:
            section_warning = f" ⚠️ تحذير: هذا النص في قسم الكود ({entry.section}) — تعديله قد يوقف البرنامج! الأفضل تعديل نصوص في .rdata/.data/.rsrc فقط."

        if entry.encoding == 'ascii':
            new_bytes = new_text.encode('ascii', errors='ignore')
            # يجب أن لا يحتوي على أحرف غير ascii إذا كان الأصلي ascii
            if len(new_text.encode('ascii', errors='ignore')) != len(new_text):
                # يحتوي على non-ascii، لكن entry ascii — نحذر لكن نسمح بترميز utf8? الأفضل نرفض
                if any(ord(c) > 127 for c in new_text):
                    return False, "النص الجديد يحتوي أحرف غير ASCII بينما الأصلي ASCII. استخدم نفس اللغة أو اختار UTF-16LE." + section_warning
            if len(new_bytes) > entry.length:
                return False, f"النص الجديد أطول ({len(new_bytes)} بايت) من الأصلي ({entry.length} بايت). اختر نصاً أقصر أو بنفس الطول. يمكنك إضافة مسافات للحشو." + section_warning
            if len(new_bytes) == 0:
                return False, "النص الجديد فارغ"
            if section_warning:
                return True, "OK" + section_warning
            return True, "OK"
        elif entry.encoding == 'utf16le':
            new_bytes = new_text.encode('utf-16le')
            if len(new_bytes) > entry.length:
                return False, f"النص الجديد أطول UTF-16LE ({len(new_bytes)} بايت) من الأصلي ({entry.length} بايت)." + section_warning
            if section_warning:
                return True, "OK" + section_warning
            return True, "OK"
        return False, "ترميز غير مدعوم"

    def patch_string(self, offset: int, new_text: str, allow_truncate: bool = True) -> Tuple[bool, str]:
        """
        يعدّل نصاً في الذاكرة (لم يحفظ بعد).
        يعيد (نجاح, رسالة)
        """
        entry = self.find_string_at(offset)
        if not entry:
            return False, f"لا يوجد نص عند offset {hex(offset)}"
        ok, msg = self.can_patch(entry, new_text)
        if not ok:
            return False, msg

        # تحويل النص الجديد إلى بايتات مع padding
        if entry.encoding == 'ascii':
            new_bytes = new_text.encode('ascii', errors='ignore')
            # padding بـ \\x00
            padded = new_bytes + b'\x00' * (entry.length - len(new_bytes))
        else:  # utf16le
            new_bytes = new_text.encode('utf-16le')
            padded = new_bytes + b'\x00' * (entry.length - len(new_bytes))

        # تطبيق في الذاكرة
        # نحتاج إلى bytearray قابل للتعديل
        if isinstance(self.data, bytes):
            self.data = bytearray(self.data)
        # احفظ patch
        old = bytes(self.data[offset:offset+entry.length])
        self.data[offset:offset+entry.length] = padded
        self.patches.append((offset, old, padded))

        # تحديث entry في القائمة (للعرض)
        entry.original = new_text
        entry.raw = padded

        return True, f"تم تعديل {hex(offset)}: '{new_text}' ({len(padded)} بايت)"

    def batch_rename(self, old_name: str, new_name: str, case_sensitive: bool = False) -> List[Tuple[int, str]]:
        """
        يغيّر كل ظهور لاسم قديم إلى اسم جديد (بنفس الطول أو أقصر)
        يعيد قائمة (offset, حالة)
        """
        results = []
        # نبحث عن كل النصوص التي تحتوي old_name
        candidates = [s for s in self.strings if (old_name in s.original if case_sensitive else old_name.lower() in s.original.lower())]
        # أيضاً نبحث عن حالات حيث النص جزء من string أكبر (مثلاً "MyApp v1.0")
        # سنستخدم الاستبدال الجزئي إذا كان الطول يسمح
        for entry in candidates:
            # استبدال جزئي
            if case_sensitive:
                new_txt = entry.original.replace(old_name, new_name)
            else:
                # case-insensitive replace: نحتاج regex
                new_txt = re.sub(re.compile(re.escape(old_name), re.I), new_name, entry.original)
            # تحقق إذا كان new_txt نفس الطول أو أقصر
            ok, msg = self.can_patch(entry, new_txt)
            if ok:
                success, m = self.patch_string(entry.offset, new_txt)
                results.append((entry.offset, f"✅ {entry.original} → {new_txt}"))
            else:
                results.append((entry.offset, f"❌ {msg} — تخطي '{entry.original}'"))
        return results

    def save(self, output_path: pathlib.Path, make_backup: bool = True, fix_checksum: bool = True) -> pathlib.Path:
        """يحفظ الملف المعدّل — يصلح PE checksum تلقائياً"""
        output_path = pathlib.Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # إذا كان نفس الملف الأصلي، اعمل backup
        if output_path.resolve() == self.path.resolve() and make_backup:
            backup = self.path.with_suffix(self.path.suffix + ".bak")
            backup.write_bytes(self.original_data)
        
        # كتابة البيانات الجديدة
        if isinstance(self.data, bytearray):
            data_to_write = bytearray(self.data)
        else:
            data_to_write = bytearray(self.data)

        # إصلاح PE checksum تلقائياً
        if fix_checksum and len(data_to_write) > 0x40 and data_to_write[0:2] == b'MZ':
            try:
                from .pe_fix import fix_pe_checksum, validate_pe
                fixed = fix_pe_checksum(data_to_write)
                if fixed:
                    # للتشخيص
                    pass
            except Exception as e:
                print(f"checksum fix failed: {e}")

        output_path.write_bytes(bytes(data_to_write))
        # تحديث self.data إلى ما تم حفظه
        self.data = data_to_write
        return output_path

    def validate_patched(self) -> dict:
        """يتحقق من صحة الملف بعد التعديل"""
        data = bytes(self.data) if isinstance(self.data, bytearray) else self.data
        try:
            from .pe_fix import validate_pe, is_packed_or_protected, get_section_for_offset
            val = validate_pe(data)
            packed = is_packed_or_protected(data, len(self.strings))
            # تحقق من التعديلات الخطرة
            dangerous = []
            for off, old, new in self.patches:
                sec = get_section_for_offset(data, off)
                if sec in [".text", ".code", "CODE", ".UPX0", ".UPX1"]:
                    dangerous.append(f"{hex(off)} في {sec} — خطر")
            return {
                "pe_valid": val["valid"],
                "pe_errors": val["errors"],
                "pe_warnings": val["warnings"],
                "packed": packed,
                "dangerous_patches": dangerous,
                "total_patches": len(self.patches),
            }
        except Exception as e:
            return {"error": str(e), "total_patches": len(self.patches)}

    def get_diff(self) -> List[dict]:
        """يعيد قائمة التعديلات"""
        return [
            {
                "offset": hex(off),
                "old_hex": old.hex()[:40],
                "new_hex": new.hex()[:40],
                "old_text": old.decode('ascii', errors='ignore')[:30],
                "new_text": new.decode('ascii', errors='ignore')[:30],
            }
            for off, old, new in self.patches
        ]

    def save_report(self, output_path: pathlib.Path):
        """يحفظ تقرير التعديلات كـ JSON"""
        import json
        report = {
            "original": str(self.path),
            "patches": self.get_diff(),
            "total": len(self.patches),
        }
        output_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        return output_path
