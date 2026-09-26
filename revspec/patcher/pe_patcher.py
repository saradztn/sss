#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PEPatcher — تعديل موارد PE (Windows .exe) مثل Version Info, Icon, Manifest

للبرامج التي تملكها فقط.
يعتمد على pefile إذا توفر، وإلا يستخدم طريقة البحث النصي.
"""
from __future__ import annotations
import pathlib
import re
import struct
from typing import Dict, List, Optional

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

class PEPatcher:
    def __init__(self, path: pathlib.Path):
        self.path = pathlib.Path(path)
        self.data = self.path.read_bytes()
        self.is_pe = self.data[:2] == b"MZ"
        self.version_info: Dict[str, str] = {}
        self._parse_version_info()

    def _parse_version_info(self):
        """يحاول استخراج FileVersion, ProductName, etc."""
        if PEFILE_AVAILABLE and self.is_pe:
            try:
                pe = pefile.PE(str(self.path), fast_load=False)
                if hasattr(pe, 'FileInfo'):
                    for fileinfo in pe.FileInfo:
                        for info in fileinfo:
                            if hasattr(info, 'StringTable'):
                                for st in info.StringTable:
                                    for key, val in st.entries.items():
                                        try:
                                            k = key.decode('utf-8', errors='ignore')
                                            v = val.decode('utf-8', errors='ignore') if isinstance(val, bytes) else str(val)
                                            self.version_info[k] = v
                                        except:
                                            pass
                            if hasattr(info, 'Var'):
                                pass
                pe.close()
            except Exception as e:
                # fallback to string search
                self._fallback_version_parse()
        else:
            self._fallback_version_parse()

    def _fallback_version_parse(self):
        """بحث نصي عن حقول VersionInfo"""
        # ابحث عن نصوص مثل FileVersion, ProductName, CompanyName etc.
        text = self.data.decode('utf-8', errors='ignore')
        # أيضاً utf16
        try:
            text16 = self.data.decode('utf-16le', errors='ignore')
        except:
            text16 = ""
        combined = text + "\n" + text16
        keys = ["FileVersion", "ProductVersion", "CompanyName", "ProductName", "FileDescription", "LegalCopyright", "OriginalFilename", "InternalName"]
        for k in keys:
            # ابحث عن k متبوعاً بقيمة قريبة
            # نمط بسيط: k ثم بايتات ثم القيمة
            # نستخدم regex للبحث عن k في البيانات الثنائية
            # pattern = re.compile(re.escape(k).encode('ascii') + rb'.{0,40}?' + rb'([A-Za-z0-9 _.\-]+)')  # unused, kept for reference
            # لكن أبسط: نبحث في النص المفكك
            if k in combined:
                # حاول استخراج القيمة التالية
                idx = combined.find(k)
                snippet = combined[idx:idx+200]
                # القيمة عادة بعد k بعدة بايتات null
                # نأخذ أول سطر بعد k يحتوي نص مفيد
                lines = snippet.split("\x00")
                for line in lines:
                    line = line.strip()
                    if line and line != k and len(line) > 2 and len(line) < 100:
                        # تجاهل إذا كان نفس المفتاح
                        if line not in keys:
                            self.version_info[k] = line
                            break

        # أيضاً ابحث عن نصوص تشبه الإصدار
        # مثلاً 1.0.0.0
        ver_re = re.compile(rb'\d+\.\d+\.\d+(?:\.\d+)?')
        for m in ver_re.finditer(self.data):
            # لا نحفظ هنا، فقط للعرض
            pass

    def get_version_info(self) -> Dict[str, str]:
        return dict(self.version_info)

    def is_pe_file(self) -> bool:
        return self.is_pe

    def get_pe_info(self) -> Dict:
        """معلومات PE أساسية"""
        if not self.is_pe:
            return {"is_pe": False, "reason": "Not MZ header"}
        info = {"is_pe": True}
        if PEFILE_AVAILABLE:
            try:
                pe = pefile.PE(str(self.path), fast_load=False)
                info.update({
                    "machine": hex(pe.FILE_HEADER.Machine),
                    "num_sections": pe.FILE_HEADER.NumberOfSections,
                    "timestamp": pe.FILE_HEADER.TimeDateStamp,
                    "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                    "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
                    "subsystem": pe.OPTIONAL_HEADER.Subsystem,
                    "is_dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),
                    "is_64bit": pe.OPTIONAL_HEADER.Magic == 0x20b,
                    "sections": [s.Name.decode().strip('\x00') for s in pe.sections],
                })
                pe.close()
            except Exception as e:
                info["error"] = str(e)
        else:
            info["pefile"] = "not installed, install with pip install pefile"
        return info

    def patch_version_string(self, patcher, key: str, new_value: str) -> bool:
        """
        يعدّل قيمة VersionInfo عبر البحث النصي.
        يستخدم BinaryPatcher للقيام بالتعديل الفعلي.
        """
        # نبحث عن القيمة القديمة في patcher.strings
        old_val = self.version_info.get(key)
        if not old_val:
            return False
        # ابحث عن entry التي تحتوي old_val
        for entry in patcher.strings:
            if old_val in entry.original:
                # حاول استبدال القيمة فقط، ليس المفتاح
                # إذا كان entry يحتوي القيمة بالضبط
                if entry.original == old_val:
                    ok, msg = patcher.can_patch(entry, new_value)
                    if ok:
                        patcher.patch_string(entry.offset, new_value)
                        self.version_info[key] = new_value
                        return True
                elif old_val in entry.original:
                    # استبدال جزئي
                    new_txt = entry.original.replace(old_val, new_value)
                    ok, msg = patcher.can_patch(entry, new_txt)
                    if ok:
                        patcher.patch_string(entry.offset, new_txt)
                        self.version_info[key] = new_value
                        return True
        return False