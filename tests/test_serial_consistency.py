"""
اختبارات revspec.protection.serial_consistency — منطق الحماية نفسه.

كل الحالات هنا **سجلّات قراءات مُصنَّعة**: لا يوجد تزوير حقيقي ولا تعديل
معرّفات في أي اختبار. هذا هو المقصود — منطق الكشف يُختبر بمدخلات، لا بأدوات.
"""
import json

import pytest

from revspec.protection.serial_consistency import (
    Reading, Verdict, analyze_history, load_history, evaluate_transition, classify,
    IdentifierClass, FULL_CHANGE_RATIO,
)


def R(sid, **ident):
    serial = ident.pop("client_serial", None)
    return Reading(session_id=sid, timestamp=f"2026-01-0{len(sid)}T00:00:00Z",
                   identifiers=dict(ident), client_serial=serial)


# baseline: كل المعرّفات متاحة وثابتة
BASE = dict(
    machine_guid="guid-aaaa", bios_serial="bios-1111", board_serial="board-2222",
    disk_serial="disk-3333", mac_address="aa:bb:cc:dd:ee:ff",
    volume_serial="1A2B-3C4D", sso_rnd_device="rnd-9999",
    install_date="1700000000", computer_name="PC-01", user_name="player",
)


def baseline(**over):
    d = dict(BASE); d.update(over); return d


# ------------------------------------------------------------ classification --

def test_classification_is_safe_by_default():
    assert classify("machine_guid") is IdentifierClass.VOLATILE
    assert classify("bios_serial") is IdentifierClass.ANCHOR
    assert classify("sso_rnd_device") is IdentifierClass.MARKER
    # معرّف غير معروف يُعامل كأسوأ حالة (طيّع) لا كمرساة
    assert classify("something_new") is IdentifierClass.VOLATILE


# ------------------------------------------------------------------ baseline --

def test_consistent_when_nothing_changes():
    rep = analyze_history([R("s1", **baseline()), R("s2", **baseline())])
    assert rep.worst_verdict is Verdict.CONSISTENT
    assert rep.action == "allow"
    assert rep.transitions[0].changed == []


def test_insufficient_data_with_one_reading():
    rep = analyze_history([R("s1", **baseline())])
    assert rep.worst_verdict is Verdict.INSUFFICIENT_DATA
    assert rep.action == "insufficient-data"
    assert rep.transitions == []


# ------------------------------------------------- the CSX signature pattern --

def test_machine_guid_only_change_is_spoof():
    """التوقيع الأساسي: MachineGuid تغيّر والمراسي كلها ثابتة."""
    rep = analyze_history([
        R("s1", **baseline()),
        R("s2", **baseline(machine_guid="guid-bbbb")),
    ])
    assert rep.worst_verdict is Verdict.SPOOF_PARTIAL
    assert rep.transitions[0].volatiles_changed == ["machine_guid"]
    assert rep.transitions[0].anchors_changed == []
    assert rep.worst_confidence >= 0.8
    assert rep.action in ("require-reauth", "block", "flag")


def test_sso_marker_delete_then_regenerate_is_reset():
    """النمط الكامل لـ CSX: حذف SSO_RND_Device ثم ظهوره بقيمة جديدة."""
    rep = analyze_history([
        R("s1", **baseline()),
        R("s2", **baseline(sso_rnd_device=None)),          # حُذف
        R("s3", **baseline(sso_rnd_device="rnd-0000")),    # أُعيد توليده
    ])
    assert rep.worst_verdict is Verdict.SPOOF_RESET
    t = rep.transitions[1]
    assert t.reappeared_changed == ["sso_rnd_device"]
    assert rep.action == "block"


def test_full_csx_pattern_blocks():
    """كل ما يفعله CSX دفعة واحدة — يجب أن يُحظر."""
    rep = analyze_history([
        R("s1", **baseline(mta_serial="MTA-OLD", client_serial="SER-OLD")),
        R("s2", **baseline(machine_guid="guid-bbbb", mta_serial=None,
                           sso_rnd_device=None, client_serial="SER-NEW")),
        R("s3", **baseline(machine_guid="guid-bbbb", mta_serial="MTA-NEW",
                           sso_rnd_device="rnd-0000", client_serial="SER-NEW")),
    ])
    assert rep.worst_verdict is Verdict.SPOOF_RESET
    assert rep.action == "block"
    # المراسي لم تتغيّر في أي انتقال
    assert all(t.anchors_changed == [] for t in rep.transitions)


def test_serial_changed_without_any_input_change():
    rep = analyze_history([
        R("s1", **baseline(), client_serial="SER-A"),
        R("s2", **baseline(), client_serial="SER-B"),
    ])
    assert rep.worst_verdict is Verdict.DERIVATION_TAMPER
    assert rep.action == "block"
    assert rep.transitions[0].changed == []


# ------------------------------------------------------------ benign patterns --

def test_full_reinstall_is_legit_change():
    """إعادة تثبيت فعلية: كل المعرّفات تتغيّر دفعة واحدة."""
    rep = analyze_history([
        R("s1", **baseline()),
        R("s2", machine_guid="g2", bios_serial="b2", board_serial="bo2",
            disk_serial="d2", mac_address="11:22:33:44:55:66",
            volume_serial="9Z8Y-7X6W", sso_rnd_device="r2",
            install_date="1800000000", computer_name="PC-02", user_name="u2"),
    ])
    t = rep.transitions[0]
    assert rep.worst_verdict is Verdict.LEGIT_CHANGE
    assert len(t.changed) / len(BASE) >= FULL_CHANGE_RATIO
    assert rep.action == "allow-with-note"


def test_real_hardware_change_is_flagged_not_blocked():
    """تغيير قرص فعلي: المرسى disk_serial يتغيّر → ليس تزويراً."""
    rep = analyze_history([
        R("s1", **baseline()),
        R("s2", **baseline(disk_serial="disk-NEW")),
    ])
    assert rep.worst_verdict is Verdict.HARDWARE_CHANGE
    assert rep.action == "require-reauth"


def test_computer_name_only_change_is_still_suspicious():
    """اسم الجهاز طيّع — تغيّره وحده لا يفسّر تغيّر serial."""
    rep = analyze_history([
        R("s1", **baseline()),
        R("s2", **baseline(computer_name="PC-RENAMED")),
    ])
    assert rep.worst_verdict is Verdict.SPOOF_PARTIAL


# --------------------------------------------------------------- edge cases --

def test_missing_identifier_is_not_a_change():
    """معرّف غير متاح في القراءتين معاً لا يُحسب تغيّراً."""
    a = baseline(); a.pop("bios_serial")
    rep = analyze_history([R("s1", **a), R("s2", **a)])
    assert rep.worst_verdict is Verdict.CONSISTENT


def test_identifier_appearing_after_being_unreadable():
    """
    فشل قراءة BIOS في جلسة ثم نجاحها في التالية **ليس** تغيير عتاد.
    لا توجد قيمة قديمة للمقارنة، فلا يُحسب تغيّراً.
    """
    a = baseline(bios_serial=None)
    rep = analyze_history([R("s1", **a), R("s2", **baseline())])
    t = rep.transitions[0]
    assert t.changed == []
    assert t.appeared == ["bios_serial"]
    assert t.anchors_changed == []
    assert rep.worst_verdict is Verdict.CONSISTENT
    assert rep.transitions[0].reappeared_changed == []


def test_marker_appearing_first_time_is_not_reset():
    """أول توليد للعلامة (لم تكن موجودة أصلاً) سلوك طبيعي، ليس إعادة ضبط."""
    rep = analyze_history([
        R("s1", **baseline(sso_rnd_device=None)),
        R("s2", **baseline(sso_rnd_device="rnd-first")),
    ])
    t = rep.transitions[0]
    assert t.reappeared_changed == []
    assert t.appeared == ["sso_rnd_device"]
    assert t.changed == []
    assert rep.worst_verdict is Verdict.CONSISTENT


def test_marker_disappearing_alone_is_noted_not_blocked():
    """
    اختفاء علامة في جلسة واحدة = النصف الأول من نمط إعادة الضبط.
    يُسجَّل كملاحظة؛ الحكم القاطع يحتاج رؤية إعادة التوليد.
    """
    rep = analyze_history([
        R("s1", **baseline(mta_serial="MTA-OLD")),
        R("s2", **baseline(mta_serial=None)),
    ])
    t = rep.transitions[0]
    assert t.disappeared == ["mta_serial"]
    assert t.reappeared_changed == []
    assert any("النصف الأول" in r for r in t.reasons)


def test_worst_transition_wins_over_multiple():
    rep = analyze_history([
        R("s1", **baseline()),
        R("s2", **baseline(computer_name="PC-X")),   # spoof-partial
        R("s3", **baseline(computer_name="PC-X")),   # consistent
    ])
    assert rep.worst_verdict is Verdict.SPOOF_PARTIAL
    assert rep.transitions[1].verdict is Verdict.CONSISTENT


def test_report_serialization_is_json_safe():
    rep = analyze_history([R("s1", **baseline()),
                           R("s2", **baseline(machine_guid="g2"))])
    s = json.dumps(rep.to_dict(), ensure_ascii=False)
    assert "spoof-partial" in s
    assert "machine_guid" in s


def test_load_history_from_file(tmp_path):
    payload = {"readings": [
        {"session_id": "s1", "timestamp": "t1", "identifiers": baseline()},
        {"session_id": "s2", "timestamp": "t2",
         "identifiers": baseline(machine_guid="guid-zzzz")},
    ]}
    p = tmp_path / "history.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    readings = load_history(p)
    assert len(readings) == 2
    rep = analyze_history(readings)
    assert rep.worst_verdict is Verdict.SPOOF_PARTIAL


def test_load_history_accepts_bare_list(tmp_path):
    p = tmp_path / "h.json"
    p.write_text(json.dumps([
        {"session_id": "s1", "identifiers": baseline()},
        {"session_id": "s2", "identifiers": baseline(machine_guid="g2")},
    ]), encoding="utf-8")
    assert len(load_history(p)) == 2


def test_evaluate_transition_directly():
    t = evaluate_transition(R("a", **baseline()), R("b", **baseline(volume_serial="NEW")))
    assert t.verdict is Verdict.SPOOF_PARTIAL
    assert t.from_session == "a" and t.to_session == "b"
