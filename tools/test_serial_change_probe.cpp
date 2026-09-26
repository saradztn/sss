// tools/test_serial_change_probe.cpp
// ---------------------------------------------------------------------------
// Unit tests for the shipped decision logic in serial_change_probe.cpp.
//
// It #includes the real translation unit (with main() compiled out) rather
// than re-implementing anything, so what is tested is what ships.
//
//   make -C tools test
// ---------------------------------------------------------------------------
#define SCP_NO_MAIN
#include "serial_change_probe.cpp"
#undef SCP_NO_MAIN

#include <cstdio>
#include <cstdlib>
#include <string>

static int g_fail = 0;
static int g_pass = 0;

#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        if (cond) { ++g_pass; }                                              \
        else { ++g_fail; std::printf("FAIL: %s  (line %d)\n", msg, __LINE__); } \
    } while (0)

static TargetKey mk(const std::string& path, Access w, Access d) {
    TargetKey t; t.path = path; t.writable = w; t.deletable = d;
    t.readable = Access::Granted; t.exists = true;
    return t;
}

static void test_decide_would_succeed_when_writable() {
    Report r;
    r.keys.push_back(mk("SOFTWARE\\Multi Theft Auto\\1.6", Access::Granted, Access::Denied));
    r.keys.push_back(mk("SOFTWARE\\WOW6432Node\\Multi Theft Auto\\1.6", Access::Denied, Access::Denied));
    decide(r);
    CHECK(r.exit_code == 0, "writable key -> exit 0 (change would succeed)");
    CHECK(r.writable_targets == 1, "writable_targets == 1");
    CHECK(r.deletable_targets == 0, "deletable_targets == 0");
    CHECK(r.total_targets == 2, "total_targets == 2");
}

static void test_decide_would_succeed_when_only_deletable() {
    // CSX uses RegDeleteKeyA: delete permission alone is enough to reset.
    Report r;
    r.keys.push_back(mk("SOFTWARE\\Multi Theft Auto\\1.6", Access::Denied, Access::Granted));
    decide(r);
    CHECK(r.exit_code == 0, "deletable-only key -> exit 0");
    CHECK(r.deletable_targets == 1, "deletable_targets == 1");
}

static void test_decide_blocked_when_all_denied() {
    Report r;
    for (size_t i = 0; i < kTargetCount; ++i)
        r.keys.push_back(mk(kTargetPaths[i], Access::Denied, Access::Denied));
    decide(r);
    CHECK(r.exit_code == 2, "all denied -> exit 2 (blocked)");
    CHECK(r.writable_targets == 0, "writable_targets == 0");
}

static void test_decide_undetermined_when_no_keys() {
    Report r;
    decide(r);
    CHECK(r.exit_code == 3, "no keys -> exit 3 (undetermined)");
    CHECK(r.total_targets == 0, "total_targets == 0");
}

static void test_decide_unknown_access_is_not_granted() {
    // An absent key must not be counted as writable.
    Report r;
    r.keys.push_back(mk("SOFTWARE\\Multi Theft Auto\\1.6", Access::Unknown, Access::Unknown));
    decide(r);
    CHECK(r.exit_code == 2, "unknown access -> exit 2, not 0");
    CHECK(r.writable_targets == 0, "unknown is not writable");
}

static void test_looks_like_serial() {
    CHECK(looks_like_serial("A1B2C3D4E5F60718293A4B5C6D7E8F90"), "32 hex chars is a serial");
    CHECK(looks_like_serial("1a2b-3c4d"), "dashed hex is a serial");
    CHECK(!looks_like_serial("DESKTOP-7QK2M1"), "hostname is not a serial");
    CHECK(!looks_like_serial("1.6"), "short non-hex is not a serial");
    CHECK(!looks_like_serial("Player Name"), "name with space is not a serial");
    CHECK(!looks_like_serial(""), "empty is not a serial");
}

static void test_mask_hides_the_middle() {
    std::string v = "A1B2C3D4E5F60718293A4B5C6D7E8F90";
    std::string m = mask(v);
    CHECK(m.size() == v.size(), "mask preserves length");
    CHECK(m.compare(0, 4, "A1B2") == 0, "mask keeps first 4");
    CHECK(m.compare(v.size() - 4, 4, "8F90") == 0, "mask keeps last 4");
    CHECK(m.find('*') != std::string::npos, "mask contains asterisks");
    CHECK(m.find("E5F6") == std::string::npos, "mask hides the middle");
    CHECK(mask("short") == "short", "short values pass through");
}

static void test_access_str_mapping() {
    CHECK(std::string(access_str(Access::Granted)) == "GRANTED", "Granted -> GRANTED");
    CHECK(std::string(access_str(Access::Denied)) == "DENIED", "Denied -> DENIED");
    CHECK(std::string(access_str(Access::Unknown)) == "unknown", "Unknown -> unknown");
}

#ifndef _WIN32
// The POSIX harness must run without crashing and must populate both vectors.
static void test_collect_posix_populates() {
    Report r;
    collect_posix(r);
    CHECK(r.ids.size() == 10, "collect_posix fills 10 identifiers");
    CHECK(r.keys.size() == 3, "collect_posix probes 3 permission targets");
    // No identifier may be reported present with an empty value.
    bool ok = true;
    for (const auto& id : r.ids) if (id.present && id.value.empty()) ok = false;
    CHECK(ok, "present implies non-empty value");
    // decide() must produce a valid exit code for a real machine report.
    decide(r);
    CHECK(r.exit_code == 0 || r.exit_code == 2 || r.exit_code == 3,
          "decide() returns a documented exit code");
}
#endif

static Identifier mkId(const std::string& key, double bits, Spoofability sp,
                       bool present = true, const std::string& val = "x") {
    Identifier id; id.key = key; id.source = "test"; id.real_bits = bits;
    id.spoof = sp; id.present = present; id.value = val;
    return id;
}

static void test_effective_bits_zeroes_out_spoofable() {
    CHECK(effective_bits(mkId("a", 64.0, Spoofability::Anchor)) == 64.0,
          "anchor keeps its full entropy");
    CHECK(effective_bits(mkId("b", 64.0, Spoofability::UsermodeSpoof)) == 0.0,
          "usermode-spoofable contributes zero");
    CHECK(effective_bits(mkId("c", 64.0, Spoofability::TrivialSpoof)) == 0.0,
          "trivial-spoofable contributes zero");
    CHECK(effective_bits(mkId("d", 64.0, Spoofability::UserReset)) > 0.0
          && effective_bits(mkId("d", 64.0, Spoofability::UserReset)) < 64.0,
          "user-resettable contributes a fraction");
    CHECK(effective_bits(mkId("e", 64.0, Spoofability::Anchor, false)) == 0.0,
          "absent identifier contributes zero");
}

static void test_score_aggregates() {
    Report r;
    r.ids.push_back(mkId("bios_serial", 24.0, Spoofability::Anchor));
    r.ids.push_back(mkId("machine_guid", 64.0, Spoofability::UsermodeSpoof));
    r.ids.push_back(mkId("mac_address", 48.0, Spoofability::TrivialSpoof));
    r.ids.push_back(mkId("gone", 30.0, Spoofability::Anchor, false));
    score(r);
    CHECK(r.collected == 3, "collected counts present only");
    CHECK(r.spoofable == 2, "spoofable counts usermode + trivial");
    CHECK(r.real_bits_total == 24.0 + 64.0 + 48.0, "nominal sums present bits");
    CHECK(r.effective_bits_total == 24.0,
          "effective keeps only the anchor's bits");
}

static void test_score_all_spoofable_is_zero() {
    Report r;
    r.ids.push_back(mkId("machine_guid", 64.0, Spoofability::UsermodeSpoof));
    r.ids.push_back(mkId("volume_serial", 32.0, Spoofability::TrivialSpoof));
    score(r);
    CHECK(r.real_bits_total == 96.0, "nominal is high");
    CHECK(r.effective_bits_total == 0.0, "effective is zero");
    CHECK(std::string(entropy_grade(0.0))[0] == 'F', "grade F at zero effective bits");
}

static void test_entropy_grade_bands() {
    CHECK(entropy_grade(0.0)[0]  == 'F', "0 bits -> F");
    CHECK(entropy_grade(0.9)[0]  == 'F', "0.9 bits -> F");
    CHECK(entropy_grade(1.0)[0]  == 'D', "1 bit -> D");
    CHECK(entropy_grade(15.9)[0] == 'D', "15.9 bits -> D");
    CHECK(entropy_grade(16.0)[0] == 'C', "16 bits -> C");
    CHECK(entropy_grade(31.9)[0] == 'C', "31.9 bits -> C");
    CHECK(entropy_grade(32.0)[0] == 'B', "32 bits -> B");
}

static void test_spoof_str_is_stable() {
    CHECK(std::string(spoof_str(Spoofability::Anchor)) == "ANCHOR", "Anchor label");
    CHECK(std::string(spoof_str(Spoofability::UsermodeSpoof)) == "USERMODE-SPOOFABLE",
          "UsermodeSpoof label");
    CHECK(std::string(spoof_str(Spoofability::TrivialSpoof)) == "TRIVIAL-SPOOFABLE",
          "TrivialSpoof label");
}

int main() {
    std::printf("serial_change_probe unit tests\n");
    test_decide_would_succeed_when_writable();
    test_decide_would_succeed_when_only_deletable();
    test_decide_blocked_when_all_denied();
    test_decide_undetermined_when_no_keys();
    test_decide_unknown_access_is_not_granted();
    test_looks_like_serial();
    test_mask_hides_the_middle();
    test_access_str_mapping();
    test_effective_bits_zeroes_out_spoofable();
    test_score_aggregates();
    test_score_all_spoofable_is_zero();
    test_entropy_grade_bands();
    test_spoof_str_is_stable();
#ifndef _WIN32
    test_collect_posix_populates();
#endif
    std::printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
