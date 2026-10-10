/**
 * ============================================================================
 * test_nrth_audit.cpp — unit tests for the defensive audit module (host build)
 * ============================================================================
 * Build & run (Linux, no Windows/PE dependency needed):
 *   g++ -std=c++17 -Wall -Wextra -Isrc tests/test_nrth_audit.cpp src/nrth_audit.cpp \
 *       -o /tmp/test_nrth_audit && /tmp/test_nrth_audit
 *
 * The module images used here are *synthetic minimal PE files* built in memory.
 * They contain: a function prologue that matches a real catalogue signature
 * verbatim (the "clean" case), the same function with its first byte replaced by
 * 0xC3 (the "check kill" footprint), with its head replaced by `E9 rel32` (the
 * near-detour footprint), and a positional-XOR-encoded pattern in .data (a
 * variant that kept the codec but changed the key). No real game module is
 * needed, and none is shipped here.
 * ============================================================================
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "nrth_audit.h"

static int g_fail = 0;
static int g_total = 0;

#define CHECK(cond, name)                                                          \
    do {                                                                           \
        ++g_total;                                                                 \
        if (!(cond)) {                                                             \
            ++g_fail;                                                              \
            printf("  [FAIL] %s   (%s:%d)\n", (name), __FILE__, __LINE__);         \
        } else {                                                                   \
            printf("  [ ok ] %s\n", (name));                                       \
        }                                                                          \
    } while (0)

/* ---- synthetic PE builder -------------------------------------------------- */
#define TXT_RVA   0x1000
#define TXT_SIZE  0x400
#define DAT_RVA   0x2000
#define DAT_SIZE  0x200
#define HDR_SIZE  0x400
#define IMG_SIZE  (HDR_SIZE + TXT_SIZE + DAT_SIZE)

struct FakeImage {
    uint8_t b[IMG_SIZE];
    FakeImage() {
        memset(b, 0, sizeof(b));
        /* DOS */
        b[0] = 'M'; b[1] = 'Z';
        uint32_t pe = 0x80;
        memcpy(b + 0x3C, &pe, 4);
        /* COFF: PE\0\0, machine x86, 2 sections */
        memcpy(b + pe, "PE\0\0", 4);
        uint16_t machine = 0x014c, nsec = 2, optSize = 0xE0, chars = 0x2102;
        uint32_t ts = 0x66000000;
        memcpy(b + pe + 4, &machine, 2);
        memcpy(b + pe + 6, &nsec, 2);
        memcpy(b + pe + 8, &ts, 4);
        memcpy(b + pe + 20, &optSize, 2);
        memcpy(b + pe + 22, &chars, 2);
        /* Optional header (PE32) */
        uint32_t opt = pe + 24;
        uint16_t magic = 0x010b;
        uint32_t entry = TXT_RVA, imgBase = 0x10000000, sectAlign = 0x1000, fileAlign = 0x200,
                 sizeOfImage = IMG_SIZE;
        memcpy(b + opt + 0, &magic, 2);
        memcpy(b + opt + 16, &entry, 4);
        memcpy(b + opt + 28, &imgBase, 4);
        memcpy(b + opt + 32, &sectAlign, 4);
        memcpy(b + opt + 36, &fileAlign, 4);
        memcpy(b + opt + 56, &sizeOfImage, 4);
        /* sections */
        uint32_t sh = opt + optSize;
        memcpy(b + sh + 0, ".text\0\0\0", 8);
        uint32_t vsz = TXT_SIZE, rva = TXT_RVA, raw = HDR_SIZE, rsz = TXT_SIZE, ch = 0x60000020;
        memcpy(b + sh + 8, &vsz, 4);
        memcpy(b + sh + 12, &rva, 4);
        memcpy(b + sh + 16, &rsz, 4);
        memcpy(b + sh + 20, &raw, 4);
        memcpy(b + sh + 36, &ch, 4);
        sh += 40;
        memcpy(b + sh + 0, ".data\0\0\0", 8);
        vsz = DAT_SIZE; rva = DAT_RVA; raw = HDR_SIZE + TXT_SIZE; rsz = DAT_SIZE; ch = 0xC0000040;
        memcpy(b + sh + 8, &vsz, 4);
        memcpy(b + sh + 12, &rva, 4);
        memcpy(b + sh + 16, &rsz, 4);
        memcpy(b + sh + 20, &raw, 4);
        memcpy(b + sh + 36, &ch, 4);
    }
    uint8_t *text() { return b + HDR_SIZE; }
    uint8_t *data() { return b + HDR_SIZE + TXT_SIZE; }
};

/* Turn a pattern string into concrete bytes ('?' -> filler). */
static uint32_t materialise(const char *pattern, uint8_t *out, uint32_t cap, uint8_t filler)
{
    uint32_t n = 0;
    const char *p = pattern;
    while (*p && n < cap) {
        while (*p == ' ') ++p;
        if (!*p) break;
        if (*p == '?') {
            out[n++] = filler;
            while (*p && *p != ' ') ++p;
            continue;
        }
        unsigned v = 0;
        for (int i = 0; i < 2 && *p; ++i, ++p) {
            char c = *p;
            int d = (c >= '0' && c <= '9') ? c - '0' : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
            if (d < 0) break;
            v = v * 16 + (unsigned)d;
        }
        out[n++] = (uint8_t)v;
        while (*p && *p != ' ') ++p;
    }
    return n;
}

static void encode_pos(const uint8_t *in, uint32_t len, uint32_t key, uint8_t *out)
{
    for (uint32_t i = 0; i < len; ++i) {
        out[i] = (uint8_t)(in[i] ^ (uint8_t)(i - key));
    }
}

int main(void)
{
    printf("[*] nrth_audit unit tests\n");

    /* ---- 1. module self test ------------------------------------------------*/
    char report[8192];
    CHECK(NrthAuditSelfTest(report, sizeof(report)) == 0, "module self-test (evidence vectors)");

    /* ---- 2. clean module: target present, nothing patched -------------------*/
    const NrthSignature *sig = NrthSigAt(1);
    if (!sig) {
        printf("  [FAIL] empty signature catalogue\n");
        return 1;
    }
    {
        FakeImage img;
        uint8_t body[256];
        uint32_t len = materialise(sig->pattern, body, sizeof(body), 0x11);
        memcpy(img.text() + 0x40, body, len);
        NrthSigFinding r[64];
        memset(r, 0, sizeof(r));
        int32_t hits = NrthAuditImage(img.b, IMG_SIZE, r, NrthSigCount());
        CHECK(hits >= 1 && r[0].fullHits >= 1 && r[0].patchedHits == 0,
              "audit: clean image -> pattern found, no prologue change");
        CHECK(r[0].firstFullRva == TXT_RVA + 0x40, "audit: reported RVA is section-relative");
    }

    /* ---- 3. check-kill footprint (the netc.dll 0xC3 write) ------------------*/
    {
        FakeImage img;
        uint8_t body[256];
        uint32_t len = materialise(sig->pattern, body, sizeof(body), 0x11);
        body[0] = 0xC3;                                   /* RET over the first byte */
        memcpy(img.text() + 0x90, body, len);
        NrthSigFinding r[64];
        memset(r, 0, sizeof(r));
        NrthAuditImage(img.b, IMG_SIZE, r, NrthSigCount());
        CHECK(r[0].fullHits == 0 && r[0].patchedHits == 1,
              "audit: 0xC3 patch -> no full match, one patched match");
        CHECK(r[0].state == NRTH_PRO_KILL_RET, "audit: state classified as KILL_RET");
        CHECK(r[0].firstPatchedRva == TXT_RVA + 0x90, "audit: patched RVA reported");
    }

    /* ---- 4. near-detour footprint (MinHook E9 rel32) ------------------------*/
    {
        FakeImage img;
        uint8_t body[256];
        uint32_t len = materialise(sig->pattern, body, sizeof(body), 0x11);
        body[0] = 0xE9;
        uint32_t rel = 0x00001234;
        memcpy(body + 1, &rel, 4);
        memcpy(img.text() + 0x120, body, len);
        NrthSigFinding r[64];
        memset(r, 0, sizeof(r));
        NrthAuditImage(img.b, IMG_SIZE, r, NrthSigCount());
        CHECK(r[0].fullHits == 0 && r[0].patchedHits == 1,
              "audit: E9 detour -> one patched match only");
        CHECK(r[0].state == NRTH_PRO_DETOUR_JMP32, "audit: state classified as DETOUR_JMP32");
        CHECK(r[0].detail == TXT_RVA + 0x120 + 5 + rel,
              "audit: detour target RVA captured for triage");
    }

    /* ---- 4a. absolute detour through memory (FF 25 abs32) ------------------*/
    {
        FakeImage img;
        uint8_t body[256];
        uint32_t len = materialise(sig->pattern, body, sizeof(body), 0x11);
        body[0] = 0xFF;
        body[1] = 0x25;
        uint32_t abs = 0x10004040;                        /* target VA, ImageBase-relative */
        memcpy(body + 2, &abs, 4);
        memcpy(img.text() + 0x160, body, len);
        NrthSigFinding r[64];
        memset(r, 0, sizeof(r));
        NrthAuditImage(img.b, IMG_SIZE, r, NrthSigCount());
        CHECK(r[0].fullHits == 0 && r[0].patchedHits == 1,
              "audit: FF 25 detour -> one patched match");
        CHECK(r[0].state == NRTH_PRO_DETOUR_FARJMP && r[0].detail == 0x4040,
              "audit: far-jump target converted to an RVA");
    }

    /* ---- 4b. a widened tail hit on a *normal* prologue must NOT alert -------*/
    {
        FakeImage img;
        uint8_t body[256];
        uint32_t len = materialise(sig->pattern, body, sizeof(body), 0x11);
        body[0] = 0x53;                        /* push ebx: another function's real entry */
        memcpy(img.text() + 0x180, body, len);
        NrthSigFinding r[64];
        memset(r, 0, sizeof(r));
        int32_t hits = NrthAuditImage(img.b, IMG_SIZE, r, NrthSigCount());
        CHECK(hits == 0 && r[0].fullHits == 0 && r[0].patchedHits == 0,
              "audit: coincidental tail match with a normal prologue is not reported");
        CHECK(NrthPrologueIsTamper(NRTH_PRO_UNKNOWN) == 0 &&
              NrthPrologueIsTamper(NRTH_PRO_KILL_RET) == 1 &&
              NrthPrologueIsTamper(NRTH_PRO_DETOUR_JMP32) == 1,
              "predicate: tamper states only");
    }

    /* ---- 4c. A/B diff: baseline clean vs suspect carrying a footprint ------*/
    {
        FakeImage clean, suspect;
        uint8_t body[256];
        uint32_t len = materialise(sig->pattern, body, sizeof(body), 0x11);
        memcpy(clean.text() + 0x40, body, len);          /* intact entry            */
        body[0] = 0xC3;                                   /* the sample's check kill */
        memcpy(suspect.text() + 0x40, body, len);
        NrthAuditDiffRow d[64];
        memset(d, 0, sizeof(d));
        int32_t n = NrthAuditDiff(clean.b, IMG_SIZE, suspect.b, IMG_SIZE, d, 64);
        CHECK(n == 1 && d[0].addedFootprint == 1, "diff: one located function changed state");
        CHECK(d[0].cleanFull == 1 && d[0].cleanPatched == 0 && d[0].susFull == 0 &&
                  d[0].susPatched == 1,
              "diff: per-row hit counts split correctly");
        CHECK(d[0].susState == NRTH_PRO_KILL_RET && d[0].susRva == TXT_RVA + 0x40,
              "diff: footprint state and RVA reported");
        memset(d, 0, sizeof(d));
        CHECK(NrthAuditDiff(clean.b, IMG_SIZE, clean.b, IMG_SIZE, d, 64) == 0 &&
                  d[0].targetLost == 0,
              "diff: identical images produce no delta");
        CHECK(NrthAuditDiff(clean.b, IMG_SIZE, suspect.b, IMG_SIZE, d, 1) == NVXA_E_INVALID,
              "diff: undersized row buffer rejected");
        /* a different build of the module: pattern gone -> targetLost, not an alert */
        FakeImage other;
        uint8_t junk[64];
        memset(junk, 0x2A, sizeof(junk));
        memcpy(other.text() + 0x40, junk, sizeof(junk));
        memset(d, 0, sizeof(d));
        CHECK(NrthAuditDiff(clean.b, IMG_SIZE, other.b, IMG_SIZE, d, 64) == 0 &&
                  d[0].targetLost == 1 && d[0].addedFootprint == 0,
              "diff: missing target is reported separately from tampering");
    }

    /* ---- 5. obfuscated record of a *key-rotated variant* --------------------*/
    {
        FakeImage img;
        const char *plain = sig->pattern;                    /* e.g. "55 8B EC ..." */
        uint8_t buf[300];
        uint32_t plen = (uint32_t)strlen(plain);
        encode_pos((const uint8_t *)plain, plen, 0x7A, buf);   /* new key = 0x7A */
        memcpy(img.data() + 0x20, buf, plen);
        char text[512] = {0};
        uint32_t key = 0;
        int32_t n = NrthXorCrack(buf, plen, text, sizeof(text), &key);
        CHECK(n == (int32_t)plen && strcmp(text, plain) == 0,
              "codec: key-rotated record still decodes (variant triage)");

        char out[4096] = {0};
        uint32_t vas[32] = {0};
        int32_t found = NrthFindHiddenSignatures(img.b, IMG_SIZE, 24, out, sizeof(out), vas, 32);
        CHECK(found >= 1 && strstr(out, plain) != NULL,
              "sweep: hidden pattern located in .data by prologue anchoring");
    }

    /* ---- 6. untrusted/malformed input is refused, never a crash -------------*/
    {
        FakeImage img;
        NrthPeView pe;
        CHECK(NrthPeMap(img.b, 8, &pe) == NVXA_E_INVALID, "PE: tiny buffer rejected");
        uint8_t bad[IMG_SIZE];
        memcpy(bad, img.b, sizeof(bad));
        uint32_t huge = 0xFFFFFFF0u;                       /* section raw pointer beyond EOF */
        const uint32_t secTab = 0x80 + 24 + 0xE0;          /* .text section header            */
        memcpy(bad + secTab + 40 + 20, &huge, 4);          /* .data PointerToRawData           */
        NrthSigFinding r[64];
        CHECK(NrthAuditImage(bad, IMG_SIZE, r, 64) >= NVXA_E_FORMAT,
              "PE: bogus section pointer handled without crash");
        memcpy(bad, img.b, sizeof(bad));
        bad[0] = 'X';
        CHECK(NrthAuditImage(bad, IMG_SIZE, r, 64) == NVXA_E_FORMAT, "PE: bad DOS magic rejected");
        CHECK(NrthPatScan(img.text(), 16, "55", NULL, 0) >= 0, "pattern: NULL hit buffer tolerated");
        CHECK(NrthXorCrack(img.text(), 4, (char *)bad, 8, &huge) >= 0, "codec: short input safe");
    }

    /* ---- 7. catalogue metadata stays evidence-linked ------------------------*/
    {
        int ok = 1;
        for (uint32_t i = 1; i <= NrthSigCount(); ++i) {
            const NrthSignature *s = NrthSigAt(i);
            if (!s || s->id != i || !s->evidence || !s->evidence[0] || s->decryptor_va < 0x10001000 ||
                s->decryptor_va > 0x1014a000) {
                ok = 0;
            }
        }
        CHECK(ok && NrthSigCount() == 20, "catalogue: 20 rows, each with sample evidence VA");
    }

    printf("[*] %d/%d checks passed\n", g_total - g_fail, g_total);
    return g_fail ? 1 : 0;
}
