/**
 * ============================================================================
 * nrth_audit_cli.cpp — command-line front end for the defensive audit module
 * ============================================================================
 * Read-only. Subcommands:
 *   selftest                       run the built-in evidence vectors
 *   signatures                     print the verified signature catalogue
 *   decode  <file> --rva 0xADDR --len N      decode one obfuscated record
 *   sweep   <file> [--min 24]              find hidden pattern strings in a sample
 *   audit   <file> [--csv out.csv] [--json out.txt]
 *                                     locate the tool's hook targets in a module copy
 *                                     or in an owned memory dump and report state
 * `audit` is the one that matters operationally: feed it the MTA client's client.dll /
 * netc.dll from a *clean reference install*, from a suspect install, or from a
 * read-only dump the team already has. It never touches a running process.
 * ============================================================================
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nrth_audit.h"

static int ends_with(const char *s, const char *suf)
{
    size_t a = strlen(s), b = strlen(suf);
    if (b > a) {
        return 0;
    }
    for (size_t i = 0; i < b; ++i) {
        char c = s[a - b + i], d = suf[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
        if (d >= 'A' && d <= 'Z') d = (char)(d + 32);
        if (c != d) {
            return 0;
        }
    }
    return 1;
}

static uint32_t parse_u32(const char *s)
{
    return (uint32_t)strtoul(s, NULL, 0);
}

static void usage(void)
{
    printf("nrth_audit %s - defensive audit for the NORTH/NVX MTA:SA cheat family\n\n",
           NRTH_AUDIT_VERSION);
    printf("usage:\n"
           "  nrth_audit selftest\n"
           "  nrth_audit signatures\n"
           "  nrth_audit decode <file> --rva <0x..> --len <n>\n"
           "  nrth_audit sweep  <file> [--min <len>] [--vas]\n"
           "  nrth_audit audit  <module-file> [--csv <out.csv>]\n"
           "  nrth_audit diff   <known-good-file> <loaded-file> [--csv <out.csv>]\n\n"
           "notes:\n"
           "  * read-only: this tool never opens another process, never writes, hooks\n"
           "    or injects; `audit` works on a file copy or an already-owned dump\n"
           "  * exit codes: 0 clean / 1 self-test or argument problem / 3 = tamper footprint\n"
           "  * a MinHook detour or a C3 patch is applied to *live memory*, so an on-disk\n"
           "    module usually still looks PRISTINE; use a dump (or your EDR's memory\n"
           "    capture) for live-state evidence. On-disk tampering is still detected.\n");
}

static int cmd_signatures(void)
{
    printf("[*] verified signature catalogue (%u entries, from NRTH.dll 947b81be..)\n\n",
           NrthSigCount());
    for (uint32_t i = 1; i <= NrthSigCount(); ++i) {
        const NrthSignature *s = NrthSigAt(i);
        printf("[%2u] target=%s  conf=%s  decryptor=0x%08x  key=0x%02X  site=%s\n",
               s->id, s->target, s->confidence == 2 ? "High" : "Medium", s->decryptor_va,
               s->xor_key, s->evidence);
        printf("     role    : %s\n", s->role);
        printf("     pattern : %s\n\n", s->pattern);
    }
    return 0;
}

static int cmd_selftest(void)
{
    char report[8192];
    int32_t failed = NrthAuditSelfTest(report, sizeof(report));
    fputs(report, stdout);
    printf("[+] selftest: %d check(s) failed\n", failed);
    return failed ? 1 : 0;
}

static int cmd_decode(int argc, char **argv, const char *file)
{
    uint32_t rva = 0, len = 16;
    int haveRva = 0;
    for (int i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "--rva") == 0 && i + 1 < argc) {
            rva = parse_u32(argv[++i]);
            haveRva = 1;
        } else if (strcmp(argv[i], "--len") == 0 && i + 1 < argc) {
            len = parse_u32(argv[++i]);
        }
    }
    if (!haveRva || len == 0) {
        fprintf(stderr, "[!] need --rva and --len\n");
        return 2;
    }
    FILE *f = fopen(file, "rb");
    if (!f) {
        fprintf(stderr, "[!] cannot open %s\n", file);
        return 2;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 64 * 1024 * 1024) {
        fclose(f);
        fprintf(stderr, "[!] bad size\n");
        return 2;
    }
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf || fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return 2;
    }
    fclose(f);

    NrthPeView pe;
    if (NrthPeMap(buf, (uint32_t)sz, &pe) != NVXA_OK) {
        fprintf(stderr, "[!] not a PE image\n");
        free(buf);
        return 2;
    }
    const uint8_t *p = NrthPeRvaToPtr(&pe, rva, len);
    if (!p) {
        fprintf(stderr, "[!] rva 0x%x + %u outside image\n", rva, len);
        free(buf);
        return 2;
    }
    char text[512];
    uint32_t key = 0;
    int32_t n = NrthXorCrack(p, len, text, sizeof(text), &key);
    printf("[*] %s  imagebase=0x%08x  rva=0x%x  len=%u\n", file, pe.imageBase, rva, len);
    printf("[*] raw            : ");
    for (uint32_t i = 0; i < len && i < 32; ++i) {
        printf("%02x ", p[i]);
    }
    printf("\n");
    if (n > 0) {
        printf("[+] decoded (key 0x%02X): %s\n", key, text);
    } else {
        printf("[-] no printable positional-XOR decode at this record\n");
    }
    free(buf);
    return n > 0 ? 0 : 1;
}

static int cmd_sweep(int argc, char **argv, const char *file)
{
    uint32_t minLen = 24;
    int showVas = 0;
    for (int i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "--min") == 0 && i + 1 < argc) {
            minLen = parse_u32(argv[++i]);
        } else if (strcmp(argv[i], "--vas") == 0) {
            showVas = 1;
        }
    }
    FILE *f = fopen(file, "rb");
    if (!f) {
        fprintf(stderr, "[!] cannot open %s\n", file);
        return 2;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 64 * 1024 * 1024) {
        fclose(f);
        return 2;
    }
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf || fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return 2;
    }
    fclose(f);

    const uint32_t cap = 1u << 20;
    char *out = (char *)malloc(cap);
    uint32_t vas[256];
    if (!out) {
        free(buf);
        return 2;
    }
    int32_t n = NrthFindHiddenSignatures(buf, (uint32_t)sz, minLen, out, cap, vas,
                                        sizeof(vas) / sizeof(vas[0]));
    if (n < 0) {
        fprintf(stderr, "[!] %s: error %d (not a PE image?)\n", file, n);
        free(out);
        free(buf);
        return 2;
    }
    printf("[*] %s: %d hidden pattern candidate(s) (>= %u chars)\n", file, n, minLen);
    fputs(out, stdout);
    if (showVas) {
        for (int32_t i = 0; i < n && i < 256; ++i) {
            printf("  candidate rva 0x%08x\n", vas[i]);
        }
    }
    printf("[*] note: candidates from a raw sweep are unverified until they match a\n"
           "        decryptor call site (tools/nrth_strings_recover.py does that).\n");
    free(out);
    free(buf);
    return 0;
}

static int cmd_diff(int argc, char **argv, const char *clean, const char *sus)
{
    const char *csv = NULL;
    int showAll = 0;
    for (int i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "--csv") == 0 && i + 1 < argc) {
            csv = argv[++i];
        } else if (strcmp(argv[i], "--all") == 0) {
            showAll = 1;
        }
    }
    NrthAuditDiffRow *rows =
        (NrthAuditDiffRow *)malloc(sizeof(NrthAuditDiffRow) * NrthSigCount());
    if (!rows) {
        fprintf(stderr, "[!] out of memory\n");
        return 2;
    }
    memset(rows, 0, sizeof(NrthAuditDiffRow) * NrthSigCount());
    int32_t n = NrthAuditDiffFiles(clean, sus, rows, NrthSigCount());
    if (n < 0) {
        fprintf(stderr, "[!] diff failed (%d): unreadable file or not a PE image\n", n);
        free(rows);
        return 2;
    }
    printf("[*] nrth_audit %s — A/B module comparison\n", NRTH_AUDIT_VERSION);
    printf("[*] baseline (known good) : %s\n", clean);
    printf("[*] compared image        : %s\n", sus);
    printf("[*] both must be the SAME build of the same module; differing builds make every\n"
           "    row look changed. RVAs are module-relative and are not comparable across bases,\n"
           "    which is why the diff works on located functions, not on absolute addresses.\n\n");
    printf("%-4s %-14s %-14s %-22s %s\n", "id", "clean f/p", "loaded f/p", "change",
           "footprint @rva / target");
    int lost = 0;
    for (uint32_t i = 0; i < NrthSigCount(); ++i) {
        const NrthAuditDiffRow *d = &rows[i];
        const NrthSignature *sg = NrthSigAt(i + 1);
        if (!d->addedFootprint && !d->targetLost && !showAll) {
            continue;
        }
        char change[64];
        if (d->addedFootprint) {
            snprintf(change, sizeof(change), "%s", NrthPrologueStateName(d->susState));
        } else if (d->targetLost) {
            snprintf(change, sizeof(change), "%s", "TARGET NOT FOUND IN LOADED IMAGE");
            ++lost;
        } else {
            snprintf(change, sizeof(change), "%s", "unchanged");
        }
        char where[64] = "-";
        if (d->susRva) {
            snprintf(where, sizeof(where), "0x%06x (detail 0x%08x)", d->susRva, d->susDetail);
        } else if (d->targetLost) {
            snprintf(where, sizeof(where), "%s", "located in the baseline only");
        }
        printf("[%2u] %4u/%-8u %4u/%-8u %-22s %s\n", sg ? sg->id : d->sigId, d->cleanFull,
               d->cleanPatched, d->susFull, d->susPatched, change, where);
        if (sg) {
            printf("     module=%s pattern=%.58s%s\n", sg->target, sg->pattern,
                   strlen(sg->pattern) > 58 ? "..." : "");
        }
    }
    if (n == 0 && lost == 0) {
        printf("     (no differing located function)\n");
    }
    printf("\n[*] verdict: %d located function(s) carry a footprint the baseline does not have\n",
           n);
    if (lost) {
        printf("[*] note: %d pattern(s) found in the baseline are absent from the loaded image —"
               " that is normally a different MTA build, not a cheat; re-baseline before alerting.\n",
               lost);
    }
    if (csv) {
        FILE *o = fopen(csv, "wb");
        if (o) {
            fprintf(o, "sig_id,target,clean_full,clean_patched,sus_full,sus_patched,"
                       "added_footprint,target_lost,state,sus_rva,detail\n");
            for (uint32_t i = 0; i < NrthSigCount(); ++i) {
                const NrthAuditDiffRow *d = &rows[i];
                const NrthSignature *sg = NrthSigAt(i + 1);
                fprintf(o, "%u,%s,%u,%u,%u,%u,%u,%u,%u,0x%x,0x%x\n", sg ? sg->id : d->sigId,
                        sg ? sg->target : "", d->cleanFull, d->cleanPatched, d->susFull,
                        d->susPatched, d->addedFootprint, d->targetLost, d->susState, d->susRva,
                        d->susDetail);
            }
            fclose(o);
            printf("[+] csv -> %s\n", csv);
        } else {
            fprintf(stderr, "[!] cannot write %s\n", csv);
        }
    }
    free(rows);
    return n ? 3 : 0;
}

static int cmd_audit(int argc, char **argv, const char *file)
{
    const char *csv = NULL;
    for (int i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "--csv") == 0 && i + 1 < argc) {
            csv = argv[++i];
        }
    }
    NrthSigFinding *res = (NrthSigFinding *)malloc(sizeof(NrthSigFinding) * NrthSigCount());
    if (!res) {
        fprintf(stderr, "[!] out of memory\n");
        return 2;
    }
    memset(res, 0, sizeof(NrthSigFinding) * NrthSigCount());
    int32_t n = NrthAuditImageFile(file, res, NrthSigCount());
    if (n < 0) {
        fprintf(stderr, "[!] audit of %s failed (%d): unreadable or not a PE image\n", file, n);
        free(res);
        return 2;
    }
    printf("[*] nrth_audit %s\n", NRTH_AUDIT_VERSION);
    printf("[*] target file : %s\n", ends_with(file, ".dll") || ends_with(file, ".exe")
                                         ? file : file);
    printf("[*] signatures  : %u checked, %u with a match\n", NrthSigCount(), n);
    printf("    columns: full = complete pattern found (target present, prologue intact)\n"
           "             patched = tail found but prologue replaced (detour / kill footprint)\n\n");
    printf("%-4s %-10s %-7s %-12s %-12s %s\n", "id", "full", "patched", "full@rva",
           "patched@rva", "state");
    int tampered = 0;
    for (uint32_t i = 0; i < NrthSigCount(); ++i) {
        const NrthSigFinding *f = &res[i];
        const NrthSignature *s = NrthSigAt(i + 1);
        if (!f->fullHits && !f->patchedHits) {
            printf("[%2u] %-10s %-7s %-12s %-12s %s\n", s->id, "-", "-", "not found", "not found",
                   "target function not located by this signature in this image");
            continue;
        }
        if (f->patchedHits) {
            ++tampered;
        }
        char st[96];
        snprintf(st, sizeof(st), "%s", f->patchedHits ? NrthPrologueStateName(f->state)
                                                      : "PRISTINE (pattern matches byte-for-byte)");
        char a[24] = "-", b[24] = "-";
        if (f->firstFullRva) {
            snprintf(a, sizeof(a), "0x%06x", f->firstFullRva);
        }
        if (f->firstPatchedRva) {
            snprintf(b, sizeof(b), "0x%06x", f->firstPatchedRva);
        }
        printf("[%2u] %-10u %-7u %-12s %-12s %s\n", s->id, f->fullHits, f->patchedHits, a, b, st);
        printf("     module=%s  role=%s\n", s->target, s->role);
        printf("     pattern=%s\n", s->pattern);
        if (f->firstFullRva) {
            printf("     first full match at RVA 0x%06x\n", f->firstFullRva);
        }
        if (f->firstPatchedRva) {
            printf("     !! patched match at RVA 0x%06x, detail=0x%08x -> %s\n",
                   f->firstPatchedRva, f->detail, NrthPrologueStateName(f->state));
        }
        printf("\n");
    }
    printf("[*] verdict: %d signature(s) found with a replaced prologue\n", tampered);
    printf("[*] only recognised footprints (E9, FF 25, 68 .. C3, C3, C2, C7 05) are counted as\n"
           "    patched; a tail match on an ordinary function prologue is ignored on purpose\n"
           "    (measured on NRTH.dll itself: 5 of the 20 patterns collide with unrelated code\n"
           "    that way, and none of them is a cheat footprint).\n");
    printf("[*] reminder: live detours/patches live in memory; run this on a read-only dump\n"
           "    of the loaded module for live evidence, and keep the file check as the\n"
           "    tamper-on-disk check. Corroborate with the other layers in the case report.\n");

    if (csv) {
        FILE *o = fopen(csv, "wb");
        if (o) {
            fprintf(o, "sig_id,target,confidence,pattern_len,full_hits,patched_hits,"
                       "first_full_rva,first_patched_rva,state,detail\n");
            for (uint32_t i = 0; i < NrthSigCount(); ++i) {
                const NrthSigFinding *f = &res[i];
                const NrthSignature *s = NrthSigAt(i + 1);
                fprintf(o, "%u,%s,%s,%u,%u,%u,0x%x,0x%x,%u,0x%x\n", s->id, s->target,
                        s->confidence == 2 ? "High" : "Medium", s->pattern_len, f->fullHits,
                        f->patchedHits, f->firstFullRva, f->firstPatchedRva, f->state, f->detail);
            }
            fclose(o);
            printf("[+] csv -> %s\n", csv);
        } else {
            fprintf(stderr, "[!] cannot write %s\n", csv);
        }
    }
    free(res);
    return tampered ? 3 : 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage();
        return 2;
    }
    const char *cmd = argv[1];
    if (strcmp(cmd, "selftest") == 0) {
        return cmd_selftest();
    }
    if (strcmp(cmd, "signatures") == 0) {
        return cmd_signatures();
    }
    if (argc < 3) {
        usage();
        return 2;
    }
    if (strcmp(cmd, "decode") == 0) {
        return cmd_decode(argc - 3, argv + 3, argv[2]);
    }
    if (strcmp(cmd, "sweep") == 0) {
        return cmd_sweep(argc - 3, argv + 3, argv[2]);
    }
    if (strcmp(cmd, "diff") == 0) {
        if (argc < 4) {
            fprintf(stderr, "[!] diff needs two files: <known-good> <loaded>\n");
            return 2;
        }
        return cmd_diff(argc - 4, argv + 4, argv[2], argv[3]);
    }
    if (strcmp(cmd, "audit") == 0) {
        return cmd_audit(argc - 3, argv + 3, argv[2]);
    }
    usage();
    return 2;
}
