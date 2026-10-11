/* nrth_config.cpp — see nrth_config.h for the evidence and the scope of each claim. */
#include "nrth_config.h"

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void NrthConfigInit(NrthConfig *cfg)
{
    if (!cfg) {
        return;
    }
    cfg->menuKey = NRTH_CFG_DEFAULT_MENU_KEY;
    cfg->noSpoofer = 0;
}

int NrthConfigFormat(const NrthConfig *cfg, char *out, int cap)
{
    if (!cfg || !out || cap <= 0) {
        return NRTH_CFG_E_INVALID;
    }
    /* The two literals below are the sample's own format strings, verbatim (see the header).
     * A newline separates them because a single-line form would be an invention. */
    int n1 = snprintf(out, (size_t)cap, " no_spoofer=%d\n", cfg->noSpoofer);
    if (n1 < 0 || n1 >= cap) {
        return NRTH_CFG_E_INVALID;
    }
    int n2 = snprintf(out + n1, (size_t)(cap - n1), " menu_key=%d\n", cfg->menuKey);
    if (n2 < 0 || n2 >= cap - n1) {
        return NRTH_CFG_E_INVALID;
    }
    return n1 + n2;
}

static const char *skipws(const char *p)
{
    while (*p && isspace((unsigned char)*p)) {
        ++p;
    }
    return p;
}

/* read "[ \t]*name[ \t]*=[ \t]*[-+]?[0-9]+" — returns the parsed integer through *val and the
 * new pointer, or NULL when the run does not parse as a token. */
static const char *read_token(const char *p, char *name, size_t nameCap, long *val)
{
    size_t i = 0;
    p = skipws(p);
    if (!*p) {
        return NULL;
    }
    while (*p && (isalnum((unsigned char)*p) || *p == '_')) {
        if (i + 1 < nameCap) {
            name[i++] = (char)*p;
        } else {
            return NULL;                       /* name too long -> refuse, don't truncate silently */
        }
        ++p;
    }
    name[i] = '\0';
    if (i == 0) {
        return NULL;
    }
    p = skipws(p);
    if (*p != '=') {
        return NULL;
    }
    p = skipws(p + 1);
    char *end = NULL;
    long v = strtol(p, &end, 10);
    if (end == p) {
        return NULL;
    }
    *val = v;
    return end;
}

int NrthConfigParse(const char *text, NrthConfig *cfg)
{
    if (!text || !cfg) {
        return NRTH_CFG_E_INVALID;
    }
    const char *p = text;
    int recognised = 0;
    int junk = 0;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
            ++p;
        }
        if (!*p) {
            break;
        }
        char name[32];
        long v = 0;
        const char *next = read_token(p, name, sizeof(name), &v);
        if (!next) {
            /* Unknown / malformed run: skip one word and keep going, because the sample's buffer is
             * built by successive sprintf calls with leading spaces, so a tolerant reader is the
             * faithful choice. If *only* junk was seen, the caller gets E_FORMAT (never silence). */
            const char *q = p;
            while (*q && !isspace((unsigned char)*q)) {
                ++q;
            }
            p = (q == p) ? p + 1 : q;
            junk = 1;
            continue;
        }
        if (strcmp(name, "menu_key") == 0) {
            cfg->menuKey = (v > 0 && v <= 0xFF) ? (int)v : cfg->menuKey;
            ++recognised;
        } else if (strcmp(name, "no_spoofer") == 0) {
            cfg->noSpoofer = v ? 1 : 0;
            ++recognised;
        }
        p = next;
    }
    if (recognised == 0 && junk) {
        return NRTH_CFG_E_FORMAT;
    }
    return recognised;
}

int NrthConfigLoadFile(const char *path, NrthConfig *cfg)
{
    if (!path || !cfg) {
        return NRTH_CFG_E_INVALID;
    }
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        return NRTH_CFG_E_IO;
    }
    char buf[1024];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[n] = '\0';
    NrthConfig copy = *cfg;
    int r = NrthConfigParse(buf, &copy);
    if (r < 0) {
        return r;
    }
    *cfg = copy;
    return r;
}

int NrthConfigSaveFile(const char *path, const NrthConfig *cfg)
{
    if (!path || !cfg) {
        return NRTH_CFG_E_INVALID;
    }
    char buf[256];
    int n = NrthConfigFormat(cfg, buf, sizeof(buf));
    if (n < 0) {
        return n;
    }
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        return NRTH_CFG_E_IO;
    }
    size_t w = fwrite(buf, 1, (size_t)n, fp);
    fclose(fp);
    return w == (size_t)n ? NRTH_CFG_OK : NRTH_CFG_E_IO;
}

/* Display names for the "Menu Toggle Key" row. Only the keys a user can plausibly bind are named;
 * everything else prints as VK_xx so the UI never lies about an unmapped code. */
int NrthConfigKeyName(int vk, char *out, int cap)
{
    static const struct { int vk; const char *name; } kNames[] = {
        { 0x08, "Backspace" }, { 0x09, "Tab" }, { 0x1B, "Escape" }, { 0x20, "Space" },
        { 0x21, "PageUp" },    { 0x22, "PageDown" }, { 0x23, "End" }, { 0x24, "Home" },
        { 0x25, "Left" },      { 0x26, "Up" },  { 0x27, "Right" }, { 0x28, "Down" },
        { 0x2D, "Insert" },    { 0x2E, "Delete" }, { 0x2F, "Help" },
        { 0x60, "Keypad0" },   { 0x61, "Keypad1" }, { 0x62, "Keypad2" }, { 0x63, "Keypad3" },
        { 0x64, "Keypad4" },   { 0x65, "Keypad5" }, { 0x66, "Keypad6" }, { 0x67, "Keypad7" },
        { 0x68, "Keypad8" },   { 0x69, "Keypad9" },
        { 0x70, "F1" },  { 0x71, "F2" },  { 0x72, "F3" },  { 0x73, "F4" },
        { 0x74, "F5" },  { 0x75, "F6" },  { 0x76, "F7" },  { 0x77, "F8" },
        { 0x78, "F9" },  { 0x79, "F10" }, { 0x7A, "F11" }, { 0x7B, "F12" },
    };
    if (!out || cap <= 0) {
        return NRTH_CFG_E_INVALID;
    }
    for (size_t i = 0; i < sizeof(kNames) / sizeof(kNames[0]); ++i) {
        if (kNames[i].vk == vk) {
            int n = snprintf(out, (size_t)cap, "%s", kNames[i].name);
            return (n >= 0 && n < cap) ? n : NRTH_CFG_E_INVALID;
        }
    }
    if (vk >= 'A' && vk <= 'Z') {
        if (cap < 2) {
            return NRTH_CFG_E_INVALID;
        }
        out[0] = (char)vk;
        out[1] = '\0';
        return 1;
    }
    if (vk >= '0' && vk <= '9') {
        if (cap < 2) {
            return NRTH_CFG_E_INVALID;
        }
        out[0] = (char)vk;
        out[1] = '\0';
        return 1;
    }
    int n = snprintf(out, (size_t)cap, "VK_%02X", vk & 0xFF);
    return (n >= 0 && n < cap) ? n : NRTH_CFG_E_INVALID;
}
