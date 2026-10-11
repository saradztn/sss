/* test_nrth_config.cpp — host unit test for the config record (no Windows headers needed).
 *
 * Every expectation here is tied to the sample's own format strings:
 *   " no_spoofer=%d" (VA 0x1001fdc5) and " menu_key=%d" (VA 0x1001fd7b), both decrypted inside
 *   the function 0x1001fc10..0x10020640, alongside the path "C:\Overwack\loader_config.cfg"
 *   (VA 0x1001fcff). Default key 0x2D = VK_INSERT, matching the ImGui key name "Insert" in
 *   .rdata (off 0xec8b4) and the loader hint "pulsa INSERT: si sale el menu".
 */
#include <stdio.h>
#include <string.h>

#include "../src/nrth_config.h"

static int g_fail = 0;
#define CHECK(cond, what)                                                       \
    do {                                                                        \
        if (!(cond)) { printf("  [FAIL] %s (%s:%d)\n", (what), __FILE__, __LINE__); ++g_fail; } \
        else { printf("  [ ok ] %s\n", (what)); }                              \
    } while (0)

int main(void)
{
    NrthConfig c;
    NrthConfigInit(&c);
    CHECK(c.menuKey == 0x2D && c.noSpoofer == 0, "defaults: VK_INSERT + spoofer-not-disabled");

    /* --- format: the two observed literals, leading space kept ---------------------------- */
    char buf[256];
    int n = NrthConfigFormat(&c, buf, sizeof(buf));
    CHECK(n > 0, "format returns a length");
    CHECK(strstr(buf, " no_spoofer=0\n") != NULL, "format emits \" no_spoofer=%d\" verbatim");
    CHECK(strstr(buf, " menu_key=45\n") != NULL, "format emits \" menu_key=%d\" with VK_INSERT=45");

    /* --- round trip ----------------------------------------------------------------------- */
    NrthConfig c2;
    c2.menuKey = 0x2D; c2.noSpoofer = 1;
    n = NrthConfigFormat(&c2, buf, sizeof(buf));
    NrthConfigInit(&c);
    CHECK(NrthConfigParse(buf, &c) == 2 && c.menuKey == 0x2D && c.noSpoofer == 1,
          "round trip preserves both tokens");

    /* --- tolerance: the file is built by successive sprintf, so extra whitespace/other keys
     *     must not break a read ------------------------------------------------------------------ */
    NrthConfigInit(&c);
    CHECK(NrthConfigParse("  menu_key = 82 \n no_spoofer=0 \n volume=11\n", &c) >= 1 && c.menuKey == 0x52,
          "spaces around = tolerated, value applied");
    CHECK(NrthConfigParse("menu_key=113 no_spoofer=1", &c) == 2 && c.menuKey == 113 && c.noSpoofer == 1,
          "single-line, no trailing newline, still parses");

    /* --- out-of-range / missing values keep the previous setting --------------------------- */
    CHECK(NrthConfigParse("menu_key=99999", &c) == 1 && c.menuKey == 113,
          "VK out of 1..0xFF range is rejected, previous value kept");
    CHECK(NrthConfigParse("menu_key=-1", &c) == 1 && c.menuKey == 113,
          "negative VK rejected");
    CHECK(NrthConfigParse("no_spoofer=7", &c) == 1 && c.noSpoofer == 1,
          "any non-zero no_spoofer normalises to 1");

    /* --- failure modes -------------------------------------------------------------------- */
    CHECK(NrthConfigParse("!!! ???", &c) == NRTH_CFG_E_FORMAT, "pure junk -> E_FORMAT, not silence");
    CHECK(NrthConfigParse("", &c) == 0, "empty text -> 0 recognised tokens");
    CHECK(NrthConfigParse(NULL, &c) == NRTH_CFG_E_INVALID, "null text -> E_INVALID");
    char tiny[8];
    CHECK(NrthConfigFormat(&c, tiny, (int)sizeof(tiny)) == NRTH_CFG_E_INVALID,
          "buffer too small -> E_INVALID (no truncation)");
    CHECK(NrthConfigLoadFile("this/file/does/not/exist.cfg", &c) == NRTH_CFG_E_IO,
          "missing file -> E_IO and cfg untouched");

    /* --- save/load against a real file ---------------------------------------------------- */
    const char *path = "nrth_config_test.cfg";
    c2.noSpoofer = 1; c2.menuKey = 0x70;
    CHECK(NrthConfigSaveFile(path, &c2) == NRTH_CFG_OK, "save writes the file");
    NrthConfig c3;
    NrthConfigInit(&c3);
    CHECK(NrthConfigLoadFile(path, &c3) == 2 && c3.menuKey == 0x70 && c3.noSpoofer == 1,
          "load reads both tokens back (F1 = 0x70)");
    remove(path);

    /* --- display names for the "Menu Toggle Key" row -------------------------------------- */
    char nm[32];
    CHECK(NrthConfigKeyName(0x2D, nm, sizeof(nm)) == 6 && strcmp(nm, "Insert") == 0,
          "0x2D names as \"Insert\" (the string present in the sample)");
    CHECK(NrthConfigKeyName('M', nm, sizeof(nm)) == 1 && nm[0] == 'M', "letters name as themselves");
    CHECK(NrthConfigKeyName(0x05, nm, sizeof(nm)) > 0 && strcmp(nm, "VK_05") == 0,
          "unmapped code prints honestly as VK_05");
    CHECK(NrthConfigKeyName(0x2D, nm, 3) == NRTH_CFG_E_INVALID, "capacity is respected");

    printf(g_fail ? "\n[!] %d check(s) failed\n" : "\n[*] all config checks passed\n", g_fail);
    return g_fail ? 1 : 0;
}
