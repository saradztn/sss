/* nrth_config.h — the loader/payload config record, format + parser.
 *
 * EVIDENCE (ORIGINAL sample, Observed):
 *   "C:\Overwack\loader_config.cfg"  decrypted at VA 0x1001fcff (K=0x20, decryptor 0x1000bc80)
 *   " no_spoofer=%d"                  decrypted at VA 0x1001fdc5 (K=0x06, decryptor 0x10022150)
 *   " menu_key=%d"                    decrypted at VA 0x1001fd7b (K=0x2D, decryptor 0x10007900)
 *   all three call sites sit in the SAME function, 0x1001fc10..0x10020640, which is also where the
 *   netc.dll cluster begins — i.e. config handling and arming share an init path.
 * NOT EVIDENCED (Unknown, deliberately not invented here): which Win32 file API performs the write,
 * the key order, and whether the file is re-read on every launch. So this module reproduces the
 * *token format and parsing tolerance* implied by the two format strings — nothing more, and it makes
 * no claim about the sample's I/O ordering. Reconstruction choice: one "key=value" token per line,
 * leading spaces tolerated (the observed format strings themselves start with a space).
 *
 * This file is platform-independent on purpose (no windows.h) so the parser can be unit-tested on the
 * Linux analysis host; `int vk` values are Windows virtual-key codes by convention only.
 */
#ifndef NRTH_CONFIG_H
#define NRTH_CONFIG_H

#define NRTH_CFG_OK            0
#define NRTH_CFG_E_INVALID    -1     /* null argument / buffer too small             */
#define NRTH_CFG_E_FORMAT     -2     /* text is not a config token stream            */
#define NRTH_CFG_E_IO         -4     /* file could not be read or written            */

#define NRTH_CFG_DEFAULT_MENU_KEY 0x2D    /* VK_INSERT — matches the ImGui key name "Insert"
                                             (sample .rdata, off 0xec8b4) and the loader hint
                                             "pulsa INSERT: si sale el menu".               */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct NrthConfig {
    int menuKey;      /* VK code that toggles the overlay; 0 = unset -> default applies */
    int noSpoofer;    /* observed key "no_spoofer": non-zero disables the spoofer path.
                         This reconstruction only stores/echoes the value; it implements
                         no spoofing behaviour of any kind (case scope). */
} NrthConfig;

/* Reset to the evidenced defaults (Insert, spoofer-not-disabled). */
void NrthConfigInit(NrthConfig *cfg);

/* Write the config as the two observed tokens, one per line, each with the observed leading space
 * (" no_spoofer=%d", " menu_key=%d") so the file is byte-comparable with the sample's format
 * strings. Returns bytes written (>=0) or NRTH_CFG_E_INVALID if `cap` is too small. */
int NrthConfigFormat(const NrthConfig *cfg, char *out, int cap);

/* Parse `text`. Unknown keys and extra whitespace are skipped; a missing key keeps the value already
 * in *cfg (call NrthConfigInit first for defaults). Returns the number of recognised tokens, or
 * NRTH_CFG_E_* on malformed input. Accepts both "key=value" and " key = value". */
int NrthConfigParse(const char *text, NrthConfig *cfg);

/* File helpers (stdio only). Missing file -> NRTH_CFG_E_IO with *cfg untouched. */
int NrthConfigLoadFile(const char *path, NrthConfig *cfg);
int NrthConfigSaveFile(const char *path, const NrthConfig *cfg);

/* Short display name for a VK code, for the "Menu Toggle Key" row (evidence off 0xe9b114).
 * Writes at most `cap` bytes including NUL; returns strlen on success, else NRTH_CFG_E_INVALID. */
int NrthConfigKeyName(int vk, char *out, int cap);

#ifdef __cplusplus
}
#endif

#endif /* NRTH_CONFIG_H */
