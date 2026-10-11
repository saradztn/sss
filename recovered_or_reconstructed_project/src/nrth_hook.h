#pragma once
/**
 * ============================================================================
 * NRTH.dll — Interface & Hook Reconstruction Header (Result Class R2)
 * Reverse engineered from native x86 library "NRTH.dll"
 * ============================================================================
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "nrth_config.h"

#ifdef __cplusplus
extern "C" {
#endif

// Exported hook procedure required by SetWindowsHookEx injection mechanism.
// Pure pass-through to CallNextHookEx.
LRESULT CALLBACK NVXHookProc(int nCode, WPARAM wParam, LPARAM lParam);

/* Config record observed in the sample (C:\Overwack\loader_config.cfg + " menu_key=%d" +
 * " no_spoofer=%d"). Owned by nrth_hook.cpp, filled by MainInitThread, edited by the Config tab. */
NrthConfig *NrthConfigGet(void);
/* Path the reconstruction reads/writes; NULL if it could not be built. The sample's evidenced path
 * is C:\Overwack\loader_config.cfg; we keep the file beside the module (documented deviation:
 * writing to the system drive root needs elevation and creates a stray artifact on the host). */
const char *NrthConfigPath(void);

#ifdef __cplusplus
}
#endif
