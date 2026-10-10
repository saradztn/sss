#pragma once
/**
 * ============================================================================
 * NRTH.dll — Interface & Hook Reconstruction Header (Result Class R2)
 * Reverse engineered from native x86 library "NRTH.dll"
 * ============================================================================
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Exported hook procedure required by SetWindowsHookEx injection mechanism.
// Pure pass-through to CallNextHookEx.
__declspec(dllexport) LRESULT CALLBACK NVXHookProc(int nCode, WPARAM wParam, LPARAM lParam);

#ifdef __cplusplus
}
#endif
