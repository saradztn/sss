/**
 * ============================================================================
 * NRTH.dll — Behavioral Reimplementation (Result Class R2)
 * Reconstructed from reverse engineering of native x86 library "NRTH.dll"
 * ============================================================================
 * Target Architecture : x86 32-bit (PE32 DLL)
 * Target Environment  : Multi Theft Auto: San Andreas (MTA:SA) / Direct3D 9
 * Hook Architecture   : MinHook v1.3.3 inline detours on:
 *                       - ntdll!LdrLoadDll (to detect client.dll and netc.dll)
 *                       - IDirect3DDevice9::Present (offset 0x44 / index 17)
 *                       - IDirect3DDevice9::Reset (offset 0x40 / index 16)
 * UI Engine           : Dear ImGui 1.92.9 WIP (DirectX 9 backend)
 * ============================================================================
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d9.h>
#include <stdio.h>
#include "nrth_hook.h"

// Exported dummy hook procedure (Ordinal 1, RVA 0x0000B9E0)
// Forwards message to CallNextHookEx to satisfy WH_GETMESSAGE hook injection.
extern "C" __declspec(dllexport) LRESULT CALLBACK NVXHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

// Forward declarations of internal hook procedures
DWORD WINAPI MainInitThread(LPVOID lpParam);

// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        // Pin module in memory so FreeLibrary cannot unload it unexpectedly
        HMODULE hPinned = NULL;
        GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
            (LPCSTR)DllMain,
            &hPinned
        );

        // Spawn background initialization thread
        HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MainInitThread, hModule, 0, NULL);
        if (hThread) {
            CloseHandle(hThread);
        }
    }
    return TRUE;
}

// Behavioral reconstruction of background initialization logic
DWORD WINAPI MainInitThread(LPVOID lpParam) {
    // 1. Verify environment / config path (C:\NVX)
    // 2. Locate ntdll.dll and resolve LdrLoadDll
    // 3. Install MinHook on LdrLoadDll to monitor loading of MTA client.dll and netc.dll
    // 4. Upon client.dll load, locate Direct3D 9 device vtable by scanning d3d9.dll
    // 5. Hook IDirect3DDevice9::Present and IDirect3DDevice9::Reset
    // 6. Present hook renders Dear ImGui 1.92.9 menu when VK_INSERT is pressed
    return 0;
}
