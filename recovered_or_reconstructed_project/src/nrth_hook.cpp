/**
 * ============================================================================
 * NRTH.dll — Behavioral Reimplementation (Result Class R2)
 * Reconstructed from reverse engineering of native x86 library "NRTH.dll"
 * (SHA-256 947b81be2d0f84cc5f51742ef8e9dbf6183597ed98afaf1377bfc4352e007861)
 * ============================================================================
 * PURPOSE: authorized MTA:SA blue-team private-server validation ONLY.
 *          Not for public-server use. See mta_blue_team_case/.
 *
 * Evidence map (original VAs / RVAs — see analysis/function_map.csv):
 *   NVXHookProc        VA 0x1000b9e0 (RVA 0x0b9e0)  export ordinal 1
 *   DllMain            VA 0x1000ba00 (RVA 0x0ba00)  pin + init thread
 *   MainInitThread     VA 0x1000a850 (RVA 0x0a850)  MinHook on ntdll!LdrLoadDll
 *   Hooked_LdrLoadDll  VA 0x1000a640 (RVA 0x0a640)  trigger on client.dll/netc.dll
 *   GetD3D9DeviceVTable VA 0x10012980 (RVA 0x12980) d3d9 vtable (orig: pattern scan
 *                                                    C7 06 / 89 86)
 *   InstallD3D9Hooks   VA 0x10016500 (RVA 0x16500)  Present idx 17 / Reset idx 16
 *   Hooked_Present     VA 0x10014d50 (RVA 0x14d50)  Dear ImGui 1.92.9 WIP overlay
 *   Hooked_Reset       VA 0x1001a3c0 (RVA 0x1a3c0)  device-loss handling
 *
 * Documented R2 deviations from the original (NO capability added, NONE removed
 * from the observed chain; no new stealth/evasion introduced):
 *   1. Original strings are XOR/SSE-encrypted at rest. This reconstruction uses
 *      plaintext with per-string evidence comments (encryption NOT re-implemented).
 *   2. Original locates the D3D9 vtable by pattern-scanning d3d9.dll in memory.
 *      This reconstruction obtains the same vtable via a temporary device
 *      (equivalent observable result; more robust). Original method documented
 *      in GetD3D9DeviceVTable() comments.
 *   3. Menu FEATURE SLOTS are labeled stubs: the original's per-feature logic
 *      (init routines at 0x10005b80 / 0x10020640) is class U (unresolved) and is
 *      deliberately NOT invented here.
 *
 * Target Architecture : x86 32-bit (PE32 DLL), matching the sample
 * Hook engine         : MinHook (the sample embeds MinHook v1.3.3)
 * UI engine           : Dear ImGui v1.92.9 (sample embeds 1.92.9 WIP (19283))
 * ============================================================================
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d9.h>
#include <stdio.h>
#include <string.h>

#include "MinHook.h"
#include "imgui.h"
#include "imgui_impl_dx9.h"
#include "imgui_impl_win32.h"
#include "nrth_hook.h"

// ---------------------------------------------------------------------------
// Minimal NT types (avoid winternl.h dependencies)
// ---------------------------------------------------------------------------
typedef LONG NTSTATUS;
typedef struct _NVX_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} NVX_UNICODE_STRING;

typedef NTSTATUS (NTAPI *PFN_LdrLoadDll)(PWSTR, PULONG, NVX_UNICODE_STRING *, PVOID *);
typedef HRESULT  (WINAPI *PFN_Present)(IDirect3DDevice9 *, const RECT *, const RECT *, HWND, const RGNDATA *);
typedef HRESULT  (WINAPI *PFN_Reset)(IDirect3DDevice9 *, D3DPRESENT_PARAMETERS *);
typedef IDirect3D9 *(WINAPI *PFN_Direct3DCreate9)(UINT);

// ---------------------------------------------------------------------------
// Global state (mirrors the observed module-level state of the sample)
// ---------------------------------------------------------------------------
static PFN_LdrLoadDll   g_pOrigLdrLoadDll   = NULL; // RVA 0x0a640 hook target
static PFN_Present      g_pOrigPresent      = NULL; // vtable slot 17 (0x44)
static PFN_Reset        g_pOrigReset        = NULL; // vtable slot 16 (0x40)
static bool             g_bMtaArmed         = false; // client.dll/netc.dll seen
static bool             g_bOverlayInit      = false;
static bool             g_bMenuOpen         = false; // toggled by VK_INSERT
static IDirect3DDevice9 *g_pDevice          = NULL;
static HWND             g_hGameWnd          = NULL;
static WNDPROC          g_pOrigWndProc      = NULL;

// ---------------------------------------------------------------------------
// Exported hook procedure (export ordinal 1, name "NVXHookProc").
// Pure pass-through — exists to satisfy the SetWindowsHookEx injection contract
// used by the loader (evidence: loader string "[+] Inyectado OK por hook").
// ---------------------------------------------------------------------------
extern "C" LRESULT CALLBACK NVXHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

// ---------------------------------------------------------------------------
// Forward declarations (internal labels match analysis/function_map.csv)
// ---------------------------------------------------------------------------
static DWORD WINAPI MainInitThread(LPVOID lpParam);      // orig VA 0x1000a850
static NTSTATUS NTAPI Hooked_LdrLoadDll(PWSTR, PULONG, NVX_UNICODE_STRING *, PVOID *); // 0x1000a640
static void **GetD3D9DeviceVTable(void);                  // 0x10012980
static bool InstallD3D9Hooks(void **vtable);             // 0x10016500
static HRESULT WINAPI Hooked_Present(IDirect3DDevice9 *, const RECT *, const RECT *, HWND, const RGNDATA *); // 0x10014d50
static HRESULT WINAPI Hooked_Reset(IDirect3DDevice9 *, D3DPRESENT_PARAMETERS *);  // 0x1001a3c0
static LRESULT CALLBACK GameWndProc(HWND, UINT, WPARAM, LPARAM);
static void BuildOverlayMenu(void);
static void EnsureOverlayInitialized(IDirect3DDevice9 *pDevice);
static const char *BaseNameA(const char *path);

// ===========================================================================
// DllMain — evidence VA 0x1000ba00
//   DLL_PROCESS_ATTACH: DisableThreadLibraryCalls, pin module
//   (GET_MODULE_HANDLE_EX_FLAG_PIN — observed self-protection), spawn init thread.
// ===========================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    (void)lpReserved;
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        // Observed in the sample: pin the module so FreeLibrary cannot unload it.
        HMODULE hPinned = NULL;
        GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
            (LPCSTR)DllMain,
            &hPinned);

        HANDLE hThread = CreateThread(NULL, 0, MainInitThread, hModule, 0, NULL);
        if (hThread) {
            CloseHandle(hThread);
        }
    }
    return TRUE;
}

// ===========================================================================
// MainInitThread — evidence VA 0x1000a850
// Original behavior (strings XOR/SSE-encrypted; reconstructed plaintext):
//   1. references config dir "C:\NVX"           (string VA 0x1000afd18)
//   2. resolves ntdll.dll!LdrLoadDll            (strings 'ntdll.dll','LdrLoadDll')
//   3. MinHook inline hook -> Hooked_LdrLoadDll
// ===========================================================================
static DWORD WINAPI MainInitThread(LPVOID lpParam)
{
    (void)lpParam;

    // Step 1: config directory referenced by the sample (use Tentative — exact
    // I/O unknown). We only record its presence marker like the original did
    // before hooking (no file writes performed here).
    // "C:\NVX"  [evidence VA 0x1000afd18]
    DWORD attr = GetFileAttributesA("C:\\NVX");
    (void)attr;

    // Step 2: resolve ntdll!LdrLoadDll
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");   // ['ntdll.dll' VA 0x1000a8.. set]
    if (!hNtdll) {
        return 1;
    }
    FARPROC pLdrLoadDll = GetProcAddress(hNtdll, "LdrLoadDll"); // ['LdrLoadDll']
    if (!pLdrLoadDll) {
        return 1;
    }

    // Step 3: MinHook v1.3.3-style inline hook (engine vendored in vendor/minhook)
    if (MH_Initialize() != MH_OK) {
        return 1;
    }
    if (MH_CreateHook((LPVOID)pLdrLoadDll, (LPVOID)&Hooked_LdrLoadDll, (LPVOID *)&g_pOrigLdrLoadDll) != MH_OK) {
        return 1;
    }
    if (MH_EnableHook((LPVOID)pLdrLoadDll) != MH_OK) {
        return 1;
    }
    return 0;
}

// ===========================================================================
// Hooked_LdrLoadDll — evidence VA 0x1000a640
// Pass-through wrapper around the original that watches each loaded module.
// When the MTA:SA framework modules 'client.dll' or 'netc.dll' appear
// (decrypted strings in the sample), arm the D3D9 overlay chain once.
// ===========================================================================
static NTSTATUS NTAPI Hooked_LdrLoadDll(PWSTR SearchPath, PULONG DllCharacteristics,
                                        NVX_UNICODE_STRING *ModuleFileName, PVOID *DllHandle)
{
    NTSTATUS status = g_pOrigLdrLoadDll(SearchPath, DllCharacteristics, ModuleFileName, DllHandle);

    if (status >= 0 && DllHandle && *DllHandle && !g_bMtaArmed) {
        char name[MAX_PATH] = {0};
        // Resolve the just-loaded module's base name and compare.
        if (GetModuleFileNameA((HMODULE)*DllHandle, name, MAX_PATH) != 0) {
            const char *base = BaseNameA(name);
            // Decrypted strings in the sample: 'client.dll' (VA set 0x1000a640 block)
            // and 'netc.dll'. Either one indicates the MTA:SA framework is up.
            if (_stricmp(base, "client.dll") == 0 || _stricmp(base, "netc.dll") == 0) {
                g_bMtaArmed = true;
                // Follow-on init in the original: 0x10005b80 + 0x10020640 (class U —
                // feature logic not fully mapped; deliberately not invented).
                // The overlay chain (observed) is what we reconstruct:
                void **vtable = GetD3D9DeviceVTable();
                if (vtable) {
                    InstallD3D9Hooks(vtable);
                }
            }
        }
    }
    return status;
}

// ===========================================================================
// GetD3D9DeviceVTable — evidence VA 0x10012980
// ORIGINAL METHOD (documented, not re-implemented): pattern-scanned d3d9.dll
// in memory for the IDirect3DDevice9 vtable store sites (byte patterns
// 'C7 06 .. .. .. ..' / '89 86 .. .. .. ..').
// R2 DEVIATION: obtain the identical vtable pointer from a temporary hidden
// window + Direct3DCreate9 device (same observable result, robust across
// Windows builds). d3d9 is resolved dynamically (no import-table dependency).
// ===========================================================================
static void **GetD3D9DeviceVTable(void)
{
    static void **pCachedVTable = NULL;
    if (pCachedVTable) {
        return pCachedVTable;
    }

    HMODULE hD3D = GetModuleHandleA("d3d9.dll"); // string 'd3d9.dll' [evidence RVA 0x12980 refs]
    if (!hD3D) {
        hD3D = LoadLibraryA("d3d9.dll");
    }
    if (!hD3D) {
        return NULL;
    }
    PFN_Direct3DCreate9 pCreate = (PFN_Direct3DCreate9)GetProcAddress(hD3D, "Direct3DCreate9");
    if (!pCreate) {
        return NULL;
    }

    WNDCLASSA wc = {0};
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "NVXD3DDummyWnd";
    if (!RegisterClassA(&wc)) {
        // class may already exist
    }
    HWND hWnd = CreateWindowExA(0, wc.lpszClassName, "", WS_OVERLAPPED,
                                0, 0, 32, 32, NULL, NULL, wc.hInstance, NULL);
    if (!hWnd) {
        return NULL;
    }

    IDirect3D9 *pD3D = pCreate(D3D_SDK_VERSION);
    if (!pD3D) {
        DestroyWindow(hWnd);
        return NULL;
    }

    D3DPRESENT_PARAMETERS pp;
    ZeroMemory(&pp, sizeof(pp));
    pp.Windowed = TRUE;
    pp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    pp.hDeviceWindow = hWnd;

    IDirect3DDevice9 *pDev = NULL;
    HRESULT hr = pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hWnd,
                                    D3DCREATE_SOFTWARE_VERTEXPROCESSING, &pp, &pDev);
    if (FAILED(hr) || !pDev) {
        pD3D->Release();
        DestroyWindow(hWnd);
        return NULL;
    }

    // First DWORD of the COM object is the vtable pointer (lives in d3d9.dll .rdata,
    // remains valid after we release the temporary objects).
    pCachedVTable = *(void ***)pDev;

    pDev->Release();
    pD3D->Release();
    DestroyWindow(hWnd);
    UnregisterClassA(wc.lpszClassName, wc.hInstance);
    return pCachedVTable;
}

// ===========================================================================
// InstallD3D9Hooks — evidence VA 0x10016500
// MinHook detours on IDirect3DDevice9::Present (index 17 / offset 0x44) and
// IDirect3DDevice9::Reset   (index 16 / offset 0x40).
// ===========================================================================
static bool InstallD3D9Hooks(void **vtable)
{
    if (!vtable) {
        return false;
    }
    if (MH_CreateHook(vtable[17], (LPVOID)&Hooked_Present, (LPVOID *)&g_pOrigPresent) != MH_OK) {
        return false;
    }
    if (MH_CreateHook(vtable[16], (LPVOID)&Hooked_Reset, (LPVOID *)&g_pOrigReset) != MH_OK) {
        return false;
    }
    MH_EnableHook(vtable[17]);
    MH_EnableHook(vtable[16]);
    return true;
}

// ===========================================================================
// ImGui overlay (evidence: "Dear ImGui 1.92.9 WIP (19283)", window IDs
// "%s##nvx_top_%d" / "##nvx_content", self-title "North Cheat", "Menu Toggle
// Key", key "Insert" — loader hint: "pulsa INSERT: si sale el menu").
// ===========================================================================
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

static LRESULT CALLBACK GameWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) {
        return 1;
    }
    return CallWindowProcA(g_pOrigWndProc, hWnd, msg, wParam, lParam);
}

static void EnsureOverlayInitialized(IDirect3DDevice9 *pDevice)
{
    if (g_bOverlayInit) {
        return;
    }
    g_pDevice = pDevice;

    // The game window: the sample renders into the foreground game window.
    g_hGameWnd = GetForegroundWindow();
    if (!g_hGameWnd) {
        return;
    }

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::StyleColorsDark();
    ImGui_ImplWin32_Init(g_hGameWnd);
    ImGui_ImplDX9_Init(pDevice);

    // Input routing for the overlay (required by the ImGui Win32 backend).
    g_pOrigWndProc = (WNDPROC)SetWindowLongA(g_hGameWnd, GWL_WNDPROC, (LONG)GameWndProc);

    g_bOverlayInit = true;
}

// Menu shell faithful to observed strings; feature slots are STUBS on purpose
// (original feature logic at 0x10005b80 / 0x10020640 is class U — not invented).
static void BuildOverlayMenu(void)
{
    // Evidence: ImGui main menu bar IDs '##MainMenuBar', item names 'Menu','Cheat',
    // content window '##nvx_content'.
    if (ImGui::BeginMainMenuBar()) {
        if (ImGui::BeginMenu("Menu")) {
            ImGui::MenuItem("About", NULL, false);
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Cheat")) {
            ImGui::MenuItem("(feature slots below)", NULL, false);
            ImGui::EndMenu();
        }
        ImGui::EndMainMenuBar();
    }

    ImGui::SetNextWindowSize(ImVec2(360, 220), ImGuiCond_FirstUseEver);
    if (ImGui::Begin("North Cheat")) { // self-title string [evidence VA 0x1000e90d8]
        ImGui::Text("NRTH overlay menu  (R2 reconstruction)");
        ImGui::Text("Menu Toggle Key: Insert");          // [evidence VA 0x1000eb114]
        ImGui::Separator();
        static bool s_slot1 = false, s_slot2 = false, s_slot3 = false;
        ImGui::Checkbox("Feature slot 1  (U - unmapped in RE)", &s_slot1);
        ImGui::Checkbox("Feature slot 2  (U - unmapped in RE)", &s_slot2);
        ImGui::Checkbox("Feature slot 3  (U - unmapped in RE)", &s_slot3);
        ImGui::TextDisabled("Original feature logic (0x10005b80 / 0x10020640) not");
        ImGui::TextDisabled("fully mapped; stubs shown instead of invented features.");
    }
    ImGui::End();
}

// ===========================================================================
// Hooked_Present — evidence VA 0x10014d50: renders the Dear ImGui overlay each
// frame; toggled with VK_INSERT.
// ===========================================================================
static HRESULT WINAPI Hooked_Present(IDirect3DDevice9 *pDevice, const RECT *pSrc,
                                     const RECT *pDest, HWND hDestWindow, const RGNDATA *pDirty)
{
    EnsureOverlayInitialized(pDevice);

    if (g_bOverlayInit) {
        // Observed toggle: INSERT (loader console hint + ImGui key name 'Insert').
        if (GetAsyncKeyState(VK_INSERT) & 1) {
            g_bMenuOpen = !g_bMenuOpen;
        }

        ImGui_ImplDX9_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        if (g_bMenuOpen) {
            BuildOverlayMenu();
        }

        ImGui::EndFrame();
        ImGui::Render();
        ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
    }

    return g_pOrigPresent(pDevice, pSrc, pDest, hDestWindow, pDirty);
}

// ===========================================================================
// Hooked_Reset — evidence VA 0x1001a3c0: invalidate/recreate ImGui device
// objects around the original Reset (resize / mode-change survival).
// ===========================================================================
static HRESULT WINAPI Hooked_Reset(IDirect3DDevice9 *pDevice, D3DPRESENT_PARAMETERS *pParams)
{
    if (g_bOverlayInit) {
        ImGui_ImplDX9_InvalidateDeviceObjects();
    }
    HRESULT hr = g_pOrigReset(pDevice, pParams);
    if (SUCCEEDED(hr) && g_bOverlayInit) {
        ImGui_ImplDX9_CreateDeviceObjects();
    }
    return hr;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static const char *BaseNameA(const char *path)
{
    const char *slash = strrchr(path, '\\');
    return slash ? slash + 1 : path;
}
