/**
 * ============================================================================
 * NORTH LOADER — Behavioral Reimplementation (Result Class R2)
 * Reconstructed from reverse engineering of native x86 binary "NORTH LOADER.exe"
 * ============================================================================
 * Target Architecture : x86 32-bit (PE32)
 * Original Compiler   : Microsoft Visual C++ 2015-2022 (v140/v141/v142/v143) Debug
 * Original PDB Path   : C:\Users\user\Desktop\src CHEATS\over\Loader\Debug\NVX Loader.pdb
 * ============================================================================
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "psapi.lib")

// Note: MSVC CRT and mingw-w64's sec_api both provide strcpy_s/strcat_s natively;
// call sites below use them directly (portable across both toolchains).

// Enables SeDebugPrivilege in the current process token
bool EnableDebugPrivilege() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool success = false;
    if (LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid)) {
        if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
            success = true;
        }
    }

    CloseHandle(hToken);
    return success;
}

// Checks if a file exists and is not a directory
bool FileExists(const char* path) {
    DWORD attr = GetFileAttributesA(path);
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        return false;
    }
    return true;
}

// Finds the first process ID with the matching executable name (case-insensitive)
DWORD FindProcessByName(const char* exeName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    DWORD pid = 0;
    if (Process32First(hSnap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, exeName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return pid;
}

// Finds the first thread ID belonging to a given PID
DWORD FindThreadInProcess(DWORD pid) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);

    DWORD tid = 0;
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                tid = te.th32ThreadID;
                break;
            }
        } while (Thread32Next(hSnap, &te));
    }

    CloseHandle(hSnap);
    return tid;
}

// Helper struct and functions to map RVAs to file offsets in an unmapped PE image
struct SectionMapper {
    WORD numberOfSections;
    IMAGE_SECTION_HEADER* sections;
};

void InitPeSectionMapper(struct SectionMapper* mapper, WORD numSections, IMAGE_SECTION_HEADER* sections) {
    mapper->numberOfSections = numSections;
    mapper->sections = sections;
}

DWORD rva2off(struct SectionMapper* mapper, DWORD rva) {
    for (WORD i = 0; i < mapper->numberOfSections; i++) {
        IMAGE_SECTION_HEADER* sec = &mapper->sections[i];
        if (rva >= sec->VirtualAddress && rva < sec->VirtualAddress + sec->Misc.VirtualSize) {
            return (rva - sec->VirtualAddress) + sec->PointerToRawData;
        }
    }
    return 0;
}

// Parses on-disk PE headers and export table to locate an exported function's RVA
bool FindExportRvaInFile(const char* dllPath, const char* exportName, DWORD* outRva) {
    HANDLE hFile = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) {
        CloseHandle(hFile);
        return false;
    }

    BYTE* pBase = (BYTE*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!pBase) {
        CloseHandle(hMap);
        CloseHandle(hFile);
        return false;
    }

    bool found = false;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pBase;
    if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(pBase + dos->e_lfanew);
        if (nt->Signature == IMAGE_NT_SIGNATURE) {
            DWORD exportDirRva = 0;
            if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
                IMAGE_NT_HEADERS32* nt32 = (IMAGE_NT_HEADERS32*)nt;
                exportDirRva = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            } else if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
                IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)nt;
                exportDirRva = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            }

            WORD numSections = nt->FileHeader.NumberOfSections;
            IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)((BYTE*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

            struct SectionMapper mapper;
            InitPeSectionMapper(&mapper, numSections, sections);

            DWORD exportDirOff = rva2off(&mapper, exportDirRva);
            if (exportDirOff != 0) {
                IMAGE_EXPORT_DIRECTORY* expDir = (IMAGE_EXPORT_DIRECTORY*)(pBase + exportDirOff);
                DWORD namesOff = rva2off(&mapper, expDir->AddressOfNames);
                DWORD funcsOff = rva2off(&mapper, expDir->AddressOfFunctions);
                DWORD ordsOff  = rva2off(&mapper, expDir->AddressOfNameOrdinals);

                if (namesOff && funcsOff && ordsOff) {
                    DWORD* nameRvas = (DWORD*)(pBase + namesOff);
                    DWORD* funcRvas = (DWORD*)(pBase + funcsOff);
                    WORD* ordinals  = (WORD*)(pBase + ordsOff);

                    for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
                        DWORD nameOff = rva2off(&mapper, nameRvas[i]);
                        if (nameOff != 0) {
                            const char* curName = (const char*)(pBase + nameOff);
                            if (strcmp(curName, exportName) == 0) {
                                WORD ord = ordinals[i];
                                *outRva = funcRvas[ord];
                                found = true;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    UnmapViewOfFile(pBase);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return found;
}

// Verifies if the target DLL has been loaded into the process using K32EnumProcessModules
bool IsModuleLoadedInProcess(DWORD pid, const char* moduleName) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        return false;
    }

    HMODULE hMods[512];
    DWORD cbNeeded = 0;
    bool found = false;

    if (K32EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
        DWORD count = cbNeeded / sizeof(HMODULE);
        if (count > 512) count = 512;

        for (DWORD i = 0; i < count; i++) {
            char baseName[MAX_PATH];
            baseName[0] = '\0';
            if (K32GetModuleBaseNameA(hProc, hMods[i], baseName, MAX_PATH)) {
                if (_stricmp(baseName, moduleName) == 0) {
                    found = true;
                    break;
                }
            }
        }
    }

    CloseHandle(hProc);
    return found;
}

// Classic injection method via CreateRemoteThread & LoadLibraryA
// Returns 0 on success, 1 on generic failure, 2 on access denied
int InjectClassic(DWORD pid, const char* dllPath) {
    DWORD desiredAccess = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                          PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
    HANDLE hProc = OpenProcess(desiredAccess, FALSE, pid);
    if (!hProc) {
        DWORD err = GetLastError();
        printf("[!] OpenProcess fallo (%lu).\n", err);
        return (err == ERROR_ACCESS_DENIED) ? 2 : 1;
    }

    size_t pathLen = strlen(dllPath) + 1;
    LPVOID pRemoteBuf = VirtualAllocEx(hProc, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteBuf) {
        DWORD err = GetLastError();
        printf("[!] VirtualAllocEx fallo (%lu)\n", err);
        CloseHandle(hProc);
        return (err == ERROR_ACCESS_DENIED) ? 2 : 1;
    }

    if (!WriteProcessMemory(hProc, pRemoteBuf, dllPath, pathLen, NULL)) {
        DWORD err = GetLastError();
        printf("[!] WriteProcessMemory fallo (%lu)\n", err);
        VirtualFreeEx(hProc, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return (err == ERROR_ACCESS_DENIED) ? 2 : 1;
    }

    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLib = hKernel ? GetProcAddress(hKernel, "LoadLibraryA") : NULL;
    if (!pLoadLib) {
        printf("[!] No se resolvio LoadLibraryA\n");
        VirtualFreeEx(hProc, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLib, pRemoteBuf, 0, NULL);
    if (!hThread) {
        DWORD err = GetLastError();
        printf("[!] CreateRemoteThread fallo (%lu)\n", err);
        VirtualFreeEx(hProc, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return (err == ERROR_ACCESS_DENIED) ? 2 : 1;
    }

    DWORD remoteMod = 0;
    if (WaitForSingleObject(hThread, 15000) == WAIT_OBJECT_0) {
        GetExitCodeThread(hThread, &remoteMod);
    }

    CloseHandle(hThread);
    VirtualFreeEx(hProc, pRemoteBuf, 0, MEM_RELEASE);
    CloseHandle(hProc);

    if (remoteMod == 0) {
        printf("[!] LoadLibrary remoto devolvio NULL (DLL bloqueado o arquitectura distinta).\n");
        return 1;
    }

    printf("[+] Inyectado OK clasico (modulo=0x%08lX)\n", remoteMod);
    return 0;
}

// Hook injection method via SetWindowsHookEx (WH_GETMESSAGE) & NVXHookProc
bool InjectHook(DWORD pid, const char* dllPath) {
    HMODULE hMod = LoadLibraryA(dllPath);
    HOOKPROC pfn = NULL;

    if (hMod != NULL) {
        pfn = (HOOKPROC)GetProcAddress(hMod, "NVXHookProc");
        if (!pfn) {
            printf("[!] El DLL no exporta NVXHookProc (usa el NRTH.dll recien compilado).\n");
            FreeLibrary(hMod);
            return false;
        }
    } else {
        printf("[*] LoadLibrary local fallo (%lu); mapeando sin ejecutar...\n", GetLastError());
        DWORD rva = 0;
        if (!FindExportRvaInFile(dllPath, "NVXHookProc", &rva)) {
            printf("[!] No se hallo el export NVXHookProc en el archivo.\n");
            return false;
        }

        hMod = LoadLibraryExA(dllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (!hMod) {
            printf("[!] Mapeo sin ejecutar fallo (%lu)\n", GetLastError());
            return false;
        }

        pfn = (HOOKPROC)((BYTE*)hMod + rva);
        printf("[*] Export NVXHookProc en RVA 0x%08lX\n", rva);
    }

    DWORD threadId = FindThreadInProcess(pid);
    if (threadId == 0) {
        printf("[!] No se hallo hilo en el proceso.\n");
        FreeLibrary(hMod);
        return false;
    }

    HHOOK hHook = SetWindowsHookExA(WH_GETMESSAGE, pfn, hMod, threadId);
    if (!hHook) {
        printf("[!] SetWindowsHookEx fallo (%lu)\n", GetLastError());
        FreeLibrary(hMod);
        return false;
    }

    printf("[*] Hook instalado, despertando el hilo del juego...\n");
    for (int i = 0; i < 10; i++) {
        PostThreadMessageA(threadId, WM_NULL, 0, 0);
        Sleep(200);
    }
    Sleep(500);

    UnhookWindowsHookEx(hHook);
    FreeLibrary(hMod);

    const char* filename = strrchr(dllPath, '\\');
    filename = filename ? filename + 1 : dllPath;

    if (IsModuleLoadedInProcess(pid, filename)) {
        printf("[+] Inyectado OK por hook (modulo verificado en el proceso).\n");
        return true;
    } else {
        printf("[*] Hook completado. Entra al juego y pulsa INSERT: si sale el menu, quedo.\n");
        return true;
    }
}

int main(int argc, char* argv[]) {
    SetConsoleTitleA("NORTH Loader");

    const char* app = "gta_sa.exe";
    char dllPath[MAX_PATH];
    dllPath[0] = '\0';
    bool autoclose = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--autoclose") == 0) {
            autoclose = true;
        } else if (strcmp(argv[i], "--proc") == 0 && i + 1 < argc) {
            app = argv[++i];
        } else if (strcmp(argv[i], "--dll") == 0 && i + 1 < argc) {
            strcpy_s(dllPath, sizeof(dllPath), argv[++i]);
        } else if (argv[i][0] != '-' && dllPath[0] == '\0') {
            size_t len = strlen(argv[i]);
            if (len > 4 && _stricmp(argv[i] + len - 4, ".dll") == 0) {
                strcpy_s(dllPath, sizeof(dllPath), argv[i]);
            }
        }
    }

    if (dllPath[0] == '\0') {
        char self[MAX_PATH];
        self[0] = '\0';
        GetModuleFileNameA(NULL, self, MAX_PATH);
        char* lastSlash = strrchr(self, '\\');
        size_t dirLen = lastSlash ? (lastSlash - self) : 0;

        char base[MAX_PATH];
        base[0] = '\0';
        if (dirLen > 0 && dirLen < MAX_PATH - 14) {
            memcpy(base, self, dirLen);
            base[dirLen] = '\0';
            strcat_s(base, sizeof(base), "\\NRTH.dll");
            strcpy_s(dllPath, sizeof(dllPath), base);
        }
    }

    printf("=== NORTH Loader ===\n");
    printf("DLL : %s\n", dllPath[0] ? dllPath : "(no encontrado)");
    printf("APP : %s\n", app);

    EnableDebugPrivilege();

    if (!FileExists(dllPath)) {
        printf("[!] No existe el DLL. Pon NRTH.dll junto al loader o pasa la ruta.\n");
        if (!autoclose) {
            printf("Pulsa ENTER para salir...\n");
            getchar();
        }
        return 1;
    }

    printf("[*] Esperando a %s (abre el juego DESPUES del loader)...\n", app);

    DWORD pid = 0;
    for (int attempt = 0; attempt < 600 && pid == 0; attempt++) {
        pid = FindProcessByName(app);
        if (pid == 0) {
            Sleep(100);
        }
    }

    if (pid == 0) {
        printf("[!] Tiempo agotado esperando el proceso.\n");
        if (!autoclose) {
            printf("Pulsa ENTER para salir...\n");
            getchar();
        }
        return 1;
    }

    printf("[*] Proceso encontrado (PID %lu), inyectando...\n", pid);

    int status = InjectClassic(pid, dllPath);
    bool ok = (status == 0);

    if (status == 2) { // Access denied
        printf("[*] Proceso protegido (acceso denegado). Probando metodo hook...\n");
        ok = InjectHook(pid, dllPath);
    }

    if (!autoclose) {
        printf("Pulsa ENTER para salir...\n");
        getchar();
    }

    return ok ? 0 : 1;
}
