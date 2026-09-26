// tools/serial_change_probe.cpp
// ===========================================================================
// SERIAL CHANGE PROBE  —  single-file, read-only, ZERO MUTATION
//
// One program that answers everything on this machine, without changing
// anything:
//
//   0. What is the CURRENT MTA client serial?            (printed first)
//   1. Which hardware identifiers exist, and how spoofable is each?
//   2. How much real entropy would a serial built from them have?
//   3. Would a serial change SUCCEED here, or be BLOCKED? (and why)
//   4. What to harden.
//
// It reads the exact identifier surface CSX.exe touches (see
// docs/client_lua_analysis.md) and probes *permissions* on the target
// registry keys. Probing permissions is an access check, not a write.
//
// WHAT THIS PROGRAM NEVER CALLS
//   RegSetValueEx*  RegDeleteKey*  RegDeleteValue*  RegCreateKeyEx*
//   CredDelete*  CredWrite*  WriteProcessMemory  CreateRemoteThread
//   VirtualAllocEx  QueueUserAPC  SetThreadContext
//   no WMI provider interception, no process injection, no file writes
//
// Registry calls used: RegOpenKeyExW, RegQueryInfoKeyW, RegEnumValueW,
//   RegQueryValueExW, RegCloseKey  (all read or access-check only)
//
// Build (this is the single source file; nothing else is required)
//   Windows (MSVC) :
//     cl /O2 /EHsc /W4 tools\serial_change_probe.cpp advapi32.lib ole32.lib ^
//        oleaut32.lib wbemuuid.lib iphlpapi.lib /Fe:serial_change_probe.exe
//   Windows (MinGW, cross-compile from Linux) :
//     x86_64-w64-mingw32-g++ -O2 -std=c++17 -Wall -Wextra ^
//        tools/serial_change_probe.cpp -o serial_change_probe.exe -static ^
//        -ladvapi32 -lole32 -loleaut32 -lwbemuuid -liphlpapi
//   Linux (logic harness) :
//     g++ -O2 -std=c++17 -Wall -Wextra tools/serial_change_probe.cpp -o serial_change_probe
//
// Run
//   serial_change_probe                 current serial masked
//   serial_change_probe --show-values   unmasked values
//   serial_change_probe --help
//
// Exit codes: 0 = change would succeed, 2 = change would be blocked,
//             3 = could not determine, 1 = usage error
// ===========================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <wbemidl.h>
#  include <oleauto.h>   // SysAllocString / SysFreeString (no <comdef.h> needed,
#  include <iphlpapi.h>  // so this file builds with MSVC *and* MinGW)
#  pragma comment(lib, "advapi32.lib")
#  pragma comment(lib, "ole32.lib")
#  pragma comment(lib, "oleaut32.lib")
#  pragma comment(lib, "wbemuuid.lib")
#  pragma comment(lib, "iphlpapi.lib")
#else
#  include <fstream>
#  include <unistd.h>
#  include <sys/stat.h>
#endif

// ---------------------------------------------------------------------------
// Shared model (platform independent — the Linux build exercises all of it)
// ---------------------------------------------------------------------------

enum class Access { Unknown, Granted, Denied };

// How hard is this identifier to change *legitimately*?
enum class Spoofability {
    Anchor,        // hardware / OS install — only real hardware or a reinstall
    UserReset,     // user can change it through supported settings
    UsermodeSpoof, // settable from user mode (registry write / API hook)
    TrivialSpoof   // one setting, or a common public tool
};

struct Identifier {
    std::string  key;
    std::string  source;
    std::string  value;
    bool         present  = false;
    double       real_bits = 0.0;   // nominal entropy if present
    Spoofability spoof    = Spoofability::UsermodeSpoof;
};

struct TargetKey {
    std::string path;
    std::string purpose;
    bool        exists    = false;
    Access      readable  = Access::Unknown;
    Access      writable  = Access::Unknown;   // KEY_SET_VALUE access check
    Access      deletable = Access::Unknown;   // DELETE access check
    std::vector<std::pair<std::string, std::string>> values;
    std::string note;
};

struct Report {
    std::vector<Identifier> ids;
    std::vector<TargetKey>  keys;
    std::string current_serial;
    std::string serial_source;      // which key/value it came from
    bool        serial_found = false;
    int         writable_targets  = 0;
    int         deletable_targets = 0;
    int         total_targets     = 0;
    double      real_bits_total      = 0.0;
    double      effective_bits_total = 0.0;
    int         collected   = 0;
    int         spoofable   = 0;
    int         exit_code   = 3;
};

// Registry keys CSX.exe operates on — taken verbatim from the sample's
// .rdata (UTF-16LE strings at 0x00443340..0x00443610).
static const char* kTargetPaths[] = {
    "SOFTWARE\\Multi Theft Auto\\1.6",
    "SOFTWARE\\Multi Theft Auto: San Andreas\\1.6",
    "SOFTWARE\\Multi Theft Auto: Province All\\1.6",
    "SOFTWARE\\WOW6432Node\\Multi Theft Auto\\1.6",
    "SOFTWARE\\Multi Theft Auto: San Andreas All\\1.6",
    "SOFTWARE\\WOW6432Node\\Multi Theft Auto: San Andreas\\1.6",
};
static const size_t kTargetCount = sizeof(kTargetPaths) / sizeof(kTargetPaths[0]);

// ---------------------------------------------------------------------------
// Spoofability scoring — the central rule
//
// Any identifier an attacker can set from user mode contributes ZERO security
// to a serial, no matter how much entropy it nominally has.
// ---------------------------------------------------------------------------

static double effective_bits(const Identifier& id) {
    if (!id.present) return 0.0;
    switch (id.spoof) {
        case Spoofability::Anchor:        return id.real_bits;
        case Spoofability::UserReset:     return id.real_bits * 0.35;
        case Spoofability::UsermodeSpoof: return 0.0;
        case Spoofability::TrivialSpoof:  return 0.0;
    }
    return 0.0;
}

static const char* spoof_str(Spoofability s) {
    switch (s) {
        case Spoofability::Anchor:        return "ANCHOR";
        case Spoofability::UserReset:     return "USER-RESETTABLE";
        case Spoofability::UsermodeSpoof: return "USERMODE-SPOOFABLE";
        case Spoofability::TrivialSpoof:  return "TRIVIAL-SPOOFABLE";
    }
    return "?";
}

static void score(Report& r) {
    r.real_bits_total = r.effective_bits_total = 0.0;
    r.collected = r.spoofable = 0;
    for (const auto& id : r.ids) {
        if (id.present) ++r.collected;
        if (id.spoof == Spoofability::UsermodeSpoof ||
            id.spoof == Spoofability::TrivialSpoof) ++r.spoofable;
        r.real_bits_total      += id.present ? id.real_bits : 0.0;
        r.effective_bits_total += effective_bits(id);
    }
}

static const char* entropy_grade(double effective_bits_total) {
    if (effective_bits_total < 1.0)
        return "F - the serial is fully regenerable from user mode";
    if (effective_bits_total < 16.0)
        return "D - relies almost entirely on spoofable inputs";
    if (effective_bits_total < 32.0)
        return "C - needs hardening";
    return "B - reasonable basis, see recommendations";
}

// ---------------------------------------------------------------------------
// Verdict logic — platform independent
// ---------------------------------------------------------------------------

static void decide(Report& r) {
    r.total_targets = (int)r.keys.size();
    for (const auto& k : r.keys) {
        if (k.writable  == Access::Granted) ++r.writable_targets;
        if (k.deletable == Access::Granted) ++r.deletable_targets;
    }
    if (r.total_targets == 0) { r.exit_code = 3; return; }
    // A serial change needs to modify (or delete) at least one target key.
    if (r.writable_targets > 0 || r.deletable_targets > 0) r.exit_code = 0;
    else                                                   r.exit_code = 2;
}

static const char* access_str(Access a) {
    switch (a) {
        case Access::Granted: return "GRANTED";
        case Access::Denied:  return "DENIED";
        case Access::Unknown: return "unknown";
    }
    return "?";
}

static bool looks_like_serial(const std::string& v) {
    if (v.size() < 8 || v.size() > 64) return false;
    for (char c : v) {
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (c != '-' && !hex) return false;
    }
    return true;
}

static std::string mask(const std::string& v) {
    if (v.size() <= 8) return v;
    std::string m = v;
    m.replace(4, m.size() - 8, std::string(m.size() - 8, '*'));
    return m;
}

// ---------------------------------------------------------------------------
// Windows collectors (read-only)
// ---------------------------------------------------------------------------
#ifdef _WIN32

static std::string wide_to_utf8(const wchar_t* w) {
    if (!w || !*w) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return "";
    std::string s((size_t)n - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], n, nullptr, nullptr);
    return s;
}

static std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w((size_t)n - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
    return w;
}

// Access check only: opening a key with a write right does NOT modify it.
static Access access_check(const std::string& path, REGSAM right) {
    HKEY h = nullptr;
    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, utf8_to_wide(path).c_str(),
                            0, right | KEY_WOW64_64KEY, &h);
    if (rc == ERROR_SUCCESS) { if (h) RegCloseKey(h); return Access::Granted; }
    if (rc == ERROR_ACCESS_DENIED)  return Access::Denied;
    if (rc == ERROR_FILE_NOT_FOUND) return Access::Unknown;   // key absent
    return Access::Unknown;
}

static void collect_target_key(TargetKey& t) {
    std::wstring wp = utf8_to_wide(t.path);
    HKEY h = nullptr;
    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, wp.c_str(), 0,
                            KEY_READ | KEY_WOW64_64KEY, &h);
    if (rc != ERROR_SUCCESS) {
        t.exists   = (rc != ERROR_FILE_NOT_FOUND);
        t.readable = (rc == ERROR_FILE_NOT_FOUND) ? Access::Unknown : Access::Denied;
        t.writable  = access_check(t.path, KEY_SET_VALUE);
        t.deletable = access_check(t.path, DELETE);
        if (rc == ERROR_FILE_NOT_FOUND) t.note = "key not present";
        return;
    }
    t.exists   = true;
    t.readable = Access::Granted;

    DWORD nvalues = 0, maxlen = 0, maxdata = 0;
    if (RegQueryInfoKeyW(h, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                         &nvalues, &maxlen, &maxdata, nullptr, nullptr) == ERROR_SUCCESS
        && nvalues) {
        std::wstring name(maxlen + 1, L'\0');
        std::vector<BYTE> data(maxdata ? maxdata : 1);
        for (DWORD i = 0; i < nvalues; ++i) {
            DWORD namelen = maxlen + 1, datalen = maxdata, type = 0;
            if (RegEnumValueW(h, i, &name[0], &namelen, nullptr, &type,
                              data.data(), &datalen) != ERROR_SUCCESS) continue;
            name.resize(namelen);
            std::string vname = wide_to_utf8(name.c_str());
            std::string vdata;
            if (type == REG_SZ || type == REG_EXPAND_SZ) {
                vdata = wide_to_utf8(reinterpret_cast<const wchar_t*>(data.data()));
            } else if (type == REG_DWORD && datalen >= 4) {
                char b[16];
                std::snprintf(b, sizeof(b), "%u",
                              (unsigned)*reinterpret_cast<const DWORD*>(data.data()));
                vdata = b;
            } else {
                char b[32];
                std::snprintf(b, sizeof(b), "<%lu bytes>", (unsigned long)datalen);
                vdata = b;
            }
            t.values.emplace_back(vname, vdata);
        }
    }
    RegCloseKey(h);

    t.writable  = access_check(t.path, KEY_SET_VALUE);
    t.deletable = access_check(t.path, DELETE);
}

static void read_reg_sz(const std::string& path, const std::string& valueName,
                        std::string& out) {
    HKEY h = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, utf8_to_wide(path).c_str(), 0,
                      KEY_READ | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS) return;
    wchar_t buf[512] = {0};
    DWORD sz = sizeof(buf), type = 0;
    if (RegQueryValueExW(h, utf8_to_wide(valueName).c_str(), nullptr, &type,
                         reinterpret_cast<LPBYTE>(buf), &sz) == ERROR_SUCCESS
        && (type == REG_SZ || type == REG_EXPAND_SZ)) {
        out = wide_to_utf8(buf);
    }
    RegCloseKey(h);
}

static bool read_reg_dword(const std::string& path, const std::string& valueName,
                           DWORD& out) {
    HKEY h = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, utf8_to_wide(path).c_str(), 0,
                      KEY_READ | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS) return false;
    DWORD sz = sizeof(out), type = 0;
    bool ok = (RegQueryValueExW(h, utf8_to_wide(valueName).c_str(), nullptr, &type,
                                reinterpret_cast<LPBYTE>(&out), &sz) == ERROR_SUCCESS
               && type == REG_DWORD);
    RegCloseKey(h);
    return ok;
}

// Minimal RAII BSTR. Avoids <comdef.h> / _bstr_t, which is MSVC-only, so the
// same source compiles with MSVC and with MinGW-w64.
struct Bstr {
    BSTR v;
    explicit Bstr(const wchar_t* s) : v(SysAllocString(s)) {}
    ~Bstr() { if (v) SysFreeString(v); }
    operator BSTR() const { return v; }
    Bstr(const Bstr&) = delete;
    Bstr& operator=(const Bstr&) = delete;
};

// WMI read-only query. Returns the first non-empty string property.
static std::string wmi_first(const wchar_t* query, const wchar_t* prop) {
    std::string out;
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool coInit = SUCCEEDED(hr);
    IWbemLocator* loc = nullptr;
    IWbemServices* svc = nullptr;
    do {
        HRESULT cs = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                nullptr, EOAC_NONE, nullptr);
        if (FAILED(cs) && cs != RPC_E_TOO_LATE) break;
        if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                    IID_IWbemLocator, (void**)&loc))) break;
        Bstr ns(L"ROOT\\CIMV2");
        if (FAILED(loc->ConnectServer(ns, nullptr, nullptr,
                                      nullptr, 0, nullptr, nullptr, &svc))) break;
        CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                          RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                          nullptr, EOAC_NONE);
        IEnumWbemClassObject* en = nullptr;
        Bstr lang(L"WQL"), q(query);
        if (FAILED(svc->ExecQuery(lang, q,
                                  WBEM_FLAG_FORWARD_ONLY, nullptr, &en))) break;
        IWbemClassObject* obj = nullptr;
        ULONG ret = 0;
        if (en->Next(WBEM_INFINITE, 1, &obj, &ret) == S_OK && ret) {
            VARIANT v; VariantInit(&v);
            if (SUCCEEDED(obj->Get(prop, 0, &v, nullptr, nullptr))
                && v.vt == VT_BSTR && v.bstrVal) out = wide_to_utf8(v.bstrVal);
            VariantClear(&v);
            obj->Release();
        }
        en->Release();
    } while (false);
    if (svc) svc->Release();
    if (loc) loc->Release();
    if (coInit) CoUninitialize();
    return out;
}

static void collect_windows(Report& r) {
    struct Spec { const char* key; const char* source; double bits; Spoofability sp; };
    static const Spec spec[] = {
        {"machine_guid",  "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid", 64.0, Spoofability::UsermodeSpoof},
        {"bios_serial",   "WMI Win32_BIOS.SerialNumber",                          24.0, Spoofability::UsermodeSpoof},
        {"board_serial",  "WMI Win32_BaseBoard.SerialNumber",                     20.0, Spoofability::UsermodeSpoof},
        {"disk_serial",   "WMI Win32_DiskDrive.SerialNumber",                     32.0, Spoofability::UsermodeSpoof},
        {"volume_serial", "GetVolumeInformationW (C:)",                           32.0, Spoofability::TrivialSpoof},
        {"mac_address",   "GetAdaptersAddresses",                                 48.0, Spoofability::TrivialSpoof},
        {"computer_name", "GetComputerNameW",                                     15.0, Spoofability::TrivialSpoof},
        {"user_name",     "GetUserNameW",                                         14.0, Spoofability::TrivialSpoof},
        {"product_id",    "HKLM\\...\\Windows NT\\CurrentVersion\\ProductId",     20.0, Spoofability::UsermodeSpoof},
        {"install_date",  "HKLM\\...\\Windows NT\\CurrentVersion\\InstallDate",   30.0, Spoofability::Anchor},
    };
    for (const auto& s : spec) {
        Identifier id; id.key = s.key; id.source = s.source;
        id.real_bits = s.bits; id.spoof = s.sp;
        r.ids.push_back(id);
    }

    read_reg_sz("SOFTWARE\\Microsoft\\Cryptography", "MachineGuid", r.ids[0].value);
    r.ids[0].present = !r.ids[0].value.empty();

    r.ids[1].value = wmi_first(L"SELECT SerialNumber FROM Win32_BIOS", L"SerialNumber");
    r.ids[1].present = !r.ids[1].value.empty();
    r.ids[2].value = wmi_first(L"SELECT SerialNumber FROM Win32_BaseBoard", L"SerialNumber");
    r.ids[2].present = !r.ids[2].value.empty();
    r.ids[3].value = wmi_first(L"SELECT SerialNumber FROM Win32_DiskDrive", L"SerialNumber");
    r.ids[3].present = !r.ids[3].value.empty();

    { wchar_t root[] = L"C:\\"; DWORD vs = 0; wchar_t nm[MAX_PATH+1]={0}, fs[MAX_PATH+1]={0};
      DWORD mc = 0, fl = 0;
      if (GetVolumeInformationW(root, nm, MAX_PATH, &vs, &mc, &fl, fs, MAX_PATH)) {
          char s[24]; std::snprintf(s, sizeof(s), "%04X-%04X",
              (unsigned)(vs >> 16), (unsigned)(vs & 0xFFFF));
          r.ids[4].value = s; r.ids[4].present = true; } }

    { ULONG sz = 0;
      GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                           nullptr, nullptr, &sz);
      if (sz) {
          std::vector<char> buf(sz);
          auto* p = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
          if (GetAdaptersAddresses(AF_UNSPEC,
                  GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, nullptr, p, &sz) == NO_ERROR) {
              for (auto* a = p; a; a = a->Next) {
                  if (a->PhysicalAddressLength == 6) {
                      char s[24];
                      std::snprintf(s, sizeof(s), "%02X:%02X:%02X:%02X:%02X:%02X",
                          a->PhysicalAddress[0], a->PhysicalAddress[1], a->PhysicalAddress[2],
                          a->PhysicalAddress[3], a->PhysicalAddress[4], a->PhysicalAddress[5]);
                      r.ids[5].value = s; r.ids[5].present = true; break;
                  }
              }
          }
      } }

    { wchar_t b[256] = {0}; DWORD n = 256;
      if (GetComputerNameW(b, &n)) { r.ids[6].value = wide_to_utf8(b); r.ids[6].present = true; } }
    { wchar_t b[256] = {0}; DWORD n = 256;
      if (GetUserNameW(b, &n)) { r.ids[7].value = wide_to_utf8(b); r.ids[7].present = true; } }

    read_reg_sz("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductId", r.ids[8].value);
    r.ids[8].present = !r.ids[8].value.empty();

    { DWORD v = 0;
      if (read_reg_dword("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "InstallDate", v)) {
          char b[16]; std::snprintf(b, sizeof(b), "%u", (unsigned)v);
          r.ids[9].value = b; r.ids[9].present = true; } }

    for (size_t i = 0; i < kTargetCount; ++i) {
        TargetKey t; t.path = kTargetPaths[i];
        t.purpose = "MTA client state / serial storage";
        collect_target_key(t);
        r.keys.push_back(t);
    }
}

#else  // ------------------------------------------- Linux logic harness

static std::string read_first_line(const std::string& p) {
    std::ifstream f(p);
    std::string l;
    if (f.is_open() && std::getline(f, l)) return l;
    return "";
}

static void collect_posix(Report& r) {
    // This path exists so the verdict/scoring logic can be compiled and
    // exercised outside Windows. It reads Linux equivalents and probes
    // filesystem permissions. MTA state does not exist on Linux, so no
    // current serial is reported. Nothing is modified.
    struct Spec { const char* key; const char* src; const char* path; double bits; Spoofability sp; };
    static const Spec spec[] = {
        {"machine_guid",  "/etc/machine-id",                   "/etc/machine-id",                   64.0, Spoofability::UsermodeSpoof},
        {"bios_serial",   "/sys/class/dmi/id/product_serial",  "/sys/class/dmi/id/product_serial",  24.0, Spoofability::UsermodeSpoof},
        {"board_serial",  "/sys/class/dmi/id/board_serial",    "/sys/class/dmi/id/board_serial",    20.0, Spoofability::UsermodeSpoof},
        {"disk_serial",   "/sys/class/dmi/id/product_uuid",    "/sys/class/dmi/id/product_uuid",    32.0, Spoofability::UsermodeSpoof},
        {"volume_serial", "/sys/class/dmi/id/chassis_serial",  "/sys/class/dmi/id/chassis_serial",  32.0, Spoofability::TrivialSpoof},
        {"mac_address",   "/sys/class/dmi/id/product_sku",     "/sys/class/dmi/id/product_sku",     48.0, Spoofability::TrivialSpoof},
        {"computer_name", "/proc/sys/kernel/hostname",         "/proc/sys/kernel/hostname",         15.0, Spoofability::TrivialSpoof},
        {"user_name",     "/sys/class/dmi/id/product_version", "/sys/class/dmi/id/product_version", 14.0, Spoofability::TrivialSpoof},
        {"product_id",    "/sys/class/dmi/id/bios_vendor",     "/sys/class/dmi/id/bios_vendor",     20.0, Spoofability::UsermodeSpoof},
        {"install_date",  "/sys/class/dmi/id/bios_date",       "/sys/class/dmi/id/bios_date",       30.0, Spoofability::Anchor},
    };
    for (const auto& s : spec) {
        Identifier id; id.key = s.key; id.source = s.src;
        id.real_bits = s.bits; id.spoof = s.sp;
        id.value = read_first_line(s.path);
        id.present = !id.value.empty();
        r.ids.push_back(id);
    }
    const char* probePaths[] = {"/etc/machine-id", "/etc/hostname", "/sys/class/dmi/id/product_uuid"};
    const char* purposes[]   = {"machine identity storage", "host identity storage", "firmware identity"};
    for (int i = 0; i < 3; ++i) {
        TargetKey t; t.path = probePaths[i]; t.purpose = purposes[i];
        struct stat st;
        t.exists    = (stat(probePaths[i], &st) == 0);
        t.readable  = (access(probePaths[i], R_OK) == 0) ? Access::Granted : Access::Denied;
        t.writable  = (access(probePaths[i], W_OK) == 0) ? Access::Granted : Access::Denied;
        t.deletable = t.writable;
        if (!t.exists) {
            t.readable = t.writable = t.deletable = Access::Unknown;
            t.note = "not present";
        }
        r.keys.push_back(t);
    }
}
#endif

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

// Guarded so tools/test_serial_change_probe.cpp can include this translation
// unit and exercise the shipped logic instead of re-implementing it.
#ifndef SCP_NO_MAIN
int main(int argc, char** argv) {
    bool showRaw = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--show-values") == 0) showRaw = true;
        else if (std::strcmp(argv[i], "--help") == 0 || std::strcmp(argv[i], "-h") == 0) {
            std::printf("Usage: serial_change_probe [--show-values]\n"
                        "Single-file, read-only. Performs zero mutations.\n"
                        "Exit: 0 = change would succeed, 2 = blocked, 3 = undetermined.\n");
            return 1;
        }
    }

    Report r;
#ifdef _WIN32
    collect_windows(r);
#else
    collect_posix(r);
#endif

    // Locate the current serial among the values read.
    for (const auto& k : r.keys) {
        for (const auto& v : k.values) {
            if (!r.serial_found && looks_like_serial(v.second)) {
                r.current_serial = v.second;
                r.serial_source  = k.path + "  [" + v.first + "]";
                r.serial_found   = true;
            }
        }
    }

    decide(r);
    score(r);

    std::printf("=============================================================\n");
    std::printf("  SERIAL CHANGE PROBE  -  READ-ONLY, ZERO MUTATION\n");
    std::printf("=============================================================\n\n");

    // ---- 0. the answer the user asked to see first -------------------------
    std::printf(">>> CURRENT SERIAL <<<\n");
    if (r.serial_found) {
        std::printf("    %s\n", showRaw ? r.current_serial.c_str()
                                        : mask(r.current_serial).c_str());
        std::printf("    source : %s\n", r.serial_source.c_str());
        if (!showRaw) std::printf("    (re-run with --show-values for the full value)\n");
    } else {
        std::printf("    NOT FOUND\n");
#ifdef _WIN32
        std::printf("    MTA is not installed under any of the %zu probed keys,\n", kTargetCount);
        std::printf("    or the key is not readable by this token.\n");
#else
        std::printf("    This is a non-Windows logic-harness build; MTA state does\n");
        std::printf("    not exist here. Build for Windows to read the real serial.\n");
#endif
    }
    std::printf("\n");

    std::printf("--- 1. Identifier inventory (read-only) --------------------\n");
    std::printf("%-14s %-44s %-19s %-7s %-7s %s\n",
                "IDENTIFIER", "SOURCE", "SPOOFABILITY", "REAL", "EFFECT", "VALUE");
    for (const auto& id : r.ids) {
        std::printf("%-14s %-44s %-19s %-7.1f %-7.1f %s\n",
                    id.key.c_str(), id.source.c_str(), spoof_str(id.spoof),
                    id.present ? id.real_bits : 0.0, effective_bits(id),
                    id.present ? (showRaw ? id.value.c_str() : mask(id.value).c_str())
                               : "(unavailable)");
    }

    std::printf("\n--- 2. Entropy assessment ----------------------------------\n");
    std::printf("  identifiers available : %d / %zu\n", r.collected, r.ids.size());
    std::printf("  spoofable from user   : %d / %zu\n", r.spoofable, r.ids.size());
    std::printf("  nominal entropy       : %.1f bits\n", r.real_bits_total);
    std::printf("  EFFECTIVE entropy     : %.1f bits  (spoofable inputs count as 0)\n",
                r.effective_bits_total);
    std::printf("  grade                 : %s\n", entropy_grade(r.effective_bits_total));

    std::printf("\n--- 3. MTA target keys (CSX operates on these) --------------\n");
    std::printf("%-52s %-8s %-8s %-8s %s\n", "PATH", "READ", "WRITE", "DELETE", "VALUES");
    for (const auto& k : r.keys) {
        std::printf("%-52s %-8s %-8s %-8s %zu%s\n", k.path.c_str(),
                    access_str(k.readable), access_str(k.writable), access_str(k.deletable),
                    k.values.size(), k.note.empty() ? "" : ("  [" + k.note + "]").c_str());
        for (const auto& v : k.values) {
            if (showRaw || looks_like_serial(v.second))
                std::printf("      %-24s = %s%s\n", v.first.c_str(),
                            showRaw ? v.second.c_str() : mask(v.second).c_str(),
                            looks_like_serial(v.second) ? "   <-- serial-shaped" : "");
        }
    }

    std::printf("\n--- 4. Verdict ---------------------------------------------\n");
    std::printf("  target keys probed : %d\n", r.total_targets);
    std::printf("  writable           : %d\n", r.writable_targets);
    std::printf("  deletable          : %d\n", r.deletable_targets);
    if (r.exit_code == 0) {
        std::printf("\n  RESULT: a serial change WOULD SUCCEED here.\n");
        std::printf("  Reason: at least one target key grants KEY_SET_VALUE or DELETE\n");
        std::printf("  to this token. Nothing was modified by this probe.\n");
    } else if (r.exit_code == 2) {
        std::printf("\n  RESULT: a serial change WOULD BE BLOCKED here.\n");
        std::printf("  Reason: no probed target key grants write or delete to this token.\n");
    } else {
        std::printf("\n  RESULT: UNDETERMINED.\n");
        std::printf("  Reason: no target key exists under the probed paths.\n");
    }

    std::printf("\n--- 5. Hardening -------------------------------------------\n");
    std::printf("  1. Never derive the serial from any USERMODE-/TRIVIAL-SPOOFABLE\n");
    std::printf("     input alone - those contribute 0 effective bits.\n");
    std::printf("  2. install_date is the discriminator: a real reinstall changes\n");
    std::printf("     it, a spoofer does not. Treat a machine_guid change with a\n");
    std::printf("     stable install_date as spoofing, not as a reinstall.\n");
    std::printf("  3. Deny write/delete on the MTA keys for non-admin tokens, and\n");
    std::printf("     sign whatever you store there so deletion cannot silently\n");
    std::printf("     regenerate a new serial.\n");
    std::printf("  4. Have the server sign the identifier; make it non-derivable\n");
    std::printf("     locally. Never fail open when the server is unreachable.\n");
    std::printf("  5. Cross-read Win32_BIOS.SerialNumber via WMI and via a direct\n");
    std::printf("     IOCTL and compare - a mismatch means WMI is being intercepted.\n");
    std::printf("  6. Scan binaries with: revspec analyze <file>  (serial_spoof)\n");

    std::printf("\n  Mutations performed by this probe: 0\n");
    return r.exit_code;
}
#endif  // SCP_NO_MAIN
