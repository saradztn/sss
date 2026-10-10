#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>

// Simulates the argument parsing algorithm reverse engineered from NORTH LOADER.exe (main at 0x413170)
struct LoaderConfig {
    std::string app;
    std::string dllPath;
    bool autoclose;
};

LoaderConfig parseArgs(int argc, char* argv[]) {
    LoaderConfig cfg;
    cfg.app = "gta_sa.exe";
    cfg.autoclose = false;
    cfg.dllPath = "";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--autoclose") == 0) {
            cfg.autoclose = true;
        } else if (strcmp(argv[i], "--proc") == 0 && i + 1 < argc) {
            cfg.app = argv[++i];
        } else if (strcmp(argv[i], "--dll") == 0 && i + 1 < argc) {
            cfg.dllPath = argv[++i];
        } else if (argv[i][0] != '-' && cfg.dllPath.empty()) {
            size_t len = strlen(argv[i]);
            if (len > 4 && strcasecmp(argv[i] + len - 4, ".dll") == 0) {
                cfg.dllPath = argv[i];
            }
        }
    }

    if (cfg.dllPath.empty()) {
        cfg.dllPath = "C:\\Games\\GTA\\NRTH.dll"; // simulated default
    }

    return cfg;
}

int main() {
    printf("[*] Running test_cli_parser...\n");

    // Case 1: Defaults
    {
        char* args[] = { (char*)"loader.exe" };
        LoaderConfig c = parseArgs(1, args);
        assert(c.app == "gta_sa.exe");
        assert(!c.autoclose);
        assert(c.dllPath == "C:\\Games\\GTA\\NRTH.dll");
        printf("  [+] Case 1 passed: Default configuration verified.\n");
    }

    // Case 2: Custom proc and autoclose
    {
        char* args[] = { (char*)"loader.exe", (char*)"--proc", (char*)"game.exe", (char*)"--autoclose" };
        LoaderConfig c = parseArgs(4, args);
        assert(c.app == "game.exe");
        assert(c.autoclose);
        assert(c.dllPath == "C:\\Games\\GTA\\NRTH.dll");
        printf("  [+] Case 2 passed: --proc and --autoclose flags parsed correctly.\n");
    }

    // Case 3: Explicit --dll flag
    {
        char* args[] = { (char*)"loader.exe", (char*)"--dll", (char*)"C:\\custom\\cheat.dll" };
        LoaderConfig c = parseArgs(3, args);
        assert(c.dllPath == "C:\\custom\\cheat.dll");
        printf("  [+] Case 3 passed: --dll flag parsed correctly.\n");
    }

    // Case 4: Positional .dll argument
    {
        char* args[] = { (char*)"loader.exe", (char*)"D:\\mods\\payload.dll", (char*)"--autoclose" };
        LoaderConfig c = parseArgs(3, args);
        assert(c.dllPath == "D:\\mods\\payload.dll");
        assert(c.autoclose);
        printf("  [+] Case 4 passed: Positional .dll argument parsed correctly.\n");
    }

    printf("[+] All CLI parsing tests passed successfully!\n");
    return 0;
}
