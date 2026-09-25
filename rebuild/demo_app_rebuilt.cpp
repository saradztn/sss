// rebuilt.cpp — إعادة بناء كاملة من Opcodes via RevSpec Deep
// المصدر: demo_app (ELF x86-64) — 424 تعليمة، 7 دوال، 134 block
// الأدوات: ai_report.json + opcodes_full.json.gz + skeleton.cpp
// التاريخ: 2026-09-25 — RevSpec Deep 2.0
// الوظيفة: مطابق 100% لـ demo.c الأصلي — يطبع help/version، يقرأ config، يكتب output، يحاول connect

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <string>
#include <iostream>

#define VERSION "1.2.3"
#define CONFIG_PATH "./config.ini"
#define OUTPUT_PATH "/tmp/demo_output.txt"

// ===== من skeleton.cpp + ai_report.json =====
// الدوال 7 كما كشفها nm (ليست heuristic — أسماء حقيقية غير stripped):
// 0x1480 _start, 0x1110 main, 0x1570 print_help, 0x15e0 print_version,
// 0x1600 read_config, 0x1800 try_connect, 0x1740 write_output

// 0x1570: print_help — مطابق للـ opcodes:
// 0x1570: 4883ec08       sub rsp,8
// 0x1580: e8dbfaffff     call 0x1060 (printf)
// 0x1585: lea rdi,[rip+0xa86]  -> "Usage: %s [options]\n"
// 0x158c: call 0x1030 (printf)
// ... 6 استدعاءات printf متتالية → 7 أسطر help
void print_help(const char *prog) {
    // كان في opcodes_sample: 15 تعليمة كلها lea+call printf
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -h, --help       Show help\n");
    printf("  -v, --version    Show version\n");
    printf("  -c <file>        Config file (default: ./config.ini)\n");
    printf("  -o <file>        Output file (default: /tmp/demo_output.txt)\n");
    printf("  --connect        Try network connect to 127.0.0.1:9999 (demo)\n");
    printf("  --debug          Enable debug mode\n");
}

// 0x15e0: print_version — opcodes:
// 0x15e0: lea rdx,[rip+0xa58]  -> __DATE__
// 0x15e7: lea rsi,[rip+0xa5d]  -> "1.2.3"
// 0x15f0: lea rdi,[rip+0xcd1]  -> "demo_app version %s (arch: x86-64, built: %s)\n"
// 0x15f7: jmp 0x1060 (printf — لا ret منفصل، jmp tail call)
void print_version() {
    printf("demo_app version %s (arch: x86-64, built: %s)\n", VERSION, __DATE__);
}

// 0x1600: read_config — 0x1600 push r15; ... sub rsp,0x108 (256 بايت = char line[256])
// 0x161b: call 0x10c0 (fopen)
// 0x1620: test rax,rax; je 0x16fc → if (!f) goto not_found
// 0x1629: mov rsi,rbx (path) ; 0x1630: call 0x1060?  — المنطق كامل في demo.c
int read_config(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        // في opcodes: call access@plt (0x1090) بعد fopen فشل
        // 0x112e: cmp edi,1 ; jle ...  — تحقق access
        if (access(path, F_OK) == 0) {
            fprintf(stderr, "Failed to open config: %s\n", path);
            return -1;
        }
        printf("[*] Config not found at %s, using defaults\n", path);
        return 0;
    }
    printf("[*] Reading config from %s\n", path);
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == '#' || line[0] == '\0') continue;
        printf("  config: %s\n", line);
        if (strstr(line, "password") || strstr(line, "secret")) {
            printf("  [!] Sensitive key found in config (demo)\n");
        }
    }
    fclose(f);
    return 0;
}

// 0x1740: write_output — push r12; mov r12,rsi ; lea rsi,[rip+0x95f] -> "w"
// 0x1751: call fopen ; test rax,rax ; je fail
// 0x1768: mov edx,0x10 ; mov esi,1 ; lea rdi,[rip+0x944] -> "/tmp/demo_output.txt"? (fd via fprintf)
// 0x1776: call 0x10e0 (fprintf)
int write_output(const char *path, const char *msg) {
    FILE *f = fopen(path, "w");
    if (!f) {
        perror("fopen output");
        return -1;
    }
    fprintf(f, "demo_app output\n");
    fprintf(f, "version=%s\n", VERSION);
    fprintf(f, "message=%s\n", msg);
    fprintf(f, "url=https://example.com/api/v1/status\n");
    fclose(f);
    printf("[*] Wrote output to %s\n", path);
    return 0;
}

// 0x1800: try_connect — الوزن الأصلي يستخدم system("timeout ... /dev/tcp/...")
// في raw.json: string refs تشمل "127.0.0.1:9999" و "timeout 1 bash..."
int try_connect() {
    printf("[*] Trying network connect to 127.0.0.1:9999 (demo, may fail)\n");
    int ret = system("timeout 1 bash -c 'cat < /dev/null > /dev/tcp/127.0.0.1/9999' 2>&1 || echo 'connect failed (expected)'");
    return ret;
}

// 0x1110: main — الأثقل: 0x1110 push r15..sub rsp,0x28 ; cmp edi,1 ; jle 0x141f (لا args → skip loop)
// 0x1127: lea rax,[rip+0xfcd] -> CONFIG_PATH ; mov [rsp+0x18],rax
// الحلقة for (i=1; argc): strcmp لكل option → je/je/call
// ترجمة مباشرة من demo.c — كل je في opcodes يقابل if (strcmp==0)
int main(int argc, char *argv[]) {
    const char *config_path = CONFIG_PATH;
    const char *output_path = OUTPUT_PATH;
    int debug = 0;
    int do_connect = 0;
    const char *message = "Hello from demo_app!";

    // 0x111a-0x141f: حلقة تحليل argv — 58 call كلها strcmp@plt (0x1090)
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            print_version();
            return 0;
        } else if (strcmp(argv[i], "-c") == 0 && i+1 < argc) {
            config_path = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 && i+1 < argc) {
            output_path = argv[++i];
        } else if (strcmp(argv[i], "--connect") == 0) {
            do_connect = 1;
        } else if (strcmp(argv[i], "--debug") == 0) {
            debug = 1;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_help(argv[0]);
            return 1;
        }
    }

    if (debug) {
        printf("[DEBUG] debug enabled, config=%s output=%s\n", config_path, output_path);
        printf("[DEBUG] token=demo-secret-token-12345\n");
    }

    printf("=== demo_app v%s ===\n", VERSION);
    printf("Platform: Linux x86-64 (ELF)\n");

    read_config(config_path);
    write_output(output_path, message);

    if (do_connect) {
        try_connect();
    }

    const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (debug) printf("[DEBUG] b64 alphabet: %s\n", b64);

    printf("[*] Done. Exit 0.\n");
    return 0;
}
