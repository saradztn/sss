/*
 * Demo App for RevSpec — برنامج تجريبي بسيط للاختبار
 * يملك هذا الملف صاحبه ويمكن تحليله بحرية.
 * الوظيفة: يقرأ config.ini (إن وجد)، يطبع رسالة، يتعامل مع CLI، يكتب ملف خرج، ويحاول اتصال شبكة اختياري.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define VERSION "1.2.3"
#define CONFIG_PATH "./config.ini"
#define OUTPUT_PATH "/tmp/demo_output.txt"

void print_help(const char *prog) {
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -h, --help       Show help\n");
    printf("  -v, --version    Show version\n");
    printf("  -c <file>        Config file (default: ./config.ini)\n");
    printf("  -o <file>        Output file (default: /tmp/demo_output.txt)\n");
    printf("  --connect        Try network connect to 127.0.0.1:9999 (demo)\n");
    printf("  --debug          Enable debug mode\n");
}

void print_version() {
    printf("demo_app version %s (arch: x86-64, built: %s)\n", VERSION, __DATE__);
}

int read_config(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
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
        // strip newline
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

int try_connect() {
    // Demo network: try to connect to 127.0.0.1:9999, will fail if no server
    printf("[*] Trying network connect to 127.0.0.1:9999 (demo, may fail)\n");
    // Use system to keep imports visible for static analysis (also shows dependency)
    int ret = system("timeout 1 bash -c 'cat < /dev/null > /dev/tcp/127.0.0.1/9999' 2>&1 || echo 'connect failed (expected)'");
    return ret;
}

int main(int argc, char *argv[]) {
    const char *config_path = CONFIG_PATH;
    const char *output_path = OUTPUT_PATH;
    int debug = 0;
    int do_connect = 0;
    const char *message = "Hello from demo_app!";

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

    // Simulate some crypto hint
    const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (debug) printf("[DEBUG] b64 alphabet: %s\n", b64);

    printf("[*] Done. Exit 0.\n");
    return 0;
}
