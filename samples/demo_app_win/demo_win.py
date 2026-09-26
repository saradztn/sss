#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Demo App for Windows — عينة تجريبية لـ RevSpec على Windows
تملك هذا الملف، يمكنك تحليله بحرية.
يحاكي نفس سلوك demo_app (C) لكنه Python ليعمل بدون gcc.
- يقرأ config.ini إن وجد
- يكتب /tmp أو %TEMP%/demo_output.txt
- يدعم CLI: --help, --version, --debug, --connect
- يحتوي على URLs و IPs و keywords لاختبار محلل strings
"""
import argparse
import os
import sys
import pathlib
import socket
import tempfile

VERSION = "1.2.3"
DEFAULT_CONFIG = pathlib.Path(__file__).parent.parent / "demo_app" / "config.ini"
# fallback to local
if not DEFAULT_CONFIG.exists():
    DEFAULT_CONFIG = pathlib.Path(__file__).parent / "config.ini"

def get_output_path(custom=None):
    if custom:
        return pathlib.Path(custom)
    # Windows: use TEMP, Linux: /tmp
    tmp = tempfile.gettempdir()
    return pathlib.Path(tmp) / "demo_output.txt"

def read_config(path: pathlib.Path):
    if not path.exists():
        print(f"[*] Config not found at {path}, using defaults")
        return {}
    print(f"[*] Reading config from {path}")
    cfg = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line=line.strip()
        if not line or line.startswith("#") or line.startswith("["):
            print(f"  config: {line}" if line else "", end="" if not line else "\n")
            continue
        print(f"  config: {line}")
        if "password" in line.lower() or "secret" in line.lower():
            print("  [!] Sensitive key found in config (demo)")
        if "=" in line:
            k,v=line.split("=",1)
            cfg[k.strip()]=v.strip()
    return cfg

def write_output(path: pathlib.Path, message="Hello from demo_win!"):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        f.write("demo_win output\n")
        f.write(f"version={VERSION}\n")
        f.write(f"message={message}\n")
        f.write(f"url=https://example.com/api/v1/status\n")
        f.write(f"ip=127.0.0.1\n")
        f.write(f"email=test@example.com\n")
    print(f"[*] Wrote output to {path}")

def try_connect():
    print("[*] Trying network connect to 127.0.0.1:9999 (demo, may fail)")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("127.0.0.1", 9999))
        print("[*] Connected! (unexpected, server running)")
        s.close()
    except Exception as e:
        print(f"connect failed (expected): {e}")

def main():
    parser = argparse.ArgumentParser(prog="demo_win", description="Demo Windows app for RevSpec")
    parser.add_argument("-c", dest="config", default=str(DEFAULT_CONFIG), help="Config file")
    parser.add_argument("-o", dest="output", default=None, help="Output file")
    parser.add_argument("--connect", action="store_true", help="Try network connect to 127.0.0.1:9999")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("-v", "--version", action="store_true", help="Show version")
    args = parser.parse_args()

    if args.version:
        print(f"demo_win version {VERSION} (platform: {sys.platform}, arch: {os.name})")
        print(f"Built: Python {sys.version.split()[0]}")
        return 0

    if args.debug:
        print(f"[DEBUG] debug enabled, config={args.config} output={args.output}")
        print(f"[DEBUG] token=demo-secret-token-12345")
        # Intentional strings for analysis
        b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        print(f"[DEBUG] b64 alphabet: {b64}")
        print(f"[DEBUG] BEGIN CERTIFICATE ----- (fake for crypto analyzer)")

    print(f"=== demo_win v{VERSION} ===")
    print(f"Platform: {sys.platform} ({os.name})")

    read_config(pathlib.Path(args.config))
    out = get_output_path(args.output)
    write_output(out, "Hello from demo_win!")

    if args.connect:
        try_connect()

    print("[*] Done. Exit 0.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
