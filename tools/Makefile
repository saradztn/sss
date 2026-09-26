# tools/ — read-only utilities. None of these modify, spoof or inject anything.
#
#   make            -> build serial_change_probe (single source file)
#   make test       -> build and run the C++ unit tests
#   make run        -> build and run
#   make clean
#
# Windows native (MSVC) — one command, one file:
#   cl /O2 /EHsc /W4 tools\serial_change_probe.cpp advapi32.lib ole32.lib ^
#      oleaut32.lib wbemuuid.lib iphlpapi.lib /Fe:serial_change_probe.exe
#
# Windows cross-compile (MinGW, from Linux):
#   x86_64-w64-mingw32-g++ -O2 -std=c++17 -Wall -Wextra \
#      tools/serial_change_probe.cpp -o serial_change_probe.exe -static \
#      -ladvapi32 -lole32 -loleaut32 -lwbemuuid -liphlpapi

CXX      ?= g++
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra

all: serial_change_probe

serial_change_probe: serial_change_probe.cpp
	$(CXX) $(CXXFLAGS) serial_change_probe.cpp -o serial_change_probe

test: test_serial_change_probe
	./test_serial_change_probe

test_serial_change_probe: test_serial_change_probe.cpp serial_change_probe.cpp
	$(CXX) $(CXXFLAGS) test_serial_change_probe.cpp -o test_serial_change_probe

run: serial_change_probe
	./serial_change_probe

clean:
	rm -f serial_change_probe test_serial_change_probe

.PHONY: all test run clean
