CC=gcc
CFLAGS=-O2 -Wall -g
TARGET=demo_app

all: $(TARGET)

$(TARGET): demo.c
	$(CC) $(CFLAGS) -o $(TARGET) demo.c

clean:
	rm -f $(TARGET) /tmp/demo_output.txt

test: $(TARGET)
	./$(TARGET) --help
	./$(TARGET) --version
	./$(TARGET) --debug
	cat /tmp/demo_output.txt || true
