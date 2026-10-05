# Makefile — Secure Memory Isolation System (Web Edition)
CC     = gcc
CFLAGS = -Wall -std=c11
TARGET = smi_server

all: $(TARGET)

$(TARGET): server.c
	$(CC) $(CFLAGS) -o $(TARGET) server.c
	@echo ""
	@echo "  Build OK!  Run with:  ./$(TARGET)"
	@echo "  Then open: http://localhost:8080"
	@echo ""

run: all
	./$(TARGET)

clean:
	rm -f $(TARGET)

# Windows (MinGW)
windows:
	gcc -o smi_server.exe server.c -lws2_32 -Wall -std=c11
