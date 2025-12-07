CC=gcc
CFLAGS=-std=c11 -Wall -Wextra -O2 -pthread
LDFLAGS=-lcrypto
INCLUDES=-Iinclude

SRC=src/main.c src/logging.c src/util.c src/workers.c src/sweep_registry.c src/sha256.c src/live_lines.c src/sweep_services.c
OBJ=$(SRC:.c=.o)
BIN=forensic

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJ) $(BIN)

.PHONY: all clean
