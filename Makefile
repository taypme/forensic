CC=gcc
CFLAGS=-std=c11 -Wall -Wextra -O2 -pthread
LDFLAGS=-lcrypto
INCLUDES=-Iinclude

SRC=src/main.c src/logging.c src/util.c src/workers.c src/sweep_registry.c src/sha256.c src/live_lines.c src/sweep_services.c
OBJ=$(SRC:.c=.o)
BIN=forensic

TEST_SRC=tests/test_args.c src/arg_parser.c src/logging.c
TEST_OBJ=$(TEST_SRC:.c=.o)
TEST_BIN=tests/test_args

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

test: $(TEST_BIN)
	./$(TEST_BIN)

$(TEST_BIN): $(TEST_OBJ)
	@mkdir -p tests
	$(CC) $(CFLAGS) -o $@ $(TEST_OBJ) $(LDFLAGS)

clean:
	rm -f $(OBJ) $(BIN) $(TEST_OBJ) $(TEST_BIN)

.PHONY: all clean test
