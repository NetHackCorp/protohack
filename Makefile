CC := clang
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -Iinclude -D_CRT_SECURE_NO_WARNINGS
LDFLAGS ?=
LIBS ?= -lm
RM := rm -f
EXE :=

ifeq ($(OS),Windows_NT)
EXE := .exe
LIBS :=
RM := cmd /C del /F /Q
endif

SRC := $(wildcard src/*.c) $(wildcard src/*/*.c) $(wildcard src/*/*/*.c)
RUNNER_SRC := src/tools/runner_stub.c
CORE_SRC := $(filter-out src/main.c $(RUNNER_SRC),$(SRC))
CORE_OBJ := $(CORE_SRC:.c=.o)
CLI_OBJ := src/main.o
RUNNER_OBJ := $(RUNNER_SRC:.c=.o)

.PHONY: all clean test run examples

all: protohackc$(EXE) protohack-runner$(EXE)

protohackc$(EXE): $(CORE_OBJ) $(CLI_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

protohack-runner$(EXE): $(CORE_OBJ) $(RUNNER_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

src/%.o: src/%.c include/protohack/protohack.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	-$(RM) $(CORE_OBJ) $(CLI_OBJ) $(RUNNER_OBJ) protohackc protohackc.exe protohack-runner protohack-runner.exe tests/test_basic tests/test_basic.exe

tests/test_basic$(EXE): tests/test_basic.c $(CORE_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

test: protohackc$(EXE) tests/test_basic$(EXE)
	./tests/test_basic$(EXE)

run: protohackc$(EXE)
	./protohackc$(EXE) examples/hello.phk --run

examples: run
