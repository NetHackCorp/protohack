CC := clang
CXX := clang++
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -Iinclude -D_CRT_SECURE_NO_WARNINGS
CXXFLAGS ?= -std=c++20 -Wall -Wextra -Werror -Iinclude -D_CRT_SECURE_NO_WARNINGS -D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH
LDFLAGS ?=
LIBS ?= -lm
RM := rm -f
EXE :=

ifeq ($(JIT),1)
CFLAGS += -DPROTOHACK_ENABLE_JIT=1
endif

ifeq ($(OS),Windows_NT)
EXE := .exe
LIBS :=
RM := cmd /C del /F /Q
endif

SRC_C := $(wildcard src/*.c) $(wildcard src/*/*.c) $(wildcard src/*/*/*.c)
SRC_C := $(filter-out src/stdlib/file_crypto.c,$(SRC_C))
SRC_C := $(filter-out src\stdlib\file_crypto.c,$(SRC_C))
SRC_CPP := $(wildcard src/*.cpp) $(wildcard src/*/*.cpp) $(wildcard src/*/*/*.cpp)
SRC_CPP += src/stdlib/file_crypto.cpp
SRC := $(SRC_C) $(SRC_CPP)
RUNNER_SRC := src/tools/runner_stub.c
CORE_SRC := $(filter-out src/main.c $(RUNNER_SRC),$(SRC))
CORE_OBJ := $(patsubst %.c,%.o,$(CORE_SRC))
CORE_OBJ := $(patsubst %.cpp,%.o,$(CORE_OBJ))
CLI_OBJ := src/main.o
RUNNER_OBJ := $(RUNNER_SRC:.c=.o)

LINKER := $(if $(SRC_CPP),$(CXX),$(CC))
LINKFLAGS := $(if $(SRC_CPP),$(CXXFLAGS),$(CFLAGS))

.PHONY: all clean test run examples

all: protohackc$(EXE) protohack-runner$(EXE)

protohackc$(EXE): $(CORE_OBJ) $(CLI_OBJ)
	$(LINKER) $(LINKFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

protohack-runner$(EXE): $(CORE_OBJ) $(RUNNER_OBJ)
	$(LINKER) $(LINKFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

src/%.o: src/%.c include/protohack/protohack.h
	$(CC) $(CFLAGS) -c $< -o $@

src/%.o: src/%.cpp include/protohack/protohack.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

src/stdlib/file_crypto.o: src/stdlib/file_crypto.cpp include/protohack/protohack.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	-$(RM) $(CORE_OBJ) $(CLI_OBJ) $(RUNNER_OBJ) tests/test_basic.o tests/test_perf.o protohackc protohackc.exe protohack-runner protohack-runner.exe tests/test_basic tests/test_basic.exe tests/test_perf tests/test_perf.exe

tests/test_basic.o: tests/test_basic.c include/protohack/protohack.h
	$(CC) $(CFLAGS) -c $< -o $@

tests/test_perf.o: tests/test_perf.c include/protohack/protohack.h
	$(CC) $(CFLAGS) -c $< -o $@

tests/test_basic$(EXE): tests/test_basic.o $(CORE_OBJ)
	$(LINKER) $(LINKFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

tests/test_perf$(EXE): tests/test_perf.o $(CORE_OBJ)
	$(LINKER) $(LINKFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

test: protohackc$(EXE) tests/test_basic$(EXE)
	./tests/test_basic$(EXE)

perf: protohackc$(EXE) tests/test_perf$(EXE)
	./tests/test_perf$(EXE)

run: protohackc$(EXE)
	./protohackc$(EXE) examples/hello.phk --run

examples: run
