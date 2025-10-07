#include "protohack/protohack.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifndef PERF_ITERATIONS
#define PERF_ITERATIONS 1000u
#endif

static const char *kPerfSource =
    "let total = 0;\n"
    "let i = 0;\n"
    "while (i < 500) {\n"
    "  total = total + sqrt(144) + rand(10);\n"
    "  i = i + 1;\n"
    "}\n"
    "let digest = hex_encode(rand_bytes(16));\n"
    "let summary = len(digest) + total;\n"
    "if (summary < 0) {\n"
    "  println(summary);\n"
    "}\n";

static size_t parse_iterations(int argc, char **argv) {
    if (argc < 2) {
        return PERF_ITERATIONS;
    }
    char *end = NULL;
    unsigned long long value = strtoull(argv[1], &end, 10);
    if (!end || *end != '\0') {
        fprintf(stderr, "[perf] Invalid iteration count '%s', using default %u.\n", argv[1], PERF_ITERATIONS);
        return PERF_ITERATIONS;
    }
    if (value == 0ull) {
        return PERF_ITERATIONS;
    }
    return (size_t)value;
}

int main(int argc, char **argv) {
    size_t iterations = parse_iterations(argc, argv);

    ProtoChunk chunk;
    protochunk_init(&chunk);

    ProtoError error;
    protoerror_reset(&error);

    if (!protohack_compile_source(kPerfSource, NULL, &chunk, &error)) {
        fprintf(stderr, "[perf] Compilation failed (line %zu): %s\n", error.line, error.message);
        protochunk_free(&chunk);
        return 1;
    }

    ProtoVM vm;
    protovm_init(&vm);

    clock_t start = clock();
    for (size_t i = 0; i < iterations; ++i) {
        protoerror_reset(&error);
        if (!protovm_run(&vm, &chunk, &error)) {
            fprintf(stderr, "[perf] VM run failed at iteration %zu (line %zu): %s\n", i, error.line, error.message);
            protochunk_free(&chunk);
            return 1;
        }
        protovm_reset(&vm);
        protovm_register_stdlib(&vm);
    }
    clock_t end = clock();

    double elapsed = (double)(end - start) / (double)CLOCKS_PER_SEC;
    double avg_ms = iterations > 0 ? (elapsed * 1000.0) / (double)iterations : 0.0;
    double throughput = elapsed > 0.0 ? (double)iterations / elapsed : 0.0;

    printf("Protohack performance benchmark\n");
    printf("Iterations: %zu\n", iterations);
    printf("Elapsed: %.3f s\n", elapsed);
    printf("Average: %.3f ms/run\n", avg_ms);
    printf("Throughput: %.1f runs/s\n", throughput);

    protochunk_free(&chunk);
    return 0;
}
