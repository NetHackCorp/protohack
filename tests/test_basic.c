#include "protohack/protohack.h"

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_failed = 0;

static void report_failure(const char *test_name, const char *message, const ProtoError *error) {
    fprintf(stderr, "[FAIL] %s: %s", test_name, message);
    if (error && !error->ok) {
        fprintf(stderr, " (line %zu: %s)", error->line, error->message);
    }
    fprintf(stderr, "\n");
    tests_failed++;
}

static void test_compile_and_run_control_flow(void) {
    const char *source =
        "const greeting = \"hello\";\n"
        "let total = 0;\n"
        "let i = 0;\n"
        "while (i < 3) {\n"
        "  total = total + i;\n"
        "  i = i + 1;\n"
        "}\n"
        "print total;\n"
        "print upper(greeting);\n"
        "print len(to_string(total));\n";
    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (!protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should succeed", &error);
        protochunk_free(&chunk);
        return;
    }

    ProtoVM vm;
    protovm_init(&vm);
    if (!protovm_run(&vm, &chunk, &error)) {
        report_failure(__func__, "VM execution should succeed", &error);
        protochunk_free(&chunk);
        return;
    }

    const ProtoValue *result = protovm_last_print(&vm);
    if (!result || result->type != PROTO_VAL_NUMBER || fabs(result->as.number - 1.0) > 1e-6) {
        report_failure(__func__, "Expected last printed result to equal 1", NULL);
    }

    protochunk_free(&chunk);
}

static void test_use_undefined_global(void) {
    const char *source = "print missing;";
    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should fail for undefined global", NULL);
        protochunk_free(&chunk);
        return;
    }

    if (error.ok || strstr(error.message, "Undefined") == NULL) {
        report_failure(__func__, "Error message should mention undefined global", &error);
    }

    protochunk_free(&chunk);
}

static void test_suggest_misspelled_native(void) {
    const char *source = "prinln(\"oops\");";
    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should fail for misspelled native", NULL);
        protochunk_free(&chunk);
        return;
    }

    if (error.ok || strstr(error.message, "Did you mean 'println'") == NULL) {
        report_failure(__func__, "Error message should suggest 'println'", &error);
    }

    protochunk_free(&chunk);
}

static void test_const_reassignment_fails(void) {
    const char *source = "const answer = 42;\nanswer = 0;\n";
    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should fail when reassigning const", NULL);
        protochunk_free(&chunk);
        return;
    }

    if (error.ok || strstr(error.message, "const") == NULL) {
        report_failure(__func__, "Error message should mention const reassignment", &error);
    }

    protochunk_free(&chunk);
}

static void test_pack_and_extract_executable(void) {
    const char *source = "const value = 123;";
    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (!protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should succeed", &error);
        protochunk_free(&chunk);
        return;
    }

    const char *runner_path = "tests/tmp_runner.bin";
    const char *exe_path = "tests/tmp_embedded.bin";

    FILE *runner = fopen(runner_path, "wb");
    if (!runner) {
        report_failure(__func__, "Failed to create runner stub", NULL);
        protochunk_free(&chunk);
        return;
    }

    const char runner_data[] = "PROTOHACK-RUNNER";
    if (fwrite(runner_data, 1, sizeof runner_data, runner) != sizeof runner_data) {
        report_failure(__func__, "Failed to write runner stub", NULL);
        fclose(runner);
        remove(runner_path);
        protochunk_free(&chunk);
        return;
    }
    fclose(runner);

    ProtoSerializedBuffer expected = {0};
    if (!protochunk_serialize_to_buffer(&chunk, &expected, &error)) {
        report_failure(__func__, "Serialization to buffer should succeed", &error);
        protochunk_free(&chunk);
        remove(runner_path);
        return;
    }

    if (!protohack_pack_executable(&chunk, runner_path, exe_path, &error)) {
        report_failure(__func__, "Packing executable should succeed", &error);
        protochunk_buffer_free(&expected);
        protochunk_free(&chunk);
        remove(runner_path);
        remove(exe_path);
        return;
    }

    ProtoSerializedBuffer extracted = {0};
    if (!protohack_extract_embedded_program(exe_path, &extracted, &error)) {
        report_failure(__func__, "Extraction should succeed", &error);
        protochunk_buffer_free(&expected);
        protochunk_free(&chunk);
        remove(runner_path);
        remove(exe_path);
        return;
    }

    if (expected.size != extracted.size || memcmp(expected.data, extracted.data, expected.size) != 0) {
        report_failure(__func__, "Extracted payload should match serialized chunk", NULL);
    }

    protochunk_buffer_free(&expected);
    protochunk_buffer_free(&extracted);
    protochunk_free(&chunk);
    remove(runner_path);
    remove(exe_path);
}

static void test_user_function_and_memory(void) {
    const char *source =
        "craft double(value as num) gives num {\n"
        "  yield value + value;\n"
        "}\n"
        "let buffer = carve numeric(2);\n"
        "etch numeric(buffer, 0, 7);\n"
        "let output = double(probe numeric(buffer, 0));\n"
        "print output;\n";

    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (!protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should succeed", &error);
        protochunk_free(&chunk);
        return;
    }

    ProtoVM vm;
    protovm_init(&vm);
    if (!protovm_run(&vm, &chunk, &error)) {
        report_failure(__func__, "VM execution should succeed", &error);
        protochunk_free(&chunk);
        return;
    }

    const ProtoValue *result = protovm_last_print(&vm);
    if (!result || result->type != PROTO_VAL_NUMBER || fabs(result->as.number - 14.0) > 1e-6) {
        report_failure(__func__, "Expected doubled value from craft function", NULL);
    }

    protochunk_free(&chunk);
}

static void test_class_methods(void) {
    const char *source =
        "class Counter {\n"
        "  init(start as num) {\n"
        "    this.value = start;\n"
        "  }\n"
        "\n"
        "  inc() gives num {\n"
        "    this.value = this.value + 1;\n"
        "    yield this.value;\n"
        "  }\n"
        "}\n"
        "\n"
        "let c = Counter(10);\n"
        "print c.inc();\n"
        "print c.value;\n"
        "c.value = 42;\n"
        "let f = c.inc;\n"
        "print f();\n"
        "print c.value;\n";

    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (!protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should succeed for class methods", &error);
        protochunk_free(&chunk);
        return;
    }

    ProtoVM vm;
    protovm_init(&vm);
    if (!protovm_run(&vm, &chunk, &error)) {
        report_failure(__func__, "VM execution should succeed for class methods", &error);
        protochunk_free(&chunk);
        return;
    }

    const ProtoValue *result = protovm_last_print(&vm);
    if (!result || result->type != PROTO_VAL_NUMBER || fabs(result->as.number - 43.0) > 1e-6) {
        report_failure(__func__, "Expected last printed value to be 43", NULL);
    }

    protochunk_free(&chunk);
}

static void test_this_outside_class_fails(void) {
    const char *source = "print this;";
    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should fail when using 'this' outside a class", NULL);
        protochunk_free(&chunk);
        return;
    }

    if (error.ok || strstr(error.message, "this") == NULL) {
        report_failure(__func__, "Error message should mention 'this' misuse", &error);
    }

    protochunk_free(&chunk);
}

static void test_include_directive(void) {
    const char *source =
        "inc(\"include_helper.phk\");\n"
        "print inc_answer;\n";

    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (!protohack_compile_source(source, "tests/test_include_main.phk", &chunk, &error)) {
        report_failure(__func__, "Compilation should succeed with include", &error);
        protochunk_free(&chunk);
        return;
    }

    ProtoVM vm;
    protovm_init(&vm);
    if (!protovm_run(&vm, &chunk, &error)) {
        report_failure(__func__, "VM execution should succeed with include", &error);
        protochunk_free(&chunk);
        return;
    }

    const ProtoValue *result = protovm_last_print(&vm);
    if (!result || result->type != PROTO_VAL_NUMBER || fabs(result->as.number - 21.0) > 1e-6) {
        report_failure(__func__, "Included constants should be accessible", NULL);
    }

    protochunk_free(&chunk);
}

static void test_jit_block_extract(void) {
    const char *source = "let value = 42;\nprint value;\n";
    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (!protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should succeed", &error);
        protochunk_free(&chunk);
        return;
    }

    ProtoJITBlock block;
    if (!protojit_block_extract(&chunk, 0, &block)) {
        report_failure(__func__, "Expected block extraction to succeed", NULL);
        protochunk_free(&chunk);
        return;
    }

    if (block.instruction_count == 0) {
        report_failure(__func__, "Extracted block should contain instructions", NULL);
    }

    protochunk_free(&chunk);
}

static bool read_all_bytes(const char *path, unsigned char **out_data, size_t *out_size) {
    *out_data = NULL;
    *out_size = 0;
    FILE *file = fopen(path, "rb");
    if (!file) {
        return false;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return false;
    }
    long size = ftell(file);
    if (size < 0) {
        fclose(file);
        return false;
    }
    rewind(file);
    if (size == 0) {
        fclose(file);
        return true;
    }
    unsigned char *buffer = (unsigned char *)malloc((size_t)size);
    if (!buffer) {
        fclose(file);
        return false;
    }
    size_t read = fread(buffer, 1, (size_t)size, file);
    fclose(file);
    if (read != (size_t)size) {
        free(buffer);
        return false;
    }
    *out_data = buffer;
    *out_size = (size_t)size;
    return true;
}

static void test_encrypt_file_roundtrip(void) {
    const char *plain_path = "tests/tmp_encrypt_plain.bin";
    const char *cipher_path = "tests/tmp_encrypt_cipher.bin";
    const char *recovered_path = "tests/tmp_encrypt_recovered.bin";
    const char *payload = "Protohack encryption payload with multiple lines\nSecond line";
    size_t payload_length = strlen(payload);

    FILE *plain = fopen(plain_path, "wb");
    if (!plain) {
        report_failure(__func__, "Failed to create plain test file", NULL);
        return;
    }
    if (fwrite(payload, 1, payload_length, plain) != payload_length) {
        fclose(plain);
        report_failure(__func__, "Failed to write plain test file", NULL);
        remove(plain_path);
        return;
    }
    fclose(plain);

    const char *source =
        "let key = encrypt_file(\"tests/tmp_encrypt_plain.bin\", \"tests/tmp_encrypt_cipher.bin\");\n"
        "print len(key);\n"
        "decrypt_file(\"tests/tmp_encrypt_cipher.bin\", \"tests/tmp_encrypt_recovered.bin\", key);\n";

    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (!protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should succeed for encrypt/decrypt", &error);
        protochunk_free(&chunk);
        goto cleanup_files;
    }

    ProtoVM vm;
    protovm_init(&vm);
    if (!protovm_run(&vm, &chunk, &error)) {
        report_failure(__func__, "VM execution should succeed for encrypt/decrypt", &error);
        protochunk_free(&chunk);
        goto cleanup_files;
    }

    const ProtoValue *result = protovm_last_print(&vm);
    if (!result || result->type != PROTO_VAL_NUMBER || result->as.number <= 0.0) {
        report_failure(__func__, "encrypt_file should return non-empty key", NULL);
    }

    unsigned char *original_data = NULL;
    unsigned char *recovered_data = NULL;
    size_t original_size = 0;
    size_t recovered_size = 0;
    if (!read_all_bytes(plain_path, &original_data, &original_size) ||
        !read_all_bytes(recovered_path, &recovered_data, &recovered_size)) {
        report_failure(__func__, "Failed to read files for comparison", NULL);
        free(original_data);
        free(recovered_data);
        protochunk_free(&chunk);
        goto cleanup_files;
    }

    if (original_size != recovered_size ||
        (original_size > 0 && memcmp(original_data, recovered_data, original_size) != 0)) {
        report_failure(__func__, "Decrypted file should match original", NULL);
    }

    free(original_data);
    free(recovered_data);
    protochunk_free(&chunk);

cleanup_files:
    remove(plain_path);
    remove(cipher_path);
    remove(recovered_path);
}

static void test_complex_natives(void) {
    const char *source =
        "craft close(actual as num, expected as num, tolerance as num) gives flag {\n"
        "  let diff = actual - expected;\n"
        "  if (diff < 0) { diff = 0 - diff; }\n"
        "  yield diff <= tolerance;\n"
        "}\n"
        "let tol = 0.0001;\n"
        "let sum = complex_add(1, 2, 3, -4);\n"
        "let prod = complex_mul(2, -1, -1, 2);\n"
        "let quotient = complex_div(1, 1, 2, -2);\n"
        "let expo = complex_exp(0, 3.141592653589793);\n"
        "let magnitude = complex_abs(3, 4);\n"
        "let ok = close(probe numeric(sum, 0), 4, tol);\n"
        "ok = ok and close(probe numeric(sum, 1), -2, tol);\n"
        "ok = ok and close(probe numeric(prod, 0), 0, tol);\n"
        "ok = ok and close(probe numeric(prod, 1), 5, tol);\n"
        "ok = ok and close(probe numeric(quotient, 0), 0, tol);\n"
        "ok = ok and close(probe numeric(quotient, 1), 0.5, tol);\n"
        "ok = ok and close(probe numeric(expo, 0), -1, tol);\n"
        "ok = ok and close(probe numeric(expo, 1), 0, tol);\n"
        "ok = ok and close(magnitude, 5, tol);\n"
        "print ok;\n";

    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (!protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should succeed for complex natives", &error);
        protochunk_free(&chunk);
        return;
    }

    ProtoVM vm;
    protovm_init(&vm);
    if (!protovm_run(&vm, &chunk, &error)) {
        report_failure(__func__, "VM execution should succeed for complex natives", &error);
        protochunk_free(&chunk);
        return;
    }

    const ProtoValue *result = protovm_last_print(&vm);
    if (!result || result->type != PROTO_VAL_BOOL || !result->as.boolean) {
        report_failure(__func__, "Complex native checks should pass", NULL);
    }

    protochunk_free(&chunk);
}

static void test_complex_division_by_zero_errors(void) {
    const char *source = "complex_div(1, 0, 0, 0);\n";
    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (!protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should succeed for complex_div", &error);
        protochunk_free(&chunk);
        return;
    }

    ProtoVM vm;
    protovm_init(&vm);
    if (protovm_run(&vm, &chunk, &error)) {
        report_failure(__func__, "complex_div should fail when dividing by zero", NULL);
        protochunk_free(&chunk);
        return;
    }

    if (error.ok || strstr(error.message, "Complex division by zero") == NULL) {
        report_failure(__func__, "Division by zero should set descriptive error", &error);
    }

    protochunk_free(&chunk);
}

static void test_hex_encode_decode(void) {
    {
        const char *source = "print hex_encode(\"proto\");\n";
        ProtoChunk chunk;
        protochunk_init(&chunk);
        ProtoError error;
        protoerror_reset(&error);

    if (!protohack_compile_source(source, NULL, &chunk, &error)) {
            report_failure(__func__, "Compilation should succeed for hex_encode", &error);
            protochunk_free(&chunk);
            return;
        }

        ProtoVM vm;
        protovm_init(&vm);
        if (!protovm_run(&vm, &chunk, &error)) {
            report_failure(__func__, "VM execution should succeed for hex_encode", &error);
            protochunk_free(&chunk);
            return;
        }

        const ProtoValue *result = protovm_last_print(&vm);
        if (!result || result->type != PROTO_VAL_STRING || !result->as.string || strcmp(result->as.string, "70726f746f") != 0) {
            report_failure(__func__, "hex_encode should output lowercase hex", NULL);
        }

        protochunk_free(&chunk);
    }

    {
        const char *source =
            "let bytes = hex_decode(\"41ff\");\n"
            "let summary = probe raw(bytes, 0) * 1000 + probe raw(bytes, 1);\n"
            "print summary;\n";

        ProtoChunk chunk;
        protochunk_init(&chunk);
        ProtoError error;
        protoerror_reset(&error);

    if (!protohack_compile_source(source, NULL, &chunk, &error)) {
            report_failure(__func__, "Compilation should succeed for hex_decode", &error);
            protochunk_free(&chunk);
            return;
        }

        ProtoVM vm;
        protovm_init(&vm);
        if (!protovm_run(&vm, &chunk, &error)) {
            report_failure(__func__, "VM execution should succeed for hex_decode", &error);
            protochunk_free(&chunk);
            return;
        }

        const ProtoValue *result = protovm_last_print(&vm);
        if (!result || result->type != PROTO_VAL_NUMBER || fabs(result->as.number - 65255.0) > 1e-6) {
            report_failure(__func__, "hex_decode should produce expected numeric probe", NULL);
        }

        protochunk_free(&chunk);
    }
}

static void test_rand_bytes(void) {
    const char *source =
        "let bytes = rand_bytes(4);\n"
        "print hex_encode(bytes);\n";

    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (!protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should succeed for rand_bytes", &error);
        protochunk_free(&chunk);
        return;
    }

    ProtoVM vm;
    protovm_init(&vm);
    vm.rand_state = 0x12345678u;
    if (!protovm_run(&vm, &chunk, &error)) {
        report_failure(__func__, "VM execution should succeed for rand_bytes", &error);
        protochunk_free(&chunk);
        return;
    }

    const ProtoValue *result = protovm_last_print(&vm);
    static const char digits[] = "0123456789abcdef";
    char expected[9] = {0};
    uint32_t state = 0x12345678u;
    for (size_t i = 0; i < 4; ++i) {
        state = state * 1664525u + 1013904223u;
        uint8_t byte = (uint8_t)(state & 0xFFu);
        expected[2 * i] = digits[(byte >> 4) & 0x0F];
        expected[2 * i + 1] = digits[byte & 0x0F];
    }

    if (!result || result->type != PROTO_VAL_STRING || !result->as.string || strcmp(result->as.string, expected) != 0) {
        report_failure(__func__, "rand_bytes should leverage VM PRNG deterministically", NULL);
    }

    protochunk_free(&chunk);
}

#if PROTOHACK_ENABLE_JIT
static void test_jit_typed_memory_block(void) {
    const char *source =
        "let buffer = carve numeric(1);\n"
        "etch numeric(buffer, 0, 21);\n"
        "let value = probe numeric(buffer, 0);\n"
        "print value;\n";

    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (!protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should succeed", &error);
        protochunk_free(&chunk);
        return;
    }

    ProtoVM vm;
    protovm_init(&vm);
    if (!protovm_run(&vm, &chunk, &error)) {
        report_failure(__func__, "VM execution should succeed", &error);
        protochunk_free(&chunk);
        return;
    }

    const ProtoValue *result = protovm_last_print(&vm);
    if (!result || result->type != PROTO_VAL_NUMBER || fabs(result->as.number - 21.0) > 1e-6) {
        report_failure(__func__, "Expected printed value to equal 21", NULL);
    }

    const ProtoJITProfiler *profiler = protovm_profiler(&vm);
    if (!profiler) {
        report_failure(__func__, "Profiler should be available", NULL);
    } else {
        if (profiler->block_hits == 0) {
            report_failure(__func__, "Expected at least one JIT block execution", NULL);
        }
        if (profiler->block_bailouts_unsupported != 0 || profiler->block_bailouts_runtime != 0) {
            report_failure(__func__, "Typed memory block should not trigger bailouts", NULL);
        }
    }

    protochunk_free(&chunk);
}

static void test_jit_bailout_counters(void) {
    const char *source = "print rand(5);\n";

    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (!protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should succeed", &error);
        protochunk_free(&chunk);
        return;
    }

    ProtoVM vm;
    protovm_init(&vm);
    if (!protovm_run(&vm, &chunk, &error)) {
        report_failure(__func__, "VM execution should succeed", &error);
        protochunk_free(&chunk);
        return;
    }

    const ProtoJITProfiler *profiler = protovm_profiler(&vm);
    if (!profiler) {
        report_failure(__func__, "Profiler should be available", NULL);
    } else {
        if (profiler->block_bailouts_unsupported == 0) {
            report_failure(__func__, "Expected unsupported bailout to be recorded", NULL);
        }
        if (profiler->bailout_opcode_counts[PROTO_OP_CALL_NATIVE] == 0) {
            report_failure(__func__, "Expected CALL_NATIVE bailout histogram entry", NULL);
        }
    }

    protochunk_free(&chunk);
}
#endif

static void run_test(void (*test_fn)(void)) {
    tests_run++;
    test_fn();
}

int main(void) {
    run_test(test_compile_and_run_control_flow);
    run_test(test_use_undefined_global);
    run_test(test_const_reassignment_fails);
    run_test(test_pack_and_extract_executable);
    run_test(test_user_function_and_memory);
    run_test(test_class_methods);
    run_test(test_this_outside_class_fails);
    run_test(test_include_directive);
    run_test(test_suggest_misspelled_native);
    run_test(test_jit_block_extract);
    run_test(test_encrypt_file_roundtrip);
    run_test(test_complex_natives);
    run_test(test_complex_division_by_zero_errors);
    run_test(test_hex_encode_decode);
    run_test(test_rand_bytes);
#if PROTOHACK_ENABLE_JIT
    run_test(test_jit_typed_memory_block);
    run_test(test_jit_bailout_counters);
#endif

    if (tests_failed > 0) {
        fprintf(stderr, "%d/%d tests failed.\n", tests_failed, tests_run);
        return 1;
    }

    printf("All %d tests passed.\n", tests_run);
    return 0;
}
