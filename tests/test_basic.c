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

    if (!protohack_compile_source(source, &chunk, &error)) {
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

    if (protohack_compile_source(source, &chunk, &error)) {
        report_failure(__func__, "Compilation should fail for undefined global", NULL);
        protochunk_free(&chunk);
        return;
    }

    if (error.ok || strstr(error.message, "Undefined") == NULL) {
        report_failure(__func__, "Error message should mention undefined global", &error);
    }

    protochunk_free(&chunk);
}

static void test_const_reassignment_fails(void) {
    const char *source = "const answer = 42;\nanswer = 0;\n";
    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (protohack_compile_source(source, &chunk, &error)) {
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

    if (!protohack_compile_source(source, &chunk, &error)) {
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

    if (!protohack_compile_source(source, &chunk, &error)) {
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

    if (tests_failed > 0) {
        fprintf(stderr, "%d/%d tests failed.\n", tests_failed, tests_run);
        return 1;
    }

    printf("All %d tests passed.\n", tests_run);
    return 0;
}
