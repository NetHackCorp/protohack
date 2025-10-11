#include "protohack/protohack.h"

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_failed = 0;

#define RUN_TEST(FN) do { \
    fprintf(stderr, "RUN %s\n", #FN); \
    run_test((FN)); \
} while (0)

static void report_failure(const char *test_name, const char *message, const ProtoError *error) {
    fprintf(stderr, "[FAIL] %s: %s", test_name, message);
    if (error && !error->ok) {
        fprintf(stderr, " (line %zu: %s)", error->line, error->message);
    }
    fprintf(stderr, "\n");
    tests_failed++;
}

static ProtoFunction *find_function_constant(const ProtoChunk *chunk, const char *name) {
    if (!chunk || !name) {
        return NULL;
    }
    for (size_t i = 0; i < chunk->constants_count; ++i) {
        const ProtoValue *constant = &chunk->constants[i];
        if (constant->type != PROTO_VAL_FUNCTION) {
            continue;
        }
        ProtoFunction *function = constant->as.function;
        if (!function || !function->name) {
            continue;
        }
        if (strcmp(function->name, name) == 0) {
            return function;
        }
    }
    return NULL;
}

static void test_protoerror_json_serialization(void) {
    ProtoError error;
    protoerror_reset(&error);

    protoerror_set_code_with_column(&error, PROTO_DIAG_NATIVE_ARG_TYPE, 12, 4, "example diagnostic");
    protoerror_set_message_key(&error, "unit.test.example");
    protoerror_set_hint(&error, "Review argument %d for compatibility.", 1);

    char json[512];
    protoerror_to_json(&error, json, sizeof json);

    if (!strstr(json, "\"code\":3") ||
        !strstr(json, "\"codeText\":\"native_argument_type\"") ||
        !strstr(json, "unit.test.example") ||
        !strstr(json, "Review argument 1")) {
        report_failure(__func__, "JSON payload missing expected fields", NULL);
    }
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

static void test_module_header_metadata(void) {
    const char *source = "const sample = 1;";
    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (!protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should succeed", &error);
        protochunk_free(&chunk);
        return;
    }

    ProtoSerializedBuffer buffer = {0};
    if (!protochunk_serialize_to_buffer(&chunk, &buffer, &error)) {
        report_failure(__func__, "Serialization should succeed", &error);
        protochunk_free(&chunk);
        return;
    }

    size_t header_bytes = 4 + 7 * sizeof(uint32_t);
    if (buffer.size < header_bytes) {
        report_failure(__func__, "Serialized buffer should include module header", NULL);
        protochunk_buffer_free(&buffer);
        protochunk_free(&chunk);
        return;
    }

    if (memcmp(buffer.data, PROTOHACK_BYTECODE_MAGIC, 4) != 0) {
        report_failure(__func__, "Bytecode magic should match current format", NULL);
        protochunk_buffer_free(&buffer);
        protochunk_free(&chunk);
        return;
    }

    uint32_t header_fields[7] = {0};
    memcpy(header_fields, buffer.data + 4, sizeof header_fields);
    if (header_fields[0] != PROTOHACK_MODULE_VERSION) {
        report_failure(__func__, "Header should encode module version", NULL);
    }
    if (header_fields[1] != 0) {
        report_failure(__func__, "Flags should be zero when no metadata is present", NULL);
    }
    if (header_fields[6] != 0) {
        report_failure(__func__, "Binding count should default to zero", NULL);
    }

    ProtoChunk roundtrip;
    protochunk_init(&roundtrip);
    if (!protochunk_deserialize_from_memory(&roundtrip, buffer.data, buffer.size, &error)) {
        report_failure(__func__, "Deserialization should succeed", &error);
        protochunk_buffer_free(&buffer);
        protochunk_free(&chunk);
        protochunk_free(&roundtrip);
        return;
    }

    if (roundtrip.module_version != PROTOHACK_MODULE_VERSION) {
        report_failure(__func__, "Roundtrip chunk should track module version", NULL);
    }
    if ((roundtrip.module_flags & PROTOHACK_MODULE_FLAG_HAS_BINDING_MAP) != 0) {
        report_failure(__func__, "Roundtrip chunk should not report binding map flag", NULL);
    }
    if (roundtrip.binding_entry_count != 0) {
        report_failure(__func__, "Roundtrip binding map should be empty", NULL);
    }

    protochunk_buffer_free(&buffer);
    protochunk_free(&roundtrip);
    protochunk_free(&chunk);
}

static void test_extend_parser_metadata(void) {
    const char *source =
        "craft identity<T>(value as T) gives T {\n"
        "  yield value;\n"
        "}\n"
        "\n"
        "extend craft identity<num> with Printable (value as num) gives num {\n"
        "  print value;\n"
        "  yield value;\n"
        "}\n";

    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (!protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should succeed for extend parsing", &error);
        protochunk_free(&chunk);
        return;
    }

    if (chunk.extension_count != 1) {
        report_failure(__func__, "Expected a single extension declaration to be recorded", NULL);
        protochunk_free(&chunk);
        return;
    }

    const ProtoExtensionDecl *first = &chunk.extensions[0];
    if (first->target_kind != PROTO_EXTENSION_TARGET_CRAFT) {
        report_failure(__func__, "First extension should target a craft", NULL);
    }
    if (strcmp(first->target.name, "identity") != 0) {
        report_failure(__func__, "First extension target name mismatch", NULL);
    }
    if (first->target.bindings.count != 1 || first->target.bindings.entries[0].tag != PROTO_TYPE_NUM) {
        report_failure(__func__, "First extension should record numeric specialization", NULL);
    }
    if (first->trait_count != 1 || strcmp(first->traits[0].name, "Printable") != 0) {
        report_failure(__func__, "First extension trait list mismatch", NULL);
    }
    if (!first->body_source || strstr(first->body_source, "yield value;") == NULL) {
        report_failure(__func__, "First extension body should capture function source", NULL);
    }

    protochunk_free(&chunk);
}

static void test_extend_requires_type_arguments(void) {
    const char *source =
        "craft identity<T>(value as T) gives T {\n"
        "  yield value;\n"
        "}\n"
        "\n"
        "extend craft identity (value as num) gives num {\n"
        "  yield value;\n"
        "}\n";

    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should fail when craft extension omits type arguments", NULL);
        protochunk_free(&chunk);
        return;
    }

    if (error.ok || !strstr(error.message, "requires 1 type argument")) {
        report_failure(__func__, "Error message should state that craft requires type arguments", &error);
    }

    protochunk_free(&chunk);
}

static void test_extend_rejects_type_arguments_for_non_generic_craft(void) {
    const char *source =
        "craft double(value as num) gives num {\n"
        "  yield value + value;\n"
        "}\n"
        "\n"
        "extend craft double<num> (value as num) gives num {\n"
        "  yield value;\n"
        "}\n";

    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should fail when non-generic craft extension supplies type arguments", NULL);
        protochunk_free(&chunk);
        return;
    }

    if (error.ok || strstr(error.message, "does not accept type arguments") == NULL) {
        report_failure(__func__, "Error message should state that craft is not generic", &error);
    }

    protochunk_free(&chunk);
}

static void test_extend_craft_specialization_execution(void) {
    const char *source =
        "craft identity<T>(value as T) gives T {\n"
        "  yield value;\n"
        "}\n"
        "\n"
        "extend craft identity<num> (value as num) gives num {\n"
        "  yield value + 10;\n"
        "}\n"
        "\n"
        "let result = identity<num>(5);\n"
        "print result;\n";

    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (!protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should succeed for craft extension override", &error);
        protochunk_free(&chunk);
        return;
    }

    ProtoVM vm;
    protovm_init(&vm);
    if (!protovm_run(&vm, &chunk, &error)) {
        report_failure(__func__, "VM execution should succeed for craft extension override", &error);
        protochunk_free(&chunk);
        return;
    }

    const ProtoValue *result = protovm_last_print(&vm);
    if (!result || result->type != PROTO_VAL_NUMBER || fabs(result->as.number - 15.0) > 1e-6) {
        report_failure(__func__, "Craft extension should modify specialization result", NULL);
    }

    protochunk_free(&chunk);
}

static void test_extend_craft_parameter_type_mismatch(void) {
    const char *source =
        "craft identity<T>(value as T) gives T {\n"
        "  yield value;\n"
        "}\n"
        "\n"
        "extend craft identity<num> (value as text) gives num {\n"
        "  yield value;\n"
        "}\n";

    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should fail when craft extension parameter type mismatches", NULL);
        protochunk_free(&chunk);
        return;
    }

    if (error.ok || strstr(error.message, "parameter 1") == NULL) {
        report_failure(__func__, "Error message should mention parameter type mismatch", &error);
    }

    protochunk_free(&chunk);
}

static void test_user_function_and_memory(void) {
    const char *source =
        "craft double(value as num) gives num {\n"
        "  yield value + value;\n"
        "}\n"
        "let output = double(7);\n"
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

static void test_generic_specialization_concrete_binding(void) {
    const char *source =
        "craft identity<T>(value as T) gives T {\n"
        "  yield value;\n"
        "}\n"
        "let answer = identity<num>(42);\n";

    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (!protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should succeed for concrete specialization", &error);
        protochunk_free(&chunk);
        return;
    }

    ProtoFunction *specialized = find_function_constant(&chunk, "identity<num>");
    if (!specialized) {
        report_failure(__func__, "Expected identity<num> specialization to be emitted", NULL);
        protochunk_free(&chunk);
        return;
    }

    if (specialized->bindings.count != 1) {
        report_failure(__func__, "Concrete specialization should record one binding", NULL);
        protochunk_free(&chunk);
        return;
    }

    const ProtoTypeBinding *binding = &specialized->bindings.entries[0];
    if (binding->tag != PROTO_TYPE_NUM || binding->param != -1) {
        report_failure(__func__, "Binding should resolve to num", NULL);
        protochunk_free(&chunk);
        return;
    }

    if (specialized->type_argument_count != 1 || specialized->type_arguments[0] != PROTO_TYPE_NUM) {
        report_failure(__func__, "Type argument metadata should capture num", NULL);
        protochunk_free(&chunk);
        return;
    }

    if (specialized->arity < 1 || specialized->param_types[0] != PROTO_TYPE_NUM) {
        report_failure(__func__, "Parameter type should be substituted with num", NULL);
        protochunk_free(&chunk);
        return;
    }

    if (specialized->return_type != PROTO_TYPE_NUM) {
        report_failure(__func__, "Return type should be substituted with num", NULL);
        protochunk_free(&chunk);
        return;
    }

    char *description = proto_function_debug_description(specialized);
    if (!description || strstr(description, "bindings{T=num") == NULL) {
        report_failure(__func__, "Debug description should include concrete binding", NULL);
        free(description);
        protochunk_free(&chunk);
        return;
    }
    free(description);

    protochunk_free(&chunk);
}

static void test_generic_specialization_symbolic_binding(void) {
    const char *source =
        "craft identity<T>(value as T) gives T {\n"
        "  yield value;\n"
        "}\n"
        "craft forward<U>(value as U) gives U {\n"
        "  let alias = identity<U>;\n"
        "  yield alias(value);\n"
        "}\n";

    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (!protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should succeed for symbolic specialization", &error);
        protochunk_free(&chunk);
        return;
    }

    ProtoFunction *forward = find_function_constant(&chunk, "forward");
    if (!forward) {
        report_failure(__func__, "Expected to find craft 'forward'", NULL);
        protochunk_free(&chunk);
        return;
    }

    ProtoFunction *specialized = NULL;
    const char *actual_name = NULL;
    for (size_t i = 0; i < forward->chunk.constants_count; ++i) {
        const ProtoValue *constant = &forward->chunk.constants[i];
        if (constant->type != PROTO_VAL_FUNCTION) {
            continue;
        }
        ProtoFunction *fn = constant->as.function;
        if (!fn || !fn->name) {
            continue;
        }
        if (strncmp(fn->name, "identity<", 9) == 0) {
            specialized = fn;
            actual_name = fn->name;
            break;
        }
    }

    if (!specialized) {
        report_failure(__func__, "Expected identity<…> specialization inside forward", NULL);
        protochunk_free(&chunk);
        return;
    }

    if (strcmp(actual_name, "identity<U>") != 0) {
        char message[256];
        snprintf(message, sizeof message, "Specialization name mismatch: got '%s'", actual_name);
        report_failure(__func__, message, NULL);
        protochunk_free(&chunk);
        return;
    }

    if (specialized->bindings.count != 1) {
        report_failure(__func__, "Symbolic specialization should retain one binding", NULL);
        protochunk_free(&chunk);
        return;
    }

    const ProtoTypeBinding *binding = &specialized->bindings.entries[0];
    if (binding->tag != PROTO_TYPE_ANY || binding->param != 0) {
        report_failure(__func__, "Symbolic binding should reference type parameter index 0", NULL);
        protochunk_free(&chunk);
        return;
    }

    if (specialized->type_argument_count != 1 || specialized->type_arguments[0] != PROTO_TYPE_ANY) {
        report_failure(__func__, "Type arguments should remain symbolic", NULL);
        protochunk_free(&chunk);
        return;
    }

    if (specialized->arity < 1 || specialized->param_types[0] != PROTO_TYPE_ANY) {
        report_failure(__func__, "Parameter type should remain symbolic", NULL);
        protochunk_free(&chunk);
        return;
    }

    if (specialized->return_type != PROTO_TYPE_ANY) {
        report_failure(__func__, "Return type should remain symbolic", NULL);
        protochunk_free(&chunk);
        return;
    }

    char *description = proto_function_debug_description(specialized);
    if (!description || strstr(description, "bindings{T=&T") == NULL) {
        report_failure(__func__, "Debug description should show symbolic binding", NULL);
        free(description);
        protochunk_free(&chunk);
        return;
    }
    free(description);

    protochunk_free(&chunk);
}

static void test_native_binding_contract_success(void) {
    const char *source =
        "craft binder<T>(value as T) gives T {\n"
        "  expect_num_binding();\n"
        "  yield value;\n"
        "}\n"
        "let value = binder<num>(42);\n";

    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (!protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should succeed for numeric specialization", &error);
        protochunk_free(&chunk);
        return;
    }

    ProtoVM vm;
    protovm_init(&vm);
    if (!protovm_run(&vm, &chunk, &error)) {
        report_failure(__func__, "VM execution should accept numeric binding contract", &error);
        protochunk_free(&chunk);
        return;
    }

    protochunk_free(&chunk);
}

static void test_native_binding_contract_failure(void) {
    const char *source =
        "craft binder<T>(value as T) gives T {\n"
        "  expect_num_binding();\n"
        "  yield value;\n"
        "}\n"
        "let value = binder<text>(\"hi\");\n";

    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (!protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should succeed for symbolic specialization", &error);
        protochunk_free(&chunk);
        return;
    }

    ProtoVM vm;
    protovm_init(&vm);
    if (protovm_run(&vm, &chunk, &error)) {
        report_failure(__func__, "VM execution should reject incompatible native binding", NULL);
        protochunk_free(&chunk);
        return;
    }

    if (protoerror_get_code(&error) != PROTO_DIAG_INTEROP_SIGNATURE_MISMATCH) {
        report_failure(__func__, "Expected interop signature mismatch diagnostic", &error);
        protochunk_free(&chunk);
        return;
    }

    const char *message_key = protoerror_get_message_key(&error);
    if (!message_key || strcmp(message_key, "runtime.native.bindingContract") != 0) {
        report_failure(__func__, "Unexpected message key for binding contract error", &error);
    }

    protochunk_free(&chunk);
}

static void test_generic_binding_map_exports(void) {
    const char *source =
        "craft identity<T>(value as T) gives T {\n"
        "  yield value;\n"
        "}\n"
        "let alias = identity<num>;\n";

    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (!protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should succeed for binding map export", &error);
        protochunk_free(&chunk);
        return;
    }

    int alias_index = protochunk_find_global(&chunk, "alias");
    if (alias_index < 0) {
        report_failure(__func__, "Expected to intern alias global", NULL);
        protochunk_free(&chunk);
        return;
    }

    if (chunk.binding_entry_count != 1) {
        report_failure(__func__, "Module should record a single binding entry", NULL);
        protochunk_free(&chunk);
        return;
    }

    const ProtoBindingMapEntry *entry = NULL;
    for (size_t i = 0; i < chunk.binding_entry_count; ++i) {
        if (chunk.binding_entries[i].symbol_index == (uint32_t)alias_index) {
            entry = &chunk.binding_entries[i];
            break;
        }
    }

    if (!entry) {
        report_failure(__func__, "Binding map should include alias symbol", NULL);
        protochunk_free(&chunk);
        return;
    }

    if (entry->bindings.count != 1 ||
        entry->bindings.entries[0].tag != PROTO_TYPE_NUM ||
        entry->bindings.entries[0].param != -1) {
        report_failure(__func__, "Binding entry should capture concrete num specialization", NULL);
        protochunk_free(&chunk);
        return;
    }

    if ((chunk.module_flags & PROTOHACK_MODULE_FLAG_HAS_BINDING_MAP) == 0) {
        report_failure(__func__, "Module flags should mark presence of binding map", NULL);
        protochunk_free(&chunk);
        return;
    }

    ProtoSerializedBuffer buffer = {0};
    if (!protochunk_serialize_to_buffer(&chunk, &buffer, &error)) {
        report_failure(__func__, "Serialization should succeed for binding map export", &error);
        protochunk_free(&chunk);
        return;
    }

    ProtoChunk roundtrip;
    protochunk_init(&roundtrip);
    if (!protochunk_deserialize_from_memory(&roundtrip, buffer.data, buffer.size, &error)) {
        report_failure(__func__, "Deserialization should preserve binding map", &error);
        protochunk_buffer_free(&buffer);
        protochunk_free(&chunk);
        return;
    }

    int roundtrip_alias = protochunk_find_global(&roundtrip, "alias");
    if (roundtrip_alias < 0) {
        report_failure(__func__, "Roundtrip chunk should intern alias global", NULL);
        protochunk_buffer_free(&buffer);
        protochunk_free(&roundtrip);
        protochunk_free(&chunk);
        return;
    }

    const ProtoBindingMapEntry *roundtrip_entry = NULL;
    for (size_t i = 0; i < roundtrip.binding_entry_count; ++i) {
        if (roundtrip.binding_entries[i].symbol_index == (uint32_t)roundtrip_alias) {
            roundtrip_entry = &roundtrip.binding_entries[i];
            break;
        }
    }

    if (!roundtrip_entry) {
        report_failure(__func__, "Roundtrip binding map should include alias symbol", NULL);
        protochunk_buffer_free(&buffer);
        protochunk_free(&roundtrip);
        protochunk_free(&chunk);
        return;
    }

    if (roundtrip_entry->bindings.count != 1 ||
        roundtrip_entry->bindings.entries[0].tag != PROTO_TYPE_NUM ||
        roundtrip_entry->bindings.entries[0].param != -1) {
        report_failure(__func__, "Roundtrip binding entry should remain concrete", NULL);
        protochunk_buffer_free(&buffer);
        protochunk_free(&roundtrip);
        protochunk_free(&chunk);
        return;
    }

    if ((roundtrip.module_flags & PROTOHACK_MODULE_FLAG_HAS_BINDING_MAP) == 0) {
        report_failure(__func__, "Roundtrip module flags should indicate binding map", NULL);
    }

    protochunk_buffer_free(&buffer);
    protochunk_free(&roundtrip);
    protochunk_free(&chunk);
}

static void test_generic_specialization_unknown_argument(void) {
    const char *source =
        "craft identity<T>(value as T) gives T {\n"
        "  yield value;\n"
        "}\n"
        "let alias = identity<foo>;\n";

    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should fail for unknown type argument", NULL);
        protochunk_free(&chunk);
        return;
    }

    if (error.ok || !strstr(error.message, "foo")) {
        report_failure(__func__, "Error message should mention unknown type argument", &error);
    }

    protochunk_free(&chunk);
}

static void test_generic_binding_serialization_roundtrip(void) {
    const char *source =
        "craft identity<T>(value as T) gives T {\n"
        "  yield value;\n"
        "}\n"
        "let answer = identity<num>(42);\n";

    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (!protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should succeed for serialization roundtrip", &error);
        protochunk_free(&chunk);
        return;
    }

    ProtoFunction *specialized = find_function_constant(&chunk, "identity<num>");
    if (!specialized) {
        report_failure(__func__, "Expected identity<num> specialization in original chunk", NULL);
        protochunk_free(&chunk);
        return;
    }

    if (specialized->bindings.count != 1 ||
        specialized->bindings.entries[0].tag != PROTO_TYPE_NUM ||
        specialized->bindings.entries[0].param != -1) {
        report_failure(__func__, "Original binding metadata should be concrete", NULL);
        protochunk_free(&chunk);
        return;
    }

    ProtoSerializedBuffer buffer = {0};
    if (!protochunk_serialize_to_buffer(&chunk, &buffer, &error)) {
        report_failure(__func__, "Serialization should succeed", &error);
        protochunk_free(&chunk);
        return;
    }

    ProtoChunk roundtrip;
    protochunk_init(&roundtrip);
    if (!protochunk_deserialize_from_memory(&roundtrip, buffer.data, buffer.size, &error)) {
        report_failure(__func__, "Deserialization should succeed", &error);
        protochunk_buffer_free(&buffer);
        protochunk_free(&chunk);
        return;
    }

    ProtoFunction *roundtrip_specialized = find_function_constant(&roundtrip, "identity<num>");
    if (!roundtrip_specialized) {
        report_failure(__func__, "Expected identity<num> specialization after roundtrip", NULL);
        protochunk_buffer_free(&buffer);
        protochunk_free(&roundtrip);
        protochunk_free(&chunk);
        return;
    }

    if (roundtrip_specialized->bindings.count != 1 ||
        roundtrip_specialized->bindings.entries[0].tag != PROTO_TYPE_NUM ||
        roundtrip_specialized->bindings.entries[0].param != -1) {
        report_failure(__func__, "Roundtrip binding metadata should remain concrete", NULL);
        protochunk_buffer_free(&buffer);
        protochunk_free(&roundtrip);
        protochunk_free(&chunk);
        return;
    }

    char *description = proto_function_debug_description(roundtrip_specialized);
    if (!description || strstr(description, "bindings{T=num") == NULL) {
        report_failure(__func__, "Roundtrip debug description should include concrete binding", NULL);
        free(description);
        protochunk_buffer_free(&buffer);
        protochunk_free(&roundtrip);
        protochunk_free(&chunk);
        return;
    }
    free(description);

    protochunk_buffer_free(&buffer);
    protochunk_free(&roundtrip);
    protochunk_free(&chunk);
}

static void test_generic_call_argument_type_mismatch(void) {
    const char *source =
        "craft identity<T>(value as T) gives T {\n"
        "  yield value;\n"
        "}\n"
        "let alias = identity<num>;\n"
        "alias(true);\n";

    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should fail for mismatched call argument", NULL);
        protochunk_free(&chunk);
        return;
    }

    if (error.ok || !strstr(error.message, "Argument 1")) {
        report_failure(__func__, "Error message should mention first argument mismatch", &error);
    }

    protochunk_free(&chunk);
}

static void test_runtime_specialization_dispatch(void) {
    const char *source =
        "craft identity<T>(value as T) gives T {\n"
        "  yield value;\n"
        "}\n"
        "craft forward<U>(value as U) gives U {\n"
        "  let helper = identity<U>;\n"
        "  yield helper(value);\n"
        "}\n"
        "print forward<num>(42);\n";

    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (!protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should succeed for runtime dispatch test", &error);
        protochunk_free(&chunk);
        return;
    }

    ProtoFunction *forward_specialized = find_function_constant(&chunk, "forward<num>");
    if (!forward_specialized) {
        report_failure(__func__, "Expected to locate forward<num> specialization", NULL);
        protochunk_free(&chunk);
        return;
    }

    ProtoFunction *symbolic_identity = NULL;
    for (size_t i = 0; i < forward_specialized->chunk.constants_count; ++i) {
        const ProtoValue *constant = &forward_specialized->chunk.constants[i];
        if (constant->type != PROTO_VAL_FUNCTION) {
            continue;
        }
        ProtoFunction *candidate = constant->as.function;
        if (!candidate || !candidate->name) {
            continue;
        }
        if (strcmp(candidate->name, "identity<U>") == 0) {
            symbolic_identity = candidate;
            break;
        }
    }

    if (!symbolic_identity) {
        report_failure(__func__, "Expected to locate symbolic identity<U> specialization", NULL);
        protochunk_free(&chunk);
        return;
    }

    ProtoVM vm;
    protovm_init(&vm);
    if (!protovm_run(&vm, &chunk, &error)) {
        report_failure(__func__, "VM execution should succeed for runtime specialization", &error);
        protochunk_free(&chunk);
        return;
    }

    ProtoTypeBindingSet binding;
    binding.count = 1;
    for (uint8_t i = 0; i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
        binding.entries[i].tag = PROTO_TYPE_ANY;
        binding.entries[i].param = -1;
    }
    binding.entries[0].tag = PROTO_TYPE_NUM;
    binding.entries[0].param = -1;

    if (vm.specializations.count == 0) {
        report_failure(__func__, "VM should record at least one specialization entry", NULL);
        protochunk_free(&chunk);
        return;
    }

    ProtoFunction *specialized = protovm_find_specialization(&vm, symbolic_identity, &binding);
    if (!specialized) {
        report_failure(__func__, "Runtime lookup should produce identity<num> specialization", NULL);
        protochunk_free(&chunk);
        return;
    }

    if (specialized->bindings.count != 1 ||
        specialized->bindings.entries[0].tag != PROTO_TYPE_NUM ||
        specialized->bindings.entries[0].param != -1) {
        report_failure(__func__, "Specialization bindings should resolve to num", NULL);
        protochunk_free(&chunk);
        return;
    }

    if (specialized->arity < 1 || specialized->param_types[0] != PROTO_TYPE_NUM) {
        report_failure(__func__, "Parameter types should be substituted at runtime", NULL);
        protochunk_free(&chunk);
        return;
    }

    if (specialized->return_type != PROTO_TYPE_NUM) {
        report_failure(__func__, "Return type should be specialized to num", NULL);
        protochunk_free(&chunk);
        return;
    }

    const ProtoValue *result = protovm_last_print(&vm);
    if (!result || result->type != PROTO_VAL_NUMBER || fabs(result->as.number - 42.0) > 1e-6) {
        report_failure(__func__, "Runtime dispatch should yield the original numeric value", NULL);
        protochunk_free(&chunk);
        return;
    }

    protovm_reset(&vm);
    protochunk_free(&chunk);
}

static void test_runtime_specialization_serialization_roundtrip(void) {
    const char *source =
        "craft identity<T>(value as T) gives T {\n"
        "  yield value;\n"
        "}\n"
        "craft forward<U>(value as U) gives U {\n"
        "  let helper = identity<U>;\n"
        "  yield helper(value);\n"
        "}\n"
        "print forward<num>(42);\n";

    ProtoChunk chunk;
    protochunk_init(&chunk);
    ProtoError error;
    protoerror_reset(&error);

    if (!protohack_compile_source(source, NULL, &chunk, &error)) {
        report_failure(__func__, "Compilation should succeed for serialization dispatch test", &error);
        protochunk_free(&chunk);
        return;
    }

    ProtoSerializedBuffer buffer = {0};
    if (!protochunk_serialize_to_buffer(&chunk, &buffer, &error)) {
        report_failure(__func__, "Serialization should succeed", &error);
        protochunk_free(&chunk);
        return;
    }

    ProtoChunk reloaded;
    protochunk_init(&reloaded);
    if (!protochunk_deserialize_from_memory(&reloaded, buffer.data, buffer.size, &error)) {
        report_failure(__func__, "Deserialization should succeed", &error);
        protochunk_buffer_free(&buffer);
        protochunk_free(&reloaded);
        protochunk_free(&chunk);
        return;
    }

    ProtoFunction *forward_specialized = find_function_constant(&reloaded, "forward<num>");
    if (!forward_specialized) {
        report_failure(__func__, "Expected to locate forward<num> specialization after reload", NULL);
        protochunk_buffer_free(&buffer);
        protochunk_free(&reloaded);
        protochunk_free(&chunk);
        return;
    }

    ProtoFunction *symbolic_identity = NULL;
    for (size_t i = 0; i < forward_specialized->chunk.constants_count; ++i) {
        const ProtoValue *constant = &forward_specialized->chunk.constants[i];
        if (constant->type != PROTO_VAL_FUNCTION) {
            continue;
        }
        ProtoFunction *candidate = constant->as.function;
        if (!candidate || !candidate->name) {
            continue;
        }
        if (strcmp(candidate->name, "identity<U>") == 0) {
            symbolic_identity = candidate;
            break;
        }
    }

    if (!symbolic_identity) {
        report_failure(__func__, "Expected to locate symbolic identity<U> specialization after reload", NULL);
        protochunk_buffer_free(&buffer);
        protochunk_free(&reloaded);
        protochunk_free(&chunk);
        return;
    }

    ProtoVM vm;
    protovm_init(&vm);
    if (!protovm_run(&vm, &reloaded, &error)) {
        report_failure(__func__, "VM execution should succeed for reloaded module", &error);
        protovm_reset(&vm);
        protochunk_buffer_free(&buffer);
        protochunk_free(&reloaded);
        protochunk_free(&chunk);
        return;
    }

    if (vm.specializations.count == 0) {
        report_failure(__func__, "VM should record specializations after runtime dispatch", NULL);
        protovm_reset(&vm);
        protochunk_buffer_free(&buffer);
        protochunk_free(&reloaded);
        protochunk_free(&chunk);
        return;
    }

    ProtoTypeBindingSet binding;
    binding.count = 1;
    for (uint8_t i = 0; i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
        binding.entries[i].tag = PROTO_TYPE_ANY;
        binding.entries[i].param = -1;
    }
    binding.entries[0].tag = PROTO_TYPE_NUM;
    binding.entries[0].param = -1;

    ProtoFunction *specialized = protovm_find_specialization(&vm, symbolic_identity, &binding);
    if (!specialized) {
        report_failure(__func__, "Runtime lookup should find identity<num> after reload", NULL);
        protovm_reset(&vm);
        protochunk_buffer_free(&buffer);
        protochunk_free(&reloaded);
        protochunk_free(&chunk);
        return;
    }

    if (specialized->bindings.count != 1 ||
        specialized->bindings.entries[0].tag != PROTO_TYPE_NUM ||
        specialized->bindings.entries[0].param != -1) {
        report_failure(__func__, "Specialization bindings should remain concrete after reload", NULL);
        protovm_reset(&vm);
        protochunk_buffer_free(&buffer);
        protochunk_free(&reloaded);
        protochunk_free(&chunk);
        return;
    }

    const ProtoValue *result = protovm_last_print(&vm);
    if (!result || result->type != PROTO_VAL_NUMBER || fabs(result->as.number - 42.0) > 1e-6) {
        report_failure(__func__, "Reloaded specialization dispatch should return original value", NULL);
        protovm_reset(&vm);
        protochunk_buffer_free(&buffer);
        protochunk_free(&reloaded);
        protochunk_free(&chunk);
        return;
    }

    protovm_reset(&vm);
    protochunk_buffer_free(&buffer);
    protochunk_free(&reloaded);
    protochunk_free(&chunk);
}

static void test_vm_specialization_table(void) {
    ProtoVM vm;
    protovm_init(&vm);

    ProtoFunction *template_fn = proto_function_new(PROTO_FUNC_CRAFT, "template");
    const char *params[1] = {"T"};
    if (!proto_function_set_type_params(template_fn, params, 1)) {
        report_failure(__func__, "Failed to set template type parameters", NULL);
        proto_function_free(template_fn);
        return;
    }

    ProtoTypeBindingSet bindings = {0};
    bindings.count = 1;
    bindings.entries[0].tag = PROTO_TYPE_NUM;
    bindings.entries[0].param = -1;

    if (protovm_find_specialization(&vm, template_fn, &bindings) != NULL) {
        report_failure(__func__, "Specialization table should be empty initially", NULL);
        proto_function_free(template_fn);
        return;
    }

    ProtoFunction *specialized_fn = proto_function_copy(template_fn);
    if (!specialized_fn) {
        report_failure(__func__, "Failed to clone specialization", NULL);
        proto_function_free(template_fn);
        return;
    }

    if (!protovm_register_specialization(&vm, template_fn, &bindings, specialized_fn, false)) {
        report_failure(__func__, "Failed to register specialization", NULL);
        proto_function_free(specialized_fn);
        proto_function_free(template_fn);
        return;
    }

    ProtoFunction *found = protovm_find_specialization(&vm, template_fn, &bindings);
    if (found != specialized_fn) {
        report_failure(__func__, "Lookup should return registered specialization", NULL);
        protovm_clear_specializations(&vm, false);
        proto_function_free(specialized_fn);
        proto_function_free(template_fn);
        return;
    }

    ProtoFunction *updated_fn = proto_function_copy(template_fn);
    if (!updated_fn) {
        report_failure(__func__, "Failed to clone updated specialization", NULL);
        protovm_clear_specializations(&vm, false);
        proto_function_free(specialized_fn);
        proto_function_free(template_fn);
        return;
    }

    if (!protovm_register_specialization(&vm, template_fn, &bindings, updated_fn, false)) {
        report_failure(__func__, "Failed to update existing specialization", NULL);
        proto_function_free(updated_fn);
        protovm_clear_specializations(&vm, false);
        proto_function_free(specialized_fn);
        proto_function_free(template_fn);
        return;
    }

    proto_function_free(specialized_fn);

    found = protovm_find_specialization(&vm, template_fn, &bindings);
    if (found != updated_fn) {
        report_failure(__func__, "Lookup should return updated specialization", NULL);
        protovm_clear_specializations(&vm, false);
        proto_function_free(updated_fn);
        proto_function_free(template_fn);
        return;
    }

    ProtoTypeBindingSet other_bindings = {0};
    other_bindings.count = 1;
    other_bindings.entries[0].tag = PROTO_TYPE_TEXT;
    other_bindings.entries[0].param = -1;

    if (protovm_find_specialization(&vm, template_fn, &other_bindings) != NULL) {
        report_failure(__func__, "Lookup with different bindings should miss", NULL);
        protovm_clear_specializations(&vm, false);
        proto_function_free(updated_fn);
        proto_function_free(template_fn);
        return;
    }

    protovm_clear_specializations(&vm, false);
    if (protovm_find_specialization(&vm, template_fn, &bindings) != NULL) {
        report_failure(__func__, "Specialization table should be empty after clear", NULL);
        proto_function_free(updated_fn);
        proto_function_free(template_fn);
        return;
    }

    proto_function_free(updated_fn);
    proto_function_free(template_fn);
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
    RUN_TEST(test_protoerror_json_serialization);
    RUN_TEST(test_compile_and_run_control_flow);
    RUN_TEST(test_use_undefined_global);
    RUN_TEST(test_const_reassignment_fails);
    RUN_TEST(test_pack_and_extract_executable);
    RUN_TEST(test_module_header_metadata);
    RUN_TEST(test_extend_parser_metadata);
    RUN_TEST(test_extend_requires_type_arguments);
    RUN_TEST(test_extend_rejects_type_arguments_for_non_generic_craft);
    RUN_TEST(test_extend_craft_specialization_execution);
    RUN_TEST(test_extend_craft_parameter_type_mismatch);
    RUN_TEST(test_user_function_and_memory);
    RUN_TEST(test_class_methods);
    RUN_TEST(test_this_outside_class_fails);
    RUN_TEST(test_include_directive);
    RUN_TEST(test_suggest_misspelled_native);
    RUN_TEST(test_jit_block_extract);
    RUN_TEST(test_encrypt_file_roundtrip);
    RUN_TEST(test_complex_natives);
    RUN_TEST(test_complex_division_by_zero_errors);
    RUN_TEST(test_hex_encode_decode);
    RUN_TEST(test_rand_bytes);
    RUN_TEST(test_generic_specialization_concrete_binding);
    RUN_TEST(test_generic_specialization_symbolic_binding);
    RUN_TEST(test_generic_binding_map_exports);
    RUN_TEST(test_generic_specialization_unknown_argument);
    RUN_TEST(test_generic_binding_serialization_roundtrip);
    RUN_TEST(test_generic_call_argument_type_mismatch);
    RUN_TEST(test_runtime_specialization_dispatch);
    RUN_TEST(test_runtime_specialization_serialization_roundtrip);
    RUN_TEST(test_vm_specialization_table);
    RUN_TEST(test_native_binding_contract_success);
    RUN_TEST(test_native_binding_contract_failure);
#if PROTOHACK_ENABLE_JIT
    RUN_TEST(test_jit_typed_memory_block);
    RUN_TEST(test_jit_bailout_counters);
#endif

    if (tests_failed > 0) {
        fprintf(stderr, "%d/%d tests failed.\n", tests_failed, tests_run);
        return 1;
    }

    printf("All %d tests passed.\n", tests_run);
    return 0;
}
