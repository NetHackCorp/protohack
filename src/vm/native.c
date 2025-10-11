#ifndef _WIN32
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L
#endif
#endif

#include "protohack/native.h"

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include "protohack/error.h"
#include "protohack/internal/common.h"
#include "protohack/stdlib/complex_math.h"
#include "protohack/stdlib/file_crypto.h"
#include "protohack/stdlib/network.h"
#include "protohack/typed_memory.h"
#include "protohack/value.h"
#include "protohack/vm.h"

static uint32_t rand_next(uint32_t state) {
    return state * 1664525u + 1013904223u;
}

static int hex_digit_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    }
    return -1;
}

static bool expect_number_arg(const ProtoValue *value, const char *function_name, size_t index, ProtoError *error, double *out) {
    if (value->type != PROTO_VAL_NUMBER) {
        if (error && error->ok) {
            protoerror_set_code(error, PROTO_DIAG_NATIVE_ARG_TYPE, 0, "%s expects argument %zu to be a number", function_name, index);
            protoerror_set_message_key(error, "native.arg_type.number");
            protoerror_set_hint(error, "Convert argument %zu to a numeric type before calling %s.", index, function_name);
        }
        return false;
    }
    *out = value->as.number;
    return true;
}

static bool expect_string_arg(const ProtoValue *value, const char *function_name, size_t index, ProtoError *error, const char **out) {
    if (value->type != PROTO_VAL_STRING) {
        if (error && error->ok) {
            protoerror_set_code(error, PROTO_DIAG_NATIVE_ARG_TYPE, 0, "%s expects argument %zu to be a string", function_name, index);
            protoerror_set_message_key(error, "native.arg_type.string");
            protoerror_set_hint(error, "Ensure argument %zu resolves to text before calling %s.", index, function_name);
        }
        return false;
    }
    *out = value->as.string ? value->as.string : "";
    return true;
}

static bool complex_from_args(const ProtoValue *args, size_t start_index, const char *function_name, ProtoError *error, ProtoStdComplex *out) {
    double real = 0.0;
    double imag = 0.0;
    if (!expect_number_arg(&args[start_index], function_name, start_index + 1, error, &real)) {
        return false;
    }
    if (!expect_number_arg(&args[start_index + 1], function_name, start_index + 2, error, &imag)) {
        return false;
    }
    out->real = real;
    out->imag = imag;
    return true;
}

static ProtoValue complex_to_value(ProtoStdComplex complex_value) {
    ProtoTypedMemory memory = proto_memory_allocate(PROTO_TYPE_NUM, 2);
    if (memory.count >= 2 && memory.data) {
        double *data = (double *)memory.data;
        data[0] = complex_value.real;
        data[1] = complex_value.imag;
    }
    return proto_value_memory(memory);
}

static bool native_sleep(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    if (arg_count != 1 || args[0].type != PROTO_VAL_NUMBER) {
        if (error && error->ok) {
            protoerror_set_code(error, PROTO_DIAG_NATIVE_ARG_ARITY, 0, "sleep expects a single numeric duration in milliseconds");
            protoerror_set_message_key(error, "native.sleep.arity");
            protoerror_set_hint(error, "Call sleep(duration_ms) with exactly one numeric argument.");
        }
        return false;
    }

    double milliseconds = args[0].as.number;
    if (!isfinite(milliseconds) || milliseconds < 0.0) {
        if (error && error->ok) {
            protoerror_set_code(error, PROTO_DIAG_NATIVE_ARG_TYPE, 0, "sleep expects a non-negative finite duration");
            protoerror_set_message_key(error, "native.sleep.range");
            protoerror_set_hint(error, "Clamp or validate the duration before invoking sleep.");
        }
        return false;
    }

#ifdef _WIN32
    DWORD duration = 0u;
    if (milliseconds > 0.0) {
        double rounded = floor(milliseconds + 0.5);
        if (rounded > (double)UINT32_MAX) {
            rounded = (double)UINT32_MAX;
        }
        duration = (DWORD)rounded;
    }
    Sleep(duration);
#else
    double seconds = milliseconds / 1000.0;
    if (seconds < 0.0) {
        seconds = 0.0;
    }
    struct timespec requested;
    requested.tv_sec = (time_t)seconds;
    double fractional = seconds - (double)requested.tv_sec;
    if (fractional < 0.0) {
        fractional = 0.0;
    }
    long nanos = (long)(fractional * 1000000000.0);
    if (nanos > 999999999L) {
        requested.tv_sec += nanos / 1000000000L;
        nanos %= 1000000000L;
    }
    requested.tv_nsec = nanos;

    struct timespec remaining;
    while (nanosleep(&requested, &remaining) == -1 && errno == EINTR) {
        requested = remaining;
    }
#endif

    *result = proto_value_null();
    return true;
}

static bool native_hex_encode(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    if (arg_count != 1) {
        if (error && error->ok) {
            protoerror_set_code(error, PROTO_DIAG_NATIVE_ARG_ARITY, 0, "hex_encode expects one argument");
            protoerror_set_message_key(error, "native.hex_encode.arity");
            protoerror_set_hint(error, "Invoke hex_encode(value) with a single raw/text buffer or string.");
        }
        return false;
    }

    const uint8_t *data = NULL;
    size_t length = 0;
    char *owned_text = NULL;

    if (args[0].type == PROTO_VAL_STRING) {
        data = (const uint8_t *)args[0].as.string;
        length = args[0].as.string ? strlen(args[0].as.string) : 0;
    } else if (args[0].type == PROTO_VAL_MEMORY) {
        const ProtoTypedMemory *memory = &args[0].as.memory;
        if (memory->count > 0 && !memory->data) {
            if (error && error->ok) {
                protoerror_set_code(error, PROTO_DIAG_NATIVE_ARG_TYPE, 0, "hex_encode received invalid memory block");
                protoerror_set_message_key(error, "native.hex_encode.memory_invalid");
                protoerror_set_hint(error, "Ensure the memory block passed to hex_encode is initialized.");
            }
            return false;
        }
        switch (memory->element_type) {
            case PROTO_TYPE_RAW:
            case PROTO_TYPE_TEXT:
                data = (const uint8_t *)memory->data;
                length = memory->count;
                break;
            default:
                if (error && error->ok) {
                    protoerror_set_code(error, PROTO_DIAG_NATIVE_ARG_TYPE, 0, "hex_encode expects raw or text memory");
                    protoerror_set_message_key(error, "native.hex_encode.memory_type");
                    protoerror_set_hint(error, "Pass a raw/text typed memory region to hex_encode.");
                }
                return false;
        }
    } else {
        owned_text = proto_value_to_cstring(&args[0]);
        data = (const uint8_t *)owned_text;
        length = owned_text ? strlen(owned_text) : 0;
    }

    if (length == 0) {
        *result = proto_value_string("", 0);
        free(owned_text);
        return true;
    }

    char *buffer = (char *)malloc(length * 2 + 1);
    if (!buffer) {
        if (error && error->ok) {
            protoerror_set_code(error, PROTO_DIAG_RUNTIME_ALLOCATION, 0, "hex_encode failed to allocate output");
            protoerror_set_message_key(error, "native.hex_encode.alloc");
            protoerror_set_hint(error, "Reduce input size or free memory before calling hex_encode.");
        }
        free(owned_text);
        return false;
    }

    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; ++i) {
        uint8_t byte = data ? data[i] : 0u;
        buffer[2 * i] = digits[(byte >> 4) & 0x0F];
        buffer[2 * i + 1] = digits[byte & 0x0F];
    }
    buffer[length * 2] = '\0';

    *result = proto_value_string(buffer, length * 2);
    free(buffer);
    free(owned_text);
    return true;
}

static bool native_hex_decode(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    if (arg_count != 1 || args[0].type != PROTO_VAL_STRING) {
        if (error && error->ok) {
            protoerror_set_code(error, PROTO_DIAG_NATIVE_ARG_TYPE, 0, "hex_decode expects a single hex string argument");
            protoerror_set_message_key(error, "native.hex_decode.arg_type");
            protoerror_set_hint(error, "Call hex_decode(text) with exactly one string argument containing hex characters.");
        }
        return false;
    }

    const char *text = args[0].as.string ? args[0].as.string : "";
    size_t length = strlen(text);

    if (length % 2 != 0) {
        if (error && error->ok) {
            protoerror_set_code(error, PROTO_DIAG_NATIVE_ARG_TYPE, 0, "hex_decode expects an even-length string");
            protoerror_set_message_key(error, "native.hex_decode.length");
            protoerror_set_hint(error, "Pad the hex string to an even length before decoding.");
        }
        return false;
    }

    ProtoTypedMemory memory = proto_memory_allocate(PROTO_TYPE_RAW, length / 2);
    uint8_t *out = memory.count > 0 ? (uint8_t *)memory.data : NULL;

    for (size_t i = 0; i < memory.count; ++i) {
        int hi = hex_digit_value(text[2 * i]);
        int lo = hex_digit_value(text[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            proto_memory_free(&memory);
            if (error && error->ok) {
                protoerror_set_code(error, PROTO_DIAG_NATIVE_ARG_TYPE, 0, "hex_decode encountered non-hex characters");
                protoerror_set_message_key(error, "native.hex_decode.invalid_char");
                protoerror_set_hint(error, "Remove characters outside [0-9a-fA-F] before decoding.");
            }
            return false;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }

    *result = proto_value_memory(memory);
    return true;
}

static bool native_rand_bytes(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    if (arg_count != 1 || args[0].type != PROTO_VAL_NUMBER) {
        if (error && error->ok) {
            protoerror_set_code(error, PROTO_DIAG_NATIVE_ARG_ARITY, 0, "rand_bytes expects a single numeric argument");
            protoerror_set_message_key(error, "native.rand_bytes.arity");
            protoerror_set_hint(error, "Call rand_bytes(length) with exactly one numeric length argument.");
        }
        return false;
    }

    double requested = args[0].as.number;
    if (!isfinite(requested) || requested < 0.0) {
        if (error && error->ok) {
            protoerror_set_code(error, PROTO_DIAG_NATIVE_ARG_TYPE, 0, "rand_bytes expects a non-negative finite length");
            protoerror_set_message_key(error, "native.rand_bytes.range");
            protoerror_set_hint(error, "Clamp the requested length to a non-negative finite number.");
        }
        return false;
    }

    if (requested > (double)SIZE_MAX) {
        if (error && error->ok) {
            protoerror_set_code(error, PROTO_DIAG_NATIVE_ARG_TYPE, 0, "rand_bytes argument is too large");
            protoerror_set_message_key(error, "native.rand_bytes.limit");
            protoerror_set_hint(error, "Request fewer bytes or stream the random data in chunks.");
        }
        return false;
    }

    size_t count = (size_t)requested;
    if (fabs(requested - (double)count) > 1e-9) {
        if (error && error->ok) {
            protoerror_set_code(error, PROTO_DIAG_NATIVE_ARG_TYPE, 0, "rand_bytes expects an integer length");
            protoerror_set_message_key(error, "native.rand_bytes.integer");
            protoerror_set_hint(error, "Round the requested length to an integer before calling rand_bytes.");
        }
        return false;
    }

    const size_t kRandBytesLimit = 1024u * 1024u;
    if (count > kRandBytesLimit) {
        if (error && error->ok) {
            protoerror_set_code(error, PROTO_DIAG_NATIVE_ARG_TYPE, 0, "rand_bytes limit exceeded (max 1048576)");
            protoerror_set_message_key(error, "native.rand_bytes.limit_max");
            protoerror_set_hint(error, "Split the request into chunks of at most 1048576 bytes.");
        }
        return false;
    }

    ProtoTypedMemory memory = proto_memory_allocate(PROTO_TYPE_RAW, count);
    uint8_t *data = count > 0 ? (uint8_t *)memory.data : NULL;
    for (size_t i = 0; i < count; ++i) {
        vm->rand_state = rand_next(vm->rand_state);
        data[i] = (uint8_t)(vm->rand_state & 0xFFu);
    }

    *result = proto_value_memory(memory);
    return true;
}

static bool native_clock(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    (void)args;
    (void)arg_count;
    (void)error;
    double seconds = (double)clock() / (double)CLOCKS_PER_SEC;
    *result = proto_value_number(seconds);
    return true;
}

static bool native_rand(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)error;
    vm->rand_state = rand_next(vm->rand_state);
    double rnd = (double)vm->rand_state / 4294967295.0;
    if (arg_count == 1) {
        if (args[0].type != PROTO_VAL_NUMBER) {
            return false;
        }
        double max = args[0].as.number;
        rnd = floor(rnd * max);
    }
    *result = proto_value_number(rnd);
    return true;
}

static bool native_sqrt(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    (void)arg_count;
    if (args[0].type != PROTO_VAL_NUMBER) {
        if (error && error->ok) {
            protoerror_set(error, 0, "sqrt expects a number");
        }
        return false;
    }
    if (args[0].as.number < 0.0) {
        if (error && error->ok) {
            protoerror_set(error, 0, "sqrt domain error");
        }
        return false;
    }
    *result = proto_value_number(sqrt(args[0].as.number));
    return true;
}

static bool native_pow(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    (void)arg_count;
    if (args[0].type != PROTO_VAL_NUMBER || args[1].type != PROTO_VAL_NUMBER) {
        if (error && error->ok) {
            protoerror_set(error, 0, "pow expects two numbers");
        }
        return false;
    }
    *result = proto_value_number(pow(args[0].as.number, args[1].as.number));
    return true;
}

static bool native_len(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    (void)arg_count;
    (void)error;
    size_t length = 0;
    switch (args[0].type) {
        case PROTO_VAL_STRING:
            length = args[0].as.string ? strlen(args[0].as.string) : 0;
            break;
        case PROTO_VAL_NULL:
            length = 0;
            break;
        case PROTO_VAL_BOOL:
            length = args[0].as.boolean ? 1 : 0;
            break;
        case PROTO_VAL_NUMBER: {
            char buffer[64];
            int written = snprintf(buffer, sizeof buffer, "%.10g", args[0].as.number);
            if (written > 0) {
                length = (size_t)written;
            }
            break;
        }
        default:
            length = 0;
            break;
    }
    *result = proto_value_number((double)length);
    return true;
}

static bool native_to_string(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    (void)arg_count;
    (void)error;
    char *text = proto_value_to_cstring(&args[0]);
    size_t length = strlen(text);
    *result = proto_value_string(text, length);
    free(text);
    return true;
}

static bool native_upper(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    (void)arg_count;
    if (args[0].type != PROTO_VAL_STRING || !args[0].as.string) {
        if (error && error->ok) {
            protoerror_set(error, 0, "upper expects a string");
        }
        return false;
    }
    size_t length = strlen(args[0].as.string);
    char *buffer = protohack_copy_string(args[0].as.string, length);
    for (size_t i = 0; i < length; ++i) {
        buffer[i] = (char)toupper((unsigned char)buffer[i]);
    }
    *result = proto_value_string(buffer, length);
    free(buffer);
    return true;
}

static bool native_lower(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    (void)arg_count;
    if (args[0].type != PROTO_VAL_STRING || !args[0].as.string) {
        if (error && error->ok) {
            protoerror_set(error, 0, "lower expects a string");
        }
        return false;
    }
    size_t length = strlen(args[0].as.string);
    char *buffer = protohack_copy_string(args[0].as.string, length);
    for (size_t i = 0; i < length; ++i) {
        buffer[i] = (char)tolower((unsigned char)buffer[i]);
    }
    *result = proto_value_string(buffer, length);
    free(buffer);
    return true;
}

static bool native_println(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    (void)error;
    for (uint8_t i = 0; i < arg_count; ++i) {
        if (i > 0) {
            printf(" ");
        }
        proto_value_print(&args[i]);
    }
    printf("\n");
    *result = proto_value_null();
    return true;
}

static bool native_expect_num_binding(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    (void)args;
    if (arg_count != 0) {
        if (error && error->ok) {
            protoerror_set(error, 0, "expect_num_binding does not take arguments");
        }
        return false;
    }
    *result = proto_value_null();
    return true;
}

static bool native_encrypt_file(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    if (arg_count < 2 || arg_count > 3) {
        if (error && error->ok) {
            protoerror_set(error, 0, "encrypt_file expects two or three string arguments");
        }
        return false;
    }

    const char *input_path = NULL;
    const char *output_path = NULL;
    if (!expect_string_arg(&args[0], "encrypt_file", 1, error, &input_path)) {
        return false;
    }
    if (!expect_string_arg(&args[1], "encrypt_file", 2, error, &output_path)) {
        return false;
    }

    const char *key_override = NULL;
    if (arg_count == 3 && !expect_string_arg(&args[2], "encrypt_file", 3, error, &key_override)) {
        return false;
    }

    ProtoError scratch;
    ProtoError *target_error = error ? error : &scratch;
    protoerror_reset(target_error);

    char *generated_key = NULL;
    if (!proto_stdlib_encrypt_file(input_path, output_path, key_override, &generated_key, target_error)) {
        free(generated_key);
        return false;
    }

    size_t key_length = generated_key ? strlen(generated_key) : 0;
    *result = proto_value_string(generated_key ? generated_key : "", key_length);
    free(generated_key);
    return true;
}

static bool native_decrypt_file(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    if (arg_count != 3) {
        if (error && error->ok) {
            protoerror_set(error, 0, "decrypt_file expects three string arguments");
        }
        return false;
    }

    const char *input_path = NULL;
    const char *output_path = NULL;
    const char *key_hex = NULL;
    if (!expect_string_arg(&args[0], "decrypt_file", 1, error, &input_path)) {
        return false;
    }
    if (!expect_string_arg(&args[1], "decrypt_file", 2, error, &output_path)) {
        return false;
    }
    if (!expect_string_arg(&args[2], "decrypt_file", 3, error, &key_hex)) {
        return false;
    }

    ProtoError scratch;
    ProtoError *target_error = error ? error : &scratch;
    protoerror_reset(target_error);

    if (!proto_stdlib_decrypt_file(input_path, output_path, key_hex, target_error)) {
        return false;
    }

    *result = proto_value_bool(true);
    return true;
}

static bool native_complex_add(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    if (arg_count != 4) {
        if (error && error->ok) {
            protoerror_set(error, 0, "complex_add expects four numeric arguments");
        }
        return false;
    }

    ProtoStdComplex lhs;
    ProtoStdComplex rhs;
    if (!complex_from_args(args, 0, "complex_add", error, &lhs)) {
        return false;
    }
    if (!complex_from_args(args, 2, "complex_add", error, &rhs)) {
        return false;
    }

    ProtoStdComplex sum = proto_stdlib_complex_add(lhs, rhs);
    *result = complex_to_value(sum);
    return true;
}

static bool native_complex_sub(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    if (arg_count != 4) {
        if (error && error->ok) {
            protoerror_set(error, 0, "complex_sub expects four numeric arguments");
        }
        return false;
    }

    ProtoStdComplex lhs;
    ProtoStdComplex rhs;
    if (!complex_from_args(args, 0, "complex_sub", error, &lhs)) {
        return false;
    }
    if (!complex_from_args(args, 2, "complex_sub", error, &rhs)) {
        return false;
    }

    ProtoStdComplex diff = proto_stdlib_complex_sub(lhs, rhs);
    *result = complex_to_value(diff);
    return true;
}

static bool native_complex_mul(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    if (arg_count != 4) {
        if (error && error->ok) {
            protoerror_set(error, 0, "complex_mul expects four numeric arguments");
        }
        return false;
    }

    ProtoStdComplex lhs;
    ProtoStdComplex rhs;
    if (!complex_from_args(args, 0, "complex_mul", error, &lhs)) {
        return false;
    }
    if (!complex_from_args(args, 2, "complex_mul", error, &rhs)) {
        return false;
    }

    ProtoStdComplex product = proto_stdlib_complex_mul(lhs, rhs);
    *result = complex_to_value(product);
    return true;
}

static bool native_complex_div(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    if (arg_count != 4) {
        if (error && error->ok) {
            protoerror_set(error, 0, "complex_div expects four numeric arguments");
        }
        return false;
    }

    ProtoStdComplex lhs;
    ProtoStdComplex rhs;
    if (!complex_from_args(args, 0, "complex_div", error, &lhs)) {
        return false;
    }
    if (!complex_from_args(args, 2, "complex_div", error, &rhs)) {
        return false;
    }

    ProtoError scratch;
    ProtoError *target_error = error ? error : &scratch;
    protoerror_reset(target_error);
    ProtoStdComplex quotient = proto_stdlib_complex_div(lhs, rhs, target_error);
    if (!target_error->ok) {
        return false;
    }

    *result = complex_to_value(quotient);
    return true;
}

static bool native_complex_abs(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    if (arg_count != 2) {
        if (error && error->ok) {
            protoerror_set(error, 0, "complex_abs expects two numeric arguments");
        }
        return false;
    }

    ProtoStdComplex value;
    if (!complex_from_args(args, 0, "complex_abs", error, &value)) {
        return false;
    }

    double magnitude = proto_stdlib_complex_abs(value);
    *result = proto_value_number(magnitude);
    return true;
}

static bool native_complex_exp(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    if (arg_count != 2) {
        if (error && error->ok) {
            protoerror_set(error, 0, "complex_exp expects two numeric arguments");
        }
        return false;
    }

    ProtoStdComplex value;
    if (!complex_from_args(args, 0, "complex_exp", error, &value)) {
        return false;
    }

    ProtoStdComplex exponent = proto_stdlib_complex_exp(value);
    *result = complex_to_value(exponent);
    return true;
}

static bool native_net_ping(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    if (arg_count < 1 || arg_count > 2) {
        if (error && error->ok) {
            protoerror_set(error, 0, "net_ping expects host and optional timeout");
        }
        return false;
    }

    const char *host = NULL;
    if (!expect_string_arg(&args[0], "net_ping", 1, error, &host)) {
        return false;
    }

    uint32_t timeout_ms = 0u;
    if (arg_count == 2) {
        double timeout_value = 0.0;
        if (!expect_number_arg(&args[1], "net_ping", 2, error, &timeout_value)) {
            return false;
        }
        if (!isfinite(timeout_value) || timeout_value < 0.0) {
            if (error && error->ok) {
                protoerror_set(error, 0, "net_ping timeout must be a non-negative finite number");
            }
            return false;
        }
        if (timeout_value > (double)UINT32_MAX) {
            if (error && error->ok) {
                protoerror_set(error, 0, "net_ping timeout exceeds maximum value");
            }
            return false;
        }
        double rounded = floor(timeout_value + 0.5);
        timeout_ms = (uint32_t)rounded;
    }

    ProtoError scratch;
    ProtoError *target_error = error ? error : &scratch;
    protoerror_reset(target_error);
    if (!proto_stdlib_net_ping(host, timeout_ms, target_error)) {
        return false;
    }

    *result = proto_value_bool(true);
    return true;
}

static bool native_net_hostname(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    (void)args;
    if (arg_count != 0) {
        if (error && error->ok) {
            protoerror_set(error, 0, "net_hostname does not take arguments");
        }
        return false;
    }

    char *hostname = proto_stdlib_net_hostname();
    if (!hostname) {
        if (error && error->ok) {
            protoerror_set(error, 0, "net_hostname failed to obtain hostname");
        }
        return false;
    }

    size_t length = strlen(hostname);
    *result = proto_value_string(hostname, length);
    free(hostname);
    return true;
}

static bool native_net_resolve(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    if (arg_count != 1) {
        if (error && error->ok) {
            protoerror_set(error, 0, "net_resolve expects a hostname string");
        }
        return false;
    }

    const char *host = NULL;
    if (!expect_string_arg(&args[0], "net_resolve", 1, error, &host)) {
        return false;
    }

    ProtoError scratch;
    ProtoError *target_error = error ? error : &scratch;
    protoerror_reset(target_error);
    char *address = proto_stdlib_net_resolve(host, target_error);
    if (!address) {
        return false;
    }

    size_t length = strlen(address);
    *result = proto_value_string(address, length);
    free(address);
    return true;
}

static bool native_net_interfaces(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    (void)args;
    if (arg_count != 0) {
        if (error && error->ok) {
            protoerror_set(error, 0, "net_interfaces does not take arguments");
        }
        return false;
    }

    ProtoError scratch;
    ProtoError *target_error = error ? error : &scratch;
    protoerror_reset(target_error);

    ProtoStdNetInterfaces interfaces = proto_stdlib_net_interfaces(target_error);
    if (!target_error->ok) {
        proto_stdlib_net_interfaces_free(&interfaces);
        return false;
    }

    if (interfaces.count == 0 || !interfaces.items) {
        *result = proto_value_string("", 0);
        proto_stdlib_net_interfaces_free(&interfaces);
        return true;
    }

    size_t total_length = 0;
    for (size_t i = 0; i < interfaces.count; ++i) {
        size_t name_length = interfaces.items[i].name ? strlen(interfaces.items[i].name) : 0;
        size_t address_length = interfaces.items[i].address ? strlen(interfaces.items[i].address) : 0;
        total_length += name_length + 1 + address_length;
        if (i + 1 < interfaces.count) {
            total_length += 1; // newline separator
        }
    }

    char *joined = (char *)malloc(total_length + 1);
    if (!joined) {
        proto_stdlib_net_interfaces_free(&interfaces);
        if (error && error->ok) {
            protoerror_set(error, 0, "net_interfaces failed to allocate result buffer");
        }
        return false;
    }

    size_t offset = 0;
    for (size_t i = 0; i < interfaces.count; ++i) {
        const char *name = interfaces.items[i].name ? interfaces.items[i].name : "";
        const char *address = interfaces.items[i].address ? interfaces.items[i].address : "";
        size_t name_length = strlen(name);
        size_t address_length = strlen(address);
        if (name_length > 0) {
            memcpy(joined + offset, name, name_length);
            offset += name_length;
        }
        joined[offset++] = '|';
        if (address_length > 0) {
            memcpy(joined + offset, address, address_length);
            offset += address_length;
        }
        if (i + 1 < interfaces.count) {
            joined[offset++] = '\n';
        }
    }
    joined[offset] = '\0';

    *result = proto_value_string(joined, offset);
    free(joined);
    proto_stdlib_net_interfaces_free(&interfaces);
    return true;
}

static const ProtoNativeEntry kNativeTable[] = {
    {"clock", native_clock, 0, 0, PROTO_NATIVE_SIGNATURE_SIMPLE(PROTO_TYPE_NUM, 0)},
    {"sleep", native_sleep, 1, 1, PROTO_NATIVE_SIGNATURE_SIMPLE(PROTO_TYPE_NONE, 1)},
    {"rand", native_rand, 0, 1, PROTO_NATIVE_SIGNATURE_SIMPLE(PROTO_TYPE_NUM, 1)},
    {"rand_bytes", native_rand_bytes, 1, 1, PROTO_NATIVE_SIGNATURE_SIMPLE(PROTO_TYPE_RAW, 1)},
    {"sqrt", native_sqrt, 1, 1, PROTO_NATIVE_SIGNATURE_SIMPLE(PROTO_TYPE_NUM, 1)},
    {"pow", native_pow, 2, 2, PROTO_NATIVE_SIGNATURE_SIMPLE(PROTO_TYPE_NUM, 2)},
    {"len", native_len, 1, 1, PROTO_NATIVE_SIGNATURE_SIMPLE(PROTO_TYPE_NUM, 1)},
    {"to_string", native_to_string, 1, 1, PROTO_NATIVE_SIGNATURE_SIMPLE(PROTO_TYPE_TEXT, 1)},
    {"upper", native_upper, 1, 1, PROTO_NATIVE_SIGNATURE_SIMPLE(PROTO_TYPE_TEXT, 1)},
    {"lower", native_lower, 1, 1, PROTO_NATIVE_SIGNATURE_SIMPLE(PROTO_TYPE_TEXT, 1)},
    {"hex_encode", native_hex_encode, 1, 1, PROTO_NATIVE_SIGNATURE_SIMPLE(PROTO_TYPE_TEXT, 1)},
    {"hex_decode", native_hex_decode, 1, 1, PROTO_NATIVE_SIGNATURE_SIMPLE(PROTO_TYPE_RAW, 1)},
    {"encrypt_file", native_encrypt_file, 2, 3, PROTO_NATIVE_SIGNATURE_SIMPLE(PROTO_TYPE_TEXT, 3)},
    {"decrypt_file", native_decrypt_file, 3, 3, PROTO_NATIVE_SIGNATURE_SIMPLE(PROTO_TYPE_FLAG, 3)},
    {"complex_add", native_complex_add, 4, 4, PROTO_NATIVE_SIGNATURE_SIMPLE(PROTO_TYPE_RAW, 4)},
    {"complex_sub", native_complex_sub, 4, 4, PROTO_NATIVE_SIGNATURE_SIMPLE(PROTO_TYPE_RAW, 4)},
    {"complex_mul", native_complex_mul, 4, 4, PROTO_NATIVE_SIGNATURE_SIMPLE(PROTO_TYPE_RAW, 4)},
    {"complex_div", native_complex_div, 4, 4, PROTO_NATIVE_SIGNATURE_SIMPLE(PROTO_TYPE_RAW, 4)},
    {"complex_abs", native_complex_abs, 2, 2, PROTO_NATIVE_SIGNATURE_SIMPLE(PROTO_TYPE_NUM, 2)},
    {"complex_exp", native_complex_exp, 2, 2, PROTO_NATIVE_SIGNATURE_SIMPLE(PROTO_TYPE_RAW, 2)},
    {"net_ping", native_net_ping, 1, 2, PROTO_NATIVE_SIGNATURE_SIMPLE(PROTO_TYPE_FLAG, 2)},
    {"net_hostname", native_net_hostname, 0, 0, PROTO_NATIVE_SIGNATURE_SIMPLE(PROTO_TYPE_TEXT, 0)},
    {"net_resolve", native_net_resolve, 1, 1, PROTO_NATIVE_SIGNATURE_SIMPLE(PROTO_TYPE_TEXT, 1)},
    {"net_interfaces", native_net_interfaces, 0, 0, PROTO_NATIVE_SIGNATURE_SIMPLE(PROTO_TYPE_TEXT, 0)},
    {"println", native_println, 0, PROTOHACK_MAX_NATIVE_ARGS, PROTO_NATIVE_SIGNATURE_SIMPLE(PROTO_TYPE_NONE, PROTOHACK_MAX_NATIVE_ARGS)},
    {"expect_num_binding", native_expect_num_binding, 0, 0,
        PROTO_NATIVE_SIGNATURE_WITH_BINDINGS(PROTO_TYPE_NONE, 0, PROTO_BINDING_SET1(PROTO_BINDING_CONCRETE(PROTO_TYPE_NUM)))},
    {NULL, NULL, 0, 0, PROTO_NATIVE_SIGNATURE_SIMPLE(PROTO_TYPE_NONE, 0)}
};

const ProtoNativeEntry *protonative_table(void) {
    return kNativeTable;
}

size_t protonative_count(void) {
    size_t count = 0;
    while (kNativeTable[count].name) {
        ++count;
    }
    return count;
}

const ProtoNativeEntry *protonative_resolve(const char *name) {
    if (!name) {
        return NULL;
    }
    for (size_t i = 0; kNativeTable[i].name; ++i) {
        if (strcmp(kNativeTable[i].name, name) == 0) {
            return &kNativeTable[i];
        }
    }
    return NULL;
}

int protonative_index(const char *name) {
    if (!name) {
        return -1;
    }
    for (size_t i = 0; kNativeTable[i].name; ++i) {
        if (strcmp(kNativeTable[i].name, name) == 0) {
            return (int)i;
        }
    }
    return -1;
}
