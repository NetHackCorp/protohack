#include "protohack/error.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    const ProtoError *error;
    ProtoDiagnosticCode code;
    char message_key[64];
    char hint[256];
} ProtoErrorMetadata;

#define PROTO_ERROR_META_CAPACITY 16

static ProtoErrorMetadata g_protoerror_meta[PROTO_ERROR_META_CAPACITY];

static ProtoErrorMetadata *protoerror_find_metadata(const ProtoError *error) {
    if (!error) {
        return NULL;
    }
    for (size_t i = 0; i < PROTO_ERROR_META_CAPACITY; ++i) {
        if (g_protoerror_meta[i].error == error) {
            return &g_protoerror_meta[i];
        }
    }
    return NULL;
}

static ProtoErrorMetadata *protoerror_get_metadata(const ProtoError *error, bool create) {
    ProtoErrorMetadata *meta = protoerror_find_metadata(error);
    if (meta || !create || !error) {
        return meta;
    }

    for (size_t i = 0; i < PROTO_ERROR_META_CAPACITY; ++i) {
        if (g_protoerror_meta[i].error == NULL) {
            g_protoerror_meta[i].error = error;
            g_protoerror_meta[i].code = PROTO_DIAG_NONE;
            g_protoerror_meta[i].message_key[0] = '\0';
            g_protoerror_meta[i].hint[0] = '\0';
            return &g_protoerror_meta[i];
        }
    }

    /* Fallback: overwrite the oldest slot (index 0) when capacity is exceeded. */
    g_protoerror_meta[0].error = error;
    g_protoerror_meta[0].code = PROTO_DIAG_NONE;
    g_protoerror_meta[0].message_key[0] = '\0';
    g_protoerror_meta[0].hint[0] = '\0';
    return &g_protoerror_meta[0];
}

static void protoerror_clear_metadata(const ProtoError *error) {
    if (!error) {
        return;
    }
    ProtoErrorMetadata *meta = protoerror_find_metadata(error);
    if (meta) {
        meta->error = NULL;
        meta->code = PROTO_DIAG_NONE;
        meta->message_key[0] = '\0';
        meta->hint[0] = '\0';
    }
}

static void protoerror_set_metadata_code(ProtoError *error, ProtoDiagnosticCode code) {
    ProtoErrorMetadata *meta = protoerror_get_metadata(error, true);
    if (!meta) {
        return;
    }
    meta->code = code;
    meta->message_key[0] = '\0';
    meta->hint[0] = '\0';
}

void protoerror_reset(ProtoError *error) {
    if (!error) {
        return;
    }
    protoerror_clear_metadata(error);
    error->ok = true;
    error->line = 0;
    error->column = 0;
    error->message[0] = '\0';
}

static void protoerror_format_message(ProtoError *error, ProtoDiagnosticCode code, size_t line, size_t column, const char *format, va_list args) {
    if (!error) {
        return;
    }
    error->ok = false;
    error->line = line;
    error->column = column;

#if defined(_MSC_VER)
    vsnprintf_s(error->message, sizeof error->message, _TRUNCATE, format, args);
#else
    vsnprintf(error->message, sizeof error->message, format, args);
#endif

    protoerror_set_metadata_code(error, code);
}

void protoerror_set_with_column(ProtoError *error, size_t line, size_t column, const char *format, ...) {
    if (!error) {
        return;
    }

    va_list args;
    va_start(args, format);
    protoerror_format_message(error, PROTO_DIAG_GENERAL_FAILURE, line, column, format, args);
    va_end(args);
}

void protoerror_set(ProtoError *error, size_t line, const char *format, ...) {
    if (!error) {
        return;
    }

    va_list args;
    va_start(args, format);
    protoerror_format_message(error, PROTO_DIAG_GENERAL_FAILURE, line, 0, format, args);
    va_end(args);
}

void protoerror_set_code_with_column(ProtoError *error, ProtoDiagnosticCode code, size_t line, size_t column, const char *format, ...) {
    if (!error) {
        return;
    }

    va_list args;
    va_start(args, format);
    protoerror_format_message(error, code, line, column, format, args);
    va_end(args);
}

void protoerror_set_code(ProtoError *error, ProtoDiagnosticCode code, size_t line, const char *format, ...) {
    if (!error) {
        return;
    }

    va_list args;
    va_start(args, format);
    protoerror_format_message(error, code, line, 0, format, args);
    va_end(args);
}

void protoerror_set_message_key(ProtoError *error, const char *message_key) {
    ProtoErrorMetadata *meta = protoerror_get_metadata(error, false);
    if (!meta) {
        return;
    }

    if (!message_key) {
        meta->message_key[0] = '\0';
        return;
    }

#if defined(_MSC_VER)
    strncpy_s(meta->message_key, sizeof meta->message_key, message_key, _TRUNCATE);
#else
    strncpy(meta->message_key, message_key, sizeof meta->message_key - 1);
    meta->message_key[sizeof meta->message_key - 1] = '\0';
#endif
}

void protoerror_set_hint(ProtoError *error, const char *format, ...) {
    ProtoErrorMetadata *meta = protoerror_get_metadata(error, false);
    if (!meta) {
        return;
    }

    if (!format) {
        meta->hint[0] = '\0';
        return;
    }

    va_list args;
    va_start(args, format);
#if defined(_MSC_VER)
    vsnprintf_s(meta->hint, sizeof meta->hint, _TRUNCATE, format, args);
#else
    vsnprintf(meta->hint, sizeof meta->hint, format, args);
#endif
    va_end(args);
}

const char *protoerror_code_string(ProtoDiagnosticCode code) {
    switch (code) {
        case PROTO_DIAG_NONE:
            return "ok";
        case PROTO_DIAG_GENERAL_FAILURE:
            return "general_failure";
        case PROTO_DIAG_NATIVE_ARG_ARITY:
            return "native_argument_arity";
        case PROTO_DIAG_NATIVE_ARG_TYPE:
            return "native_argument_type";
        case PROTO_DIAG_RUNTIME_ALLOCATION:
            return "runtime_allocation_failure";
        case PROTO_DIAG_GENERIC_BINDING_MISMATCH:
            return "generic_binding_mismatch";
        case PROTO_DIAG_GENERIC_BINDING_CONFLICT:
            return "generic_binding_conflict";
        case PROTO_DIAG_INTEROP_SIGNATURE_MISMATCH:
            return "interop_signature_mismatch";
        case PROTO_DIAG_SERIALIZATION_METADATA_MISSING:
            return "serialization_metadata_missing";
        case PROTO_DIAG_VM_DISPATCH_FAILURE:
            return "vm_dispatch_failure";
        default:
            return "unknown";
    }
}

static size_t protoerror_escape_json(const char *input, char *output, size_t output_size) {
    if (!output || output_size == 0) {
        return 0;
    }

    size_t written = 0;
    if (!input) {
        output[0] = '\0';
        return 0;
    }

    for (const unsigned char *cursor = (const unsigned char *)input; *cursor != '\0'; ++cursor) {
        const char *escape = NULL;
        char buffer[7] = {0};
        switch (*cursor) {
            case '\\': escape = "\\\\"; break;
            case '"': escape = "\\\""; break;
            case '\b': escape = "\\b"; break;
            case '\f': escape = "\\f"; break;
            case '\n': escape = "\\n"; break;
            case '\r': escape = "\\r"; break;
            case '\t': escape = "\\t"; break;
            default:
                if (*cursor < 0x20) {
                    snprintf(buffer, sizeof buffer, "\\u%04x", (unsigned int)*cursor);
                    escape = buffer;
                }
                break;
        }

        const char *chunk = escape ? escape : (const char *)cursor;
        size_t chunk_len = escape ? strlen(escape) : 1;
        if (written + chunk_len >= output_size) {
            break;
        }
        memcpy(output + written, chunk, chunk_len);
        written += chunk_len;
    }

    if (written < output_size) {
        output[written] = '\0';
    } else {
        output[output_size - 1] = '\0';
    }

    return written;
}

void protoerror_to_json(const ProtoError *error, char *out, size_t out_size) {
    if (!out || out_size == 0) {
        return;
    }

    if (!error) {
        snprintf(out, out_size, "{\"ok\":true}");
        return;
    }

    ProtoErrorMetadata *meta = protoerror_find_metadata(error);
    ProtoDiagnosticCode code = meta ? meta->code : PROTO_DIAG_NONE;

    char message_buffer[512];
    char key_buffer[160];
    char hint_buffer[512];
    char code_buffer[64];

    protoerror_escape_json(error->message, message_buffer, sizeof message_buffer);
    protoerror_escape_json(meta ? meta->message_key : NULL, key_buffer, sizeof key_buffer);
    protoerror_escape_json(meta ? meta->hint : NULL, hint_buffer, sizeof hint_buffer);
    protoerror_escape_json(protoerror_code_string(code), code_buffer, sizeof code_buffer);

    snprintf(out, out_size,
             "{\"ok\":%s,\"code\":%d,\"codeText\":\"%s\",\"message\":\"%s\",\"line\":%zu,\"column\":%zu,"
             "\"messageKey\":\"%s\",\"hint\":\"%s\"}",
             error->ok ? "true" : "false",
             (int)code,
             code_buffer,
             message_buffer,
             error->line,
             error->column,
             key_buffer,
             hint_buffer);
}

ProtoDiagnosticCode protoerror_get_code(const ProtoError *error) {
    ProtoErrorMetadata *meta = protoerror_find_metadata(error);
    return meta ? meta->code : PROTO_DIAG_NONE;
}

const char *protoerror_get_message_key(const ProtoError *error) {
    ProtoErrorMetadata *meta = protoerror_find_metadata(error);
    return meta ? meta->message_key : NULL;
}

const char *protoerror_get_hint(const ProtoError *error) {
    ProtoErrorMetadata *meta = protoerror_find_metadata(error);
    return meta ? meta->hint : NULL;
}
