#include <stdint.h>
#ifndef PROTOHACK_ERROR_H
#define PROTOHACK_ERROR_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PROTO_DIAG_NONE = 0,
    PROTO_DIAG_GENERAL_FAILURE,
    PROTO_DIAG_NATIVE_ARG_ARITY,
    PROTO_DIAG_NATIVE_ARG_TYPE,
    PROTO_DIAG_RUNTIME_ALLOCATION,
    PROTO_DIAG_GENERIC_BINDING_MISMATCH,
    PROTO_DIAG_GENERIC_BINDING_CONFLICT,
    PROTO_DIAG_INTEROP_SIGNATURE_MISMATCH,
    PROTO_DIAG_SERIALIZATION_METADATA_MISSING,
    PROTO_DIAG_VM_DISPATCH_FAILURE
} ProtoDiagnosticCode;

typedef struct {
    bool ok;
    char message[256];
    size_t line;
    size_t column;
} ProtoError;

void protoerror_reset(ProtoError *error);
void protoerror_set(ProtoError *error, size_t line, const char *format, ...);
void protoerror_set_with_column(ProtoError *error, size_t line, size_t column, const char *format, ...);
void protoerror_set_code(ProtoError *error, ProtoDiagnosticCode code, size_t line, const char *format, ...);
void protoerror_set_code_with_column(ProtoError *error, ProtoDiagnosticCode code, size_t line, size_t column, const char *format, ...);
void protoerror_set_message_key(ProtoError *error, const char *message_key);
void protoerror_set_hint(ProtoError *error, const char *format, ...);
const char *protoerror_code_string(ProtoDiagnosticCode code);
ProtoDiagnosticCode protoerror_get_code(const ProtoError *error);
const char *protoerror_get_message_key(const ProtoError *error);
const char *protoerror_get_hint(const ProtoError *error);
void protoerror_to_json(const ProtoError *error, char *out, size_t out_size);

#ifdef __cplusplus
}
#endif

#endif
