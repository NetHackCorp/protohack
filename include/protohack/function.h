#ifndef PROTOHACK_FUNCTION_H
#define PROTOHACK_FUNCTION_H

#include <stdbool.h>
#include <stdint.h>

#include "protohack/chunk.h"
#include "protohack/types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PROTOHACK_MAX_PARAMS 16

typedef enum {
    PROTO_FUNC_SCRIPT = 0,
    PROTO_FUNC_CRAFT
} ProtoFunctionKind;

typedef struct ProtoFunction {
    ProtoFunctionKind kind;
    uint8_t arity;
    ProtoTypeTag return_type;
    ProtoTypeTag param_types[PROTOHACK_MAX_PARAMS];
    char *name;
    ProtoChunk chunk;
} ProtoFunction;

ProtoFunction *proto_function_new(ProtoFunctionKind kind, const char *name);
void proto_function_free(ProtoFunction *function);
ProtoFunction *proto_function_copy(const ProtoFunction *function);

#ifdef __cplusplus
}
#endif

#endif
