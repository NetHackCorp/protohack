#ifndef PROTOHACK_FUNCTION_H
#define PROTOHACK_FUNCTION_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "protohack/binding.h"
#include "protohack/chunk.h"
#include "protohack/types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PROTOHACK_MAX_PARAMS 16

typedef enum {
    PROTO_FUNC_SCRIPT = 0,
    PROTO_FUNC_CRAFT,
    PROTO_FUNC_METHOD,
    PROTO_FUNC_INITIALIZER
} ProtoFunctionKind;

typedef struct ProtoFunction {
    ProtoFunctionKind kind;
    uint8_t arity;
    ProtoTypeTag return_type;
    ProtoTypeTag param_types[PROTOHACK_MAX_PARAMS];
    int8_t param_type_params[PROTOHACK_MAX_PARAMS];
    uint8_t type_param_count;
    char *type_params[PROTOHACK_MAX_TYPE_PARAMS];
    uint8_t type_argument_count;
    ProtoTypeTag type_arguments[PROTOHACK_MAX_TYPE_PARAMS];
    int8_t return_type_param;
    ProtoTypeBindingSet bindings;
    const struct ProtoFunction *template_origin;
    char *name;
    ProtoChunk chunk;
} ProtoFunction;

ProtoFunction *proto_function_new(ProtoFunctionKind kind, const char *name);
void proto_function_free(ProtoFunction *function);
ProtoFunction *proto_function_copy(const ProtoFunction *function);
bool proto_function_set_type_params(ProtoFunction *function, const char *const *params, uint8_t count);
bool proto_function_set_type_arguments(ProtoFunction *function, const ProtoTypeTag *arguments, uint8_t count);
bool proto_function_set_name(ProtoFunction *function, const char *name);
uint8_t proto_function_type_param_count(const ProtoFunction *function);
const char *proto_function_type_param_name(const ProtoFunction *function, uint8_t index);
uint8_t proto_function_type_argument_count(const ProtoFunction *function);
ProtoTypeTag proto_function_type_argument(const ProtoFunction *function, uint8_t index);
int8_t proto_function_param_type_binding(const ProtoFunction *function, uint8_t index);
int8_t proto_function_return_type_binding(const ProtoFunction *function);
char *proto_function_debug_description(const ProtoFunction *function);
bool proto_function_format_specialization_name(const char *base_name,
                                               const ProtoFunction *template_function,
                                               const ProtoTypeBindingSet *bindings,
                                               const char *const *labels,
                                               uint8_t label_count,
                                               char *buffer,
                                               size_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif
