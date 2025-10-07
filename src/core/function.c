#include "protohack/function.h"

#include <stdlib.h>
#include <string.h>

#include "protohack/error.h"
#include "protohack/internal/common.h"
#include "protohack/serialize.h"

ProtoFunction *proto_function_new(ProtoFunctionKind kind, const char *name) {
    ProtoFunction *function = (ProtoFunction *)calloc(1, sizeof(ProtoFunction));
    if (!function) {
        PROTOHACK_FATAL("Failed to allocate ProtoFunction");
    }
    function->kind = kind;
    function->arity = 0;
    function->return_type = PROTO_TYPE_NONE;
    function->name = name ? protohack_copy_string(name, strlen(name)) : NULL;
    protochunk_init(&function->chunk);
    return function;
}

void proto_function_free(ProtoFunction *function) {
    if (!function) {
        return;
    }
    free(function->name);
    function->name = NULL;
    protochunk_free(&function->chunk);
    free(function);
}

ProtoFunction *proto_function_copy(const ProtoFunction *function) {
    if (!function) {
        return NULL;
    }
    ProtoFunction *copy = proto_function_new(function->kind, function->name);
    copy->arity = function->arity;
    copy->return_type = function->return_type;
    memcpy(copy->param_types, function->param_types, sizeof(function->param_types));

    // Deep copy the chunk by serializing and deserializing
    ProtoError error;
    protoerror_reset(&error);
    ProtoSerializedBuffer buffer = {0};
    if (!protochunk_serialize_to_buffer(&function->chunk, &buffer, &error)) {
        PROTOHACK_FATAL("Failed to clone function chunk");
    }
    if (!protochunk_deserialize_from_memory(&copy->chunk, buffer.data, buffer.size, &error)) {
        protochunk_buffer_free(&buffer);
        PROTOHACK_FATAL("Failed to deserialize cloned function chunk");
    }
    protochunk_buffer_free(&buffer);
    return copy;
}
