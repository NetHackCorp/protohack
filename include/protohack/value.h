#ifndef PROTOHACK_VALUE_H
#define PROTOHACK_VALUE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "protohack/types.h"
#include "protohack/typed_memory.h"
#include "protohack/object.h"

struct ProtoFunction;
typedef struct ProtoFunction ProtoFunction;

#ifdef __cplusplus
extern "C" {
#endif

struct ProtoValue;

typedef enum {
    PROTO_POINTER_STACK,
    PROTO_POINTER_GLOBAL
} ProtoPointerKind;

typedef struct {
    ProtoPointerKind kind;
    bool is_const;
    union {
        struct {
            struct ProtoValue *slot;
            uint32_t generation;
        } stack;
        struct {
            struct ProtoValue *slot;
            bool *initialized;
            uint16_t index;
        } global;
    } as;
} ProtoPointer;

typedef enum {
    PROTO_VAL_NULL = 0,
    PROTO_VAL_NUMBER,
    PROTO_VAL_BOOL,
    PROTO_VAL_STRING,
    PROTO_VAL_FUNCTION,
    PROTO_VAL_CLASS,
    PROTO_VAL_INSTANCE,
    PROTO_VAL_BOUND_METHOD,
    PROTO_VAL_MEMORY,
    PROTO_VAL_POINTER
} ProtoValueType;

typedef struct ProtoValue {
    ProtoValueType type;
    union {
        double number;
        bool boolean;
        char *string;
        ProtoFunction *function;
        ProtoClass *klass;
        ProtoInstance *instance;
        ProtoBoundMethod *bound_method;
        ProtoTypedMemory memory;
        ProtoPointer pointer;
    } as;
} ProtoValue;

ProtoValue proto_value_null(void);
ProtoValue proto_value_number(double value);
ProtoValue proto_value_bool(bool value);
ProtoValue proto_value_string(const char *data, size_t length);
ProtoValue proto_value_function(ProtoFunction *function);
ProtoValue proto_value_class(ProtoClass *klass);
ProtoValue proto_value_instance(ProtoInstance *instance);
ProtoValue proto_value_bound_method(ProtoBoundMethod *bound);
ProtoValue proto_value_memory(ProtoTypedMemory memory);
ProtoValue proto_value_pointer(ProtoPointer pointer);
ProtoValue proto_value_copy(const ProtoValue *value);
void proto_value_free(ProtoValue *value);
bool proto_value_equal(const ProtoValue *a, const ProtoValue *b);
void proto_value_print(const ProtoValue *value);
char *proto_value_to_cstring(const ProtoValue *value);

#ifdef __cplusplus
}
#endif

#endif
