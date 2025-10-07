#ifndef PROTOHACK_VALUE_H
#define PROTOHACK_VALUE_H

#include <stdbool.h>
#include <stddef.h>

#include "protohack/types.h"
#include "protohack/typed_memory.h"

struct ProtoFunction;
typedef struct ProtoFunction ProtoFunction;

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PROTO_VAL_NULL = 0,
    PROTO_VAL_NUMBER,
    PROTO_VAL_BOOL,
    PROTO_VAL_STRING,
    PROTO_VAL_FUNCTION,
    PROTO_VAL_MEMORY
} ProtoValueType;

typedef struct {
    ProtoValueType type;
    union {
        double number;
        bool boolean;
        char *string;
    ProtoFunction *function;
        ProtoTypedMemory memory;
    } as;
} ProtoValue;

ProtoValue proto_value_null(void);
ProtoValue proto_value_number(double value);
ProtoValue proto_value_bool(bool value);
ProtoValue proto_value_string(const char *data, size_t length);
ProtoValue proto_value_function(ProtoFunction *function);
ProtoValue proto_value_memory(ProtoTypedMemory memory);
ProtoValue proto_value_copy(const ProtoValue *value);
void proto_value_free(ProtoValue *value);
bool proto_value_equal(const ProtoValue *a, const ProtoValue *b);
void proto_value_print(const ProtoValue *value);
char *proto_value_to_cstring(const ProtoValue *value);

#ifdef __cplusplus
}
#endif

#endif
