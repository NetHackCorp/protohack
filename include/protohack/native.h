#ifndef PROTOHACK_NATIVE_H
#define PROTOHACK_NATIVE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "protohack/config.h"
#include "protohack/error.h"
#include "protohack/value.h"
#include "protohack/binding.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ProtoVM;
typedef struct ProtoVM ProtoVM;

typedef bool (*ProtoNativeFn)(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error);

typedef struct {
    ProtoTypeTag return_type;
    uint8_t param_count;
    ProtoTypeTag param_types[PROTOHACK_MAX_NATIVE_ARGS];
    ProtoTypeBindingSet binding_contract;
} ProtoNativeSignature;

#define PROTO_NATIVE_SIGNATURE_SIMPLE(RETURN_TAG, PARAM_COUNT) \
    ((ProtoNativeSignature){ \
        .return_type = (RETURN_TAG), \
        .param_count = (PARAM_COUNT), \
        .binding_contract = PROTO_BINDING_SET_EMPTY() \
    })

#define PROTO_NATIVE_SIGNATURE_WITH_BINDINGS(RETURN_TAG, PARAM_COUNT, BINDING_SET) \
    ((ProtoNativeSignature){ \
        .return_type = (RETURN_TAG), \
        .param_count = (PARAM_COUNT), \
        .binding_contract = (BINDING_SET) \
    })

typedef struct {
    const char *name;
    ProtoNativeFn function;
    uint8_t min_arity;
    uint8_t max_arity;
    ProtoNativeSignature signature;
} ProtoNativeEntry;

const ProtoNativeEntry *protonative_resolve(const char *name);
int protonative_index(const char *name);
const ProtoNativeEntry *protonative_table(void);
size_t protonative_count(void);

#ifdef __cplusplus
}
#endif

#endif
