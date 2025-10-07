#ifndef PROTOHACK_NATIVE_H
#define PROTOHACK_NATIVE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "protohack/config.h"
#include "protohack/error.h"
#include "protohack/value.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ProtoVM;
typedef struct ProtoVM ProtoVM;

typedef bool (*ProtoNativeFn)(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error);

typedef struct {
    const char *name;
    ProtoNativeFn function;
    uint8_t min_arity;
    uint8_t max_arity;
} ProtoNativeEntry;

const ProtoNativeEntry *protonative_resolve(const char *name);
int protonative_index(const char *name);
const ProtoNativeEntry *protonative_table(void);
size_t protonative_count(void);

#ifdef __cplusplus
}
#endif

#endif
