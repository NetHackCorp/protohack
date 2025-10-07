#ifndef PROTOHACK_VM_H
#define PROTOHACK_VM_H

#include <stddef.h>
#include <stdint.h>

#include "protohack/config.h"
#include "protohack/value.h"
#include "protohack/native.h"
#include "protohack/chunk.h"
#include "protohack/function.h"
#include "protohack/error.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ProtoCallFrame {
    const ProtoFunction *function;
    size_t ip;
    ProtoValue *slots;
} ProtoCallFrame;

typedef struct ProtoVM {
    ProtoValue stack[PROTOHACK_STACK_MAX];
    ProtoValue *stack_top;

    ProtoCallFrame frames[PROTOHACK_MAX_CALL_STACK];
    int frame_count;

    ProtoValue globals[PROTOHACK_MAX_GLOBALS];
    bool globals_initialized[PROTOHACK_MAX_GLOBALS];
    size_t globals_count;

    ProtoValue last_print_value;

    uint32_t rand_state;
} ProtoVM;

void protovm_init(ProtoVM *vm);
void protovm_reset(ProtoVM *vm);
bool protovm_run(ProtoVM *vm, const ProtoChunk *chunk, ProtoError *error);
const ProtoValue *protovm_last_print(const ProtoVM *vm);
void protovm_register_stdlib(ProtoVM *vm);

#ifdef __cplusplus
}
#endif

#endif
