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
#include "protohack/jit.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ProtoCallFrame {
    const ProtoFunction *function;
    size_t ip;
    ProtoValue *slots;
    ProtoTypeBindingSet bindings;
} ProtoCallFrame;

typedef struct ProtoSpecializationEntry {
    const ProtoFunction *template_function;
    ProtoTypeBindingSet bindings;
    ProtoFunction *specialization;
    uint64_t fingerprint;
    bool owned;
} ProtoSpecializationEntry;

typedef struct ProtoSpecializationTable {
    ProtoSpecializationEntry entries[PROTOHACK_MAX_SPECIALIZATIONS];
    size_t count;
} ProtoSpecializationTable;

typedef struct ProtoVM {
    ProtoValue stack[PROTOHACK_STACK_MAX];
    ProtoValue *stack_top;
    uint32_t stack_generation[PROTOHACK_STACK_MAX];

    ProtoCallFrame frames[PROTOHACK_MAX_CALL_STACK];
    int frame_count;

    ProtoValue globals[PROTOHACK_MAX_GLOBALS];
    bool globals_initialized[PROTOHACK_MAX_GLOBALS];
    size_t globals_count;

    ProtoValue last_print_value;

    uint32_t rand_state;

    ProtoSpecializationTable specializations;

#if PROTOHACK_ENABLE_JIT
    ProtoJITProfiler profiler;
#endif
} ProtoVM;

void protovm_init(ProtoVM *vm);
void protovm_reset(ProtoVM *vm);
bool protovm_run(ProtoVM *vm, const ProtoChunk *chunk, ProtoError *error);
const ProtoValue *protovm_last_print(const ProtoVM *vm);
void protovm_register_stdlib(ProtoVM *vm);
ProtoFunction *protovm_find_specialization(const ProtoVM *vm, const ProtoFunction *template_function, const ProtoTypeBindingSet *bindings);
bool protovm_register_specialization(ProtoVM *vm, const ProtoFunction *template_function, const ProtoTypeBindingSet *bindings, ProtoFunction *specialization, bool take_ownership);
void protovm_clear_specializations(ProtoVM *vm, bool free_specializations);

#if PROTOHACK_ENABLE_JIT
const ProtoJITProfiler *protovm_profiler(const ProtoVM *vm);
void protovm_profiler_reset(ProtoVM *vm);
#endif

#ifdef __cplusplus
}
#endif

#endif
