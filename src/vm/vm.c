#include "protohack/vm.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "protohack/error.h"
#include "protohack/binding.h"
#include "protohack/internal/common.h"
#include "protohack/native.h"
#include "protohack/opcode.h"
#include "protohack/typed_memory.h"
#include "protohack/value.h"
#include "protohack/object.h"
#include "protohack/jit_ir.h"

static ProtoCallFrame *current_frame(ProtoVM *vm);

static bool binding_sets_equal(const ProtoTypeBindingSet *a, const ProtoTypeBindingSet *b) {
    if (!a || !b) {
        return false;
    }
    if (a->count != b->count) {
        return false;
    }
    for (uint8_t i = 0; i < a->count && i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
        const ProtoTypeBinding *lhs = &a->entries[i];
        const ProtoTypeBinding *rhs = &b->entries[i];
        if (lhs->tag != rhs->tag || lhs->param != rhs->param) {
            return false;
        }
    }
    return true;
}

static void binding_set_copy(ProtoTypeBindingSet *dest, const ProtoTypeBindingSet *src) {
    if (!dest) {
        return;
    }
    if (!src) {
        dest->count = 0;
        for (uint8_t i = 0; i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
            dest->entries[i].tag = PROTO_TYPE_ANY;
            dest->entries[i].param = -1;
        }
        return;
    }
    dest->count = src->count;
    for (uint8_t i = 0; i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
        dest->entries[i] = src->entries[i];
    }
}

static uint64_t fnv1a_update(uint64_t hash, uint8_t byte) {
    const uint64_t prime = 1099511628211ull;
    hash ^= (uint64_t)byte;
    hash *= prime;
    return hash;
}

static uint64_t binding_set_fingerprint(const ProtoFunction *template_function, const ProtoTypeBindingSet *bindings) {
    const uint64_t offset_basis = 1469598103934665603ull;
    uint64_t hash = offset_basis;

    const ProtoFunction *key_template = template_function;
    if (key_template && key_template->template_origin) {
        key_template = key_template->template_origin;
    }

    uintptr_t ptr_value = (uintptr_t)key_template;
    for (size_t i = 0; i < sizeof(ptr_value); ++i) {
        hash = fnv1a_update(hash, (uint8_t)((ptr_value >> (i * 8)) & 0xFFu));
    }

    if (!bindings) {
        return fnv1a_update(hash, 0u);
    }

    hash = fnv1a_update(hash, bindings->count);
    uint8_t count = bindings->count;
    if (count > PROTOHACK_MAX_TYPE_PARAMS) {
        count = PROTOHACK_MAX_TYPE_PARAMS;
    }
    for (uint8_t i = 0; i < count; ++i) {
        const ProtoTypeBinding *binding = &bindings->entries[i];
        hash = fnv1a_update(hash, (uint8_t)binding->tag);
        hash = fnv1a_update(hash, (uint8_t)(binding->param & 0xFF));
    }
    return hash;
}

static bool binding_is_concrete(const ProtoTypeBinding *binding) {
    return binding && binding->tag != PROTO_TYPE_ANY && binding->param < 0;
}

static bool binding_set_fully_concrete(const ProtoTypeBindingSet *set) {
    if (!set) {
        return false;
    }
    for (uint8_t i = 0; i < set->count && i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
        if (!binding_is_concrete(&set->entries[i])) {
            return false;
        }
    }
    return set->count > 0;
}

static bool binding_contract_satisfied(const ProtoTypeBindingSet *contract, const ProtoTypeBindingSet *active) {
    if (!contract || contract->count == 0) {
        return true;
    }
    if (!active || active->count < contract->count) {
        return false;
    }

    uint8_t limit = contract->count;
    if (limit > PROTOHACK_MAX_TYPE_PARAMS) {
        limit = PROTOHACK_MAX_TYPE_PARAMS;
    }

    for (uint8_t i = 0; i < limit; ++i) {
        const ProtoTypeBinding *expected = &contract->entries[i];
        const ProtoTypeBinding *observed = &active->entries[i];

        bool expected_symbolic = expected->param >= 0;
        bool observed_symbolic = observed->param >= 0;

        if (expected_symbolic) {
            if (observed_symbolic && expected->param != observed->param) {
                return false;
            }
            // Symbolic expectations tolerate concrete bindings at runtime.
            continue;
        }

        if (observed_symbolic) {
            return false;
        }

        if (observed->tag != expected->tag) {
            return false;
        }
    }

    return true;
}

static bool ensure_native_binding_contract(ProtoVM *vm, const ProtoNativeEntry *entry, ProtoError *error) {
    if (!vm || !entry) {
        return false;
    }

    if (entry->signature.binding_contract.count == 0) {
        return true;
    }
    ProtoCallFrame *frame = current_frame(vm);
    const ProtoTypeBindingSet *active = frame ? &frame->bindings : NULL;
    if (binding_contract_satisfied(&entry->signature.binding_contract, active)) {
        return true;
    }

    if (error && error->ok) {
        char expected[128];
        char actual[128];
        proto_binding_set_format(&entry->signature.binding_contract, expected, sizeof expected);
        proto_binding_set_format(active, actual, sizeof actual);
        protoerror_set_code(error, PROTO_DIAG_INTEROP_SIGNATURE_MISMATCH, 0, "Native '%s' binding contract violated", entry->name);
        protoerror_set_message_key(error, "runtime.native.bindingContract");
        protoerror_set_hint(error, "expected %s but active specialization provided %s", expected, actual);
    }

    return false;
}

static bool protovm_verify_binding_contracts(ProtoVM *vm, const ProtoChunk *chunk, ProtoError *error) {
    if (!vm || !chunk) {
        return false;
    }
    if (chunk->binding_entry_count == 0) {
        return true;
    }
    if (!error) {
        return false;
    }

    for (size_t i = 0; i < chunk->binding_entry_count; ++i) {
        const ProtoBindingMapEntry *entry = &chunk->binding_entries[i];
        size_t slot = (size_t)entry->symbol_index;
        const char *global_name = (slot < chunk->globals_count && chunk->globals && chunk->globals[slot]) ? chunk->globals[slot] : "<global>";

        if (slot >= chunk->globals_count) {
            protoerror_set_code(error, PROTO_DIAG_GENERIC_BINDING_MISMATCH, 0, "Binding metadata references invalid global index %u", (unsigned)slot);
            protoerror_set_message_key(error, "runtime.binding.invalidGlobal");
            return false;
        }
        if (slot >= PROTOHACK_MAX_GLOBALS || !vm->globals_initialized[slot]) {
            protoerror_set_code(error, PROTO_DIAG_GENERIC_BINDING_MISMATCH, 0, "Global '%s' was not initialized for binding enforcement", global_name);
            protoerror_set_message_key(error, "runtime.binding.uninitialized");
            return false;
        }

        const ProtoValue *value = &vm->globals[slot];
        if (value->type != PROTO_VAL_FUNCTION || !value->as.function) {
            protoerror_set_code(error, PROTO_DIAG_GENERIC_BINDING_MISMATCH, 0, "Global '%s' did not resolve to a function specialization", global_name);
            protoerror_set_message_key(error, "runtime.binding.nonFunction");
            return false;
        }

        const ProtoFunction *function = value->as.function;
        if (!binding_sets_equal(&function->bindings, &entry->bindings)) {
            char expected[128];
            char actual[128];
            proto_binding_set_format(&entry->bindings, expected, sizeof expected);
            proto_binding_set_format(&function->bindings, actual, sizeof actual);
            protoerror_set_code(error, PROTO_DIAG_GENERIC_BINDING_CONFLICT, 0, "Global '%s' binding mismatch", global_name);
            protoerror_set_message_key(error, "runtime.binding.conflict");
            protoerror_set_hint(error, "expected %s but module initialized with %s", expected, actual);
            return false;
        }
    }

    return true;
}

typedef struct {
    ProtoFunction **items;
    size_t count;
    size_t capacity;
} ProtoFunctionList;

typedef struct {
    char base[256];
    ProtoFunctionKind kind;
    uint8_t type_param_count;
    ProtoFunction *function;
} ProtoTemplateRecord;

typedef struct {
    ProtoTemplateRecord *entries;
    size_t count;
    size_t capacity;
} ProtoTemplateRegistry;

static bool function_list_append_unique(ProtoFunctionList *list, ProtoFunction *function) {
    if (!list || !function) {
        return true;
    }
    for (size_t i = 0; i < list->count; ++i) {
        if (list->items[i] == function) {
            return true;
        }
    }
    size_t new_count = list->count + 1;
    if (new_count > list->capacity) {
        size_t new_capacity = list->capacity == 0 ? 16u : list->capacity * 2u;
        ProtoFunction **resized = (ProtoFunction **)realloc(list->items, new_capacity * sizeof *resized);
        if (!resized) {
            return false;
        }
        list->items = resized;
        list->capacity = new_capacity;
    }
    list->items[list->count++] = function;
    return true;
}

static bool collect_functions_from_chunk(const ProtoChunk *chunk, ProtoFunctionList *list) {
    if (!chunk || !list) {
        return true;
    }
    for (size_t i = 0; i < chunk->constants_count; ++i) {
        const ProtoValue *value = &chunk->constants[i];
        if (value->type != PROTO_VAL_FUNCTION) {
            continue;
        }
        ProtoFunction *fn = value->as.function;
        if (!fn) {
            continue;
        }
        if (!function_list_append_unique(list, fn)) {
            return false;
        }
        if (!collect_functions_from_chunk(&fn->chunk, list)) {
            return false;
        }
    }
    return true;
}

static bool function_base_name(const ProtoFunction *function, char *buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0) {
        return false;
    }
    buffer[0] = '\0';
    if (!function || !function->name) {
        return false;
    }
    const char *name = function->name;
    const char *angle = strchr(name, '<');
    size_t length = angle ? (size_t)(angle - name) : strlen(name);
    if (length >= buffer_size) {
        length = buffer_size - 1;
    }
    if (length == 0) {
        return false;
    }
    memcpy(buffer, name, length);
    buffer[length] = '\0';
    return true;
}

static bool template_registry_add(ProtoTemplateRegistry *registry, ProtoFunction *function) {
    if (!registry || !function || function->type_param_count == 0) {
        return true;
    }
    char base[256];
    if (!function_base_name(function, base, sizeof base)) {
        return true;
    }
    for (size_t i = 0; i < registry->count; ++i) {
        ProtoTemplateRecord *record = &registry->entries[i];
        if (record->function == function) {
            return true;
        }
        if (record->kind == function->kind && record->type_param_count == function->type_param_count && strcmp(record->base, base) == 0) {
            return true;
        }
    }
    size_t new_count = registry->count + 1;
    if (new_count > registry->capacity) {
        size_t new_capacity = registry->capacity == 0 ? 16u : registry->capacity * 2u;
        ProtoTemplateRecord *resized = (ProtoTemplateRecord *)realloc(registry->entries, new_capacity * sizeof *resized);
        if (!resized) {
            return false;
        }
        registry->entries = resized;
        registry->capacity = new_capacity;
    }
    ProtoTemplateRecord *record = &registry->entries[registry->count++];
    strncpy(record->base, base, sizeof record->base - 1);
    record->base[sizeof record->base - 1] = '\0';
    record->kind = function->kind;
    record->type_param_count = function->type_param_count;
    record->function = function;
    return true;
}

static ProtoFunction *template_registry_find(const ProtoTemplateRegistry *registry, ProtoFunctionKind kind, const char *base, uint8_t type_param_count) {
    if (!registry || !base) {
        return NULL;
    }
    for (size_t i = 0; i < registry->count; ++i) {
        const ProtoTemplateRecord *record = &registry->entries[i];
        if (record->kind == kind && record->type_param_count == type_param_count && strcmp(record->base, base) == 0) {
            return record->function;
        }
    }
    return NULL;
}

static void template_registry_free(ProtoTemplateRegistry *registry) {
    if (!registry) {
        return;
    }
    free(registry->entries);
    registry->entries = NULL;
    registry->capacity = 0;
    registry->count = 0;
}

static void function_list_free(ProtoFunctionList *list) {
    if (!list) {
        return;
    }
    free(list->items);
    list->items = NULL;
    list->capacity = 0;
    list->count = 0;
}

static void protovm_seed_chunk_specializations(ProtoVM *vm, const ProtoChunk *chunk) {
    if (!vm || !chunk) {
        return;
    }

    ProtoFunctionList functions = {0};
    if (!collect_functions_from_chunk(chunk, &functions)) {
        function_list_free(&functions);
        return;
    }

    ProtoTemplateRegistry registry = {0};
    for (size_t i = 0; i < functions.count; ++i) {
        ProtoFunction *fn = functions.items[i];
        if (!template_registry_add(&registry, fn)) {
            template_registry_free(&registry);
            function_list_free(&functions);
            return;
        }
    }

    for (size_t i = 0; i < functions.count; ++i) {
        ProtoFunction *fn = functions.items[i];
        if (!fn) {
            continue;
        }
        if (fn->bindings.count == 0) {
            continue;
        }
        if (!binding_set_fully_concrete(&fn->bindings)) {
            continue;
        }
        const ProtoFunction *origin = fn->template_origin;
        if (!origin) {
            char base[256];
            if (function_base_name(fn, base, sizeof base)) {
                ProtoFunction *resolved = template_registry_find(&registry, fn->kind, base, fn->type_param_count);
                if (resolved && resolved != fn) {
                    origin = resolved;
                    fn->template_origin = resolved;
                }
            }
        }
        if (!origin || origin == fn) {
            continue;
        }
        protovm_register_specialization(vm, origin, &fn->bindings, fn, false);
    }

    template_registry_free(&registry);
    function_list_free(&functions);
}

static bool resolve_binding_via_stack(const ProtoVM *vm, size_t caller_index, int8_t param_index, ProtoTypeBinding *out) {
    if (!vm || !out || param_index < 0) {
        return false;
    }
    int8_t current = param_index;
    for (ptrdiff_t frame_index = (ptrdiff_t)caller_index; frame_index >= 0 && current >= 0; --frame_index) {
        const ProtoCallFrame *frame = &vm->frames[frame_index];
        if (!frame || current < 0) {
            break;
        }
        if ((uint8_t)current >= frame->bindings.count || frame->bindings.count > PROTOHACK_MAX_TYPE_PARAMS) {
            return false;
        }
        ProtoTypeBinding candidate = frame->bindings.entries[current];
        if (candidate.tag != PROTO_TYPE_ANY || candidate.param < 0) {
            *out = candidate;
            return true;
        }
        if (candidate.param == current) {
            /* Prevent infinite loops when bindings self-reference without progress */
            continue;
        }
        current = candidate.param;
    }
    return false;
}

static bool resolve_bindings_for_call(const ProtoVM *vm, const ProtoFunction *function, ProtoTypeBindingSet *out) {
    if (!function || !out) {
        return false;
    }
    if (function->bindings.count == 0) {
        out->count = 0;
        for (uint8_t i = 0; i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
            out->entries[i].tag = PROTO_TYPE_ANY;
            out->entries[i].param = -1;
        }
        return false;
    }

    binding_set_copy(out, &function->bindings);

    if (!vm || vm->frame_count == 0) {
        return true;
    }

    size_t caller_index = (size_t)(vm->frame_count - 1);
    for (uint8_t i = 0; i < out->count && i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
        ProtoTypeBinding *binding = &out->entries[i];
        if (binding->tag == PROTO_TYPE_ANY && binding->param >= 0) {
            ProtoTypeBinding resolved;
            if (resolve_binding_via_stack(vm, caller_index, binding->param, &resolved)) {
                *binding = resolved;
            }
        }
    }
    return true;
}

static void apply_bindings_to_function(ProtoFunction *function, const ProtoTypeBindingSet *bindings) {
    if (!function || !bindings) {
        return;
    }
    function->bindings = *bindings;

    ProtoTypeTag argument_tags[PROTOHACK_MAX_TYPE_PARAMS];
    for (uint8_t i = 0; i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
        argument_tags[i] = PROTO_TYPE_ANY;
    }

    uint8_t count = bindings->count;
    if (count > PROTOHACK_MAX_TYPE_PARAMS) {
        count = PROTOHACK_MAX_TYPE_PARAMS;
    }
    for (uint8_t i = 0; i < count; ++i) {
        if (bindings->entries[i].tag != PROTO_TYPE_ANY && bindings->entries[i].param < 0) {
            argument_tags[i] = bindings->entries[i].tag;
        }
    }

    proto_function_set_type_arguments(function, argument_tags, count);

    for (uint8_t i = 0; i < function->arity && i < PROTOHACK_MAX_PARAMS; ++i) {
        int8_t binding_index = function->param_type_params[i];
        if (binding_index >= 0 && (uint8_t)binding_index < count) {
            const ProtoTypeBinding *binding = &bindings->entries[binding_index];
            if (binding->tag != PROTO_TYPE_ANY && binding->param < 0) {
                function->param_types[i] = binding->tag;
            }
        }
    }

    if (function->return_type_param >= 0 && (uint8_t)function->return_type_param < count) {
        const ProtoTypeBinding *binding = &bindings->entries[function->return_type_param];
        if (binding->tag != PROTO_TYPE_ANY && binding->param < 0) {
            function->return_type = binding->tag;
        }
    }
}

static ProtoFunction *instantiate_runtime_specialization(ProtoVM *vm, const ProtoFunction *template_function, const ProtoTypeBindingSet *bindings, ProtoError *error) {
    if (!vm || !template_function || !bindings) {
        if (error) {
            protoerror_set(error, 0, "Invalid specialization request");
        }
        return NULL;
    }

    const ProtoFunction *origin = template_function->template_origin ? template_function->template_origin : template_function;

    ProtoFunction *specialization = proto_function_copy(origin);
    if (!specialization) {
        if (error) {
            protoerror_set(error, 0, "Failed to clone template during specialization");
        }
        return NULL;
    }

    specialization->template_origin = origin;
    apply_bindings_to_function(specialization, bindings);

    char name_buffer[256];
    if (proto_function_format_specialization_name(NULL, origin, bindings, NULL, 0, name_buffer, sizeof name_buffer)) {
        proto_function_set_name(specialization, name_buffer);
    }

    if (!protovm_register_specialization(vm, origin, bindings, specialization, true)) {
        proto_function_free(specialization);
        if (error) {
            protoerror_set(error, 0, "Specialization table overflow");
        }
        return NULL;
    }

    return specialization;
}

ProtoFunction *protovm_find_specialization(const ProtoVM *vm, const ProtoFunction *template_function, const ProtoTypeBindingSet *bindings) {
    if (!vm || !template_function || !bindings) {
        return NULL;
    }
    uint64_t fingerprint = binding_set_fingerprint(template_function, bindings);
    for (size_t i = 0; i < vm->specializations.count; ++i) {
        const ProtoSpecializationEntry *entry = &vm->specializations.entries[i];
        if (entry->template_function == template_function && entry->fingerprint == fingerprint && binding_sets_equal(&entry->bindings, bindings)) {
            return entry->specialization;
        }
    }
    return NULL;
}

bool protovm_register_specialization(ProtoVM *vm, const ProtoFunction *template_function, const ProtoTypeBindingSet *bindings, ProtoFunction *specialization, bool take_ownership) {
    if (!vm || !template_function || !bindings || !specialization) {
        return false;
    }
    uint64_t fingerprint = binding_set_fingerprint(template_function, bindings);
    ProtoFunction *existing = protovm_find_specialization(vm, template_function, bindings);
    if (existing) {
        for (size_t i = 0; i < vm->specializations.count; ++i) {
            ProtoSpecializationEntry *entry = &vm->specializations.entries[i];
            if (entry->template_function == template_function && entry->fingerprint == fingerprint && binding_sets_equal(&entry->bindings, bindings)) {
                entry->specialization = specialization;
                entry->bindings = *bindings;
                entry->fingerprint = fingerprint;
                entry->owned = take_ownership;
                return true;
            }
        }
        return true;
    }
    if (vm->specializations.count >= PROTOHACK_MAX_SPECIALIZATIONS) {
        return false;
    }
    ProtoSpecializationEntry *entry = &vm->specializations.entries[vm->specializations.count++];
    entry->template_function = template_function;
    entry->bindings = *bindings;
    entry->specialization = specialization;
    entry->fingerprint = fingerprint;
    entry->owned = take_ownership;
    return true;
}

void protovm_clear_specializations(ProtoVM *vm, bool free_specializations) {
    if (!vm) {
        return;
    }
    if (free_specializations) {
        for (size_t i = 0; i < vm->specializations.count; ++i) {
            ProtoSpecializationEntry *entry = &vm->specializations.entries[i];
            if (entry->owned && entry->specialization && entry->specialization != entry->template_function) {
                proto_function_free(entry->specialization);
            }
            entry->specialization = NULL;
            entry->owned = false;
        }
    }
    vm->specializations.count = 0;
}

static ProtoCallFrame *current_frame(ProtoVM *vm) {
    PROTOHACK_ASSERT(vm && vm->frame_count > 0, "VM has no active frames");
    return &vm->frames[vm->frame_count - 1];
}

static uint8_t frame_read_byte(ProtoCallFrame *frame) {
    const ProtoChunk *chunk = &frame->function->chunk;
    PROTOHACK_ASSERT(frame->ip < chunk->code_count, "VM attempted to read past bytecode");
    return chunk->code[frame->ip++];
}

static uint16_t frame_read_short(ProtoCallFrame *frame) {
    uint16_t high = frame_read_byte(frame);
    uint16_t low = frame_read_byte(frame);
    return (uint16_t)((high << 8) | low);
}

static void stack_push(ProtoVM *vm, ProtoValue value) {
    PROTOHACK_ASSERT(vm->stack_top - vm->stack < PROTOHACK_STACK_MAX, "Stack overflow");
    *vm->stack_top++ = value;
}

static ProtoValue stack_pop(ProtoVM *vm) {
    PROTOHACK_ASSERT(vm->stack_top > vm->stack, "Stack underflow");
    vm->stack_top--;
    size_t index = (size_t)(vm->stack_top - vm->stack);
    vm->stack_generation[index]++;
    return *vm->stack_top;
}

static bool stack_pointer_valid(const ProtoVM *vm, const ProtoPointer *pointer, size_t *out_index) {
    if (!vm || !pointer || pointer->kind != PROTO_POINTER_STACK || !pointer->as.stack.slot) {
        return false;
    }
    ptrdiff_t diff = pointer->as.stack.slot - vm->stack;
    if (diff < 0 || diff >= (ptrdiff_t)PROTOHACK_STACK_MAX) {
        return false;
    }
    size_t index = (size_t)diff;
    if (out_index) {
        *out_index = index;
    }
    return vm->stack_generation[index] == pointer->as.stack.generation;
}

#if PROTOHACK_ENABLE_JIT
static bool protojit_execute_block(ProtoVM *vm, ProtoCallFrame *frame, ProtoChunk *chunk, ProtoJITIR *ir, ProtoError *error, ProtoOpCode *failed_opcode);
static int protojit_try_dispatch_block(ProtoVM *vm, ProtoCallFrame *frame, ProtoChunk *chunk, ProtoError *error);
#endif

static ProtoValue *stack_peek(ProtoVM *vm, size_t distance) {
    PROTOHACK_ASSERT(vm->stack_top - vm->stack > (ptrdiff_t)distance, "Stack peek out of range");
    return vm->stack_top - distance - 1;
}

static bool ensure_number_operand(ProtoValue *value, ProtoError *error, size_t line) {
    if (value->type == PROTO_VAL_NUMBER) {
        return true;
    }
    protoerror_set(error, line, "Operand must be a number");
    return false;
}

static bool ensure_number_operands(ProtoValue *a, ProtoValue *b, ProtoError *error, size_t line) {
    if (a->type == PROTO_VAL_NUMBER && b->type == PROTO_VAL_NUMBER) {
        return true;
    }
    protoerror_set(error, line, "Operands must be numbers");
    return false;
}

static bool is_falsey(const ProtoValue *value) {
    if (!value) {
        return true;
    }
    switch (value->type) {
        case PROTO_VAL_NULL:
            return true;
        case PROTO_VAL_BOOL:
            return !value->as.boolean;
        default:
            return false;
    }
}

static bool call_native(ProtoVM *vm, uint8_t native_index, uint8_t arg_count, ProtoError *error) {
    if (arg_count > PROTOHACK_MAX_NATIVE_ARGS) {
        protoerror_set(error, 0, "Too many arguments to native function");
        return false;
    }

    const ProtoNativeEntry *table = protonative_table();
    size_t count = protonative_count();
    if (native_index >= count) {
        protoerror_set(error, 0, "Unknown native function");
        return false;
    }

    const ProtoNativeEntry *entry = &table[native_index];
    if (!ensure_native_binding_contract(vm, entry, error)) {
        return false;
    }
    ProtoValue args_buffer[PROTOHACK_MAX_NATIVE_ARGS];
    for (uint8_t i = 0; i < arg_count; ++i) {
        args_buffer[arg_count - i - 1] = stack_pop(vm);
    }

    ProtoValue result = proto_value_null();
    bool ok = entry->function(vm, args_buffer, arg_count, &result, error);

    for (uint8_t i = 0; i < arg_count; ++i) {
        proto_value_free(&args_buffer[i]);
    }

    if (!ok) {
        proto_value_free(&result);
        return false;
    }

    stack_push(vm, result);
    return true;
}

static bool call_function(ProtoVM *vm, const ProtoFunction *function, const ProtoTypeBindingSet *bindings, uint8_t arg_count, ProtoError *error) {
    if (!function) {
        protoerror_set(error, 0, "Attempted to call null function");
        return false;
    }
    if (function->arity != arg_count) {
        protoerror_set(error, 0, "Function '%s' expects %u arguments but received %u",
                       function->name ? function->name : "<anonymous>", function->arity, arg_count);
        return false;
    }
    if (vm->frame_count >= PROTOHACK_MAX_CALL_STACK) {
        protoerror_set(error, 0, "Call stack overflow");
        return false;
    }

    ProtoCallFrame *frame = &vm->frames[vm->frame_count++];
    frame->function = function;
    frame->ip = 0;
    frame->slots = vm->stack_top - arg_count - 1;
    if (bindings) {
        binding_set_copy(&frame->bindings, bindings);
    } else {
        binding_set_copy(&frame->bindings, &function->bindings);
    }
    return true;
}

static bool call_value(ProtoVM *vm, ProtoValue callee, uint8_t arg_count, ProtoError *error) {
    ProtoValue *callee_slot = stack_peek(vm, arg_count);
    if (!callee_slot) {
        protoerror_set(error, 0, "Invalid call target");
        return false;
    }

    switch (callee.type) {
        case PROTO_VAL_FUNCTION: {
            ProtoFunction *function = callee.as.function;
            if (!function) {
                protoerror_set(error, 0, "Attempted to call null function");
                return false;
            }
            const ProtoFunction *dispatch = function;
            ProtoTypeBindingSet resolved_bindings;
            bool has_bindings = resolve_bindings_for_call(vm, function, &resolved_bindings);
            bool function_bindings_concrete = binding_set_fully_concrete(&function->bindings);

            if (has_bindings && binding_set_fully_concrete(&resolved_bindings) && !function_bindings_concrete) {
                const ProtoFunction *origin = function->template_origin ? function->template_origin : function;
                ProtoFunction *specialization = protovm_find_specialization(vm, origin, &resolved_bindings);
                if (!specialization) {
                    specialization = instantiate_runtime_specialization(vm, function, &resolved_bindings, error);
                    if (!specialization) {
                        return false;
                    }
                }
                dispatch = specialization;
                proto_value_free(callee_slot);
                *callee_slot = proto_value_function(specialization);
                return call_function(vm, dispatch, &dispatch->bindings, arg_count, error);
            }

            if (has_bindings) {
                return call_function(vm, dispatch, &resolved_bindings, arg_count, error);
            }

            return call_function(vm, dispatch, &dispatch->bindings, arg_count, error);
        }
        case PROTO_VAL_CLASS: {
            ProtoClass *klass = callee.as.klass;
            ProtoInstance *instance = proto_instance_new(klass);

            proto_value_free(callee_slot);
            *callee_slot = proto_value_instance(instance);
            proto_instance_release(instance);

            ProtoFunction *initializer = proto_class_find_method(klass, "init");
            if (initializer) {
                if (initializer->arity != arg_count) {
                    protoerror_set(error, 0, "Initializer expects %u arguments but received %u",
                                   initializer->arity, arg_count);
                    return false;
                }
                return call_function(vm, initializer, &initializer->bindings, arg_count, error);
            }

            if (arg_count != 0) {
                protoerror_set(error, 0, "Class constructors expect %u arguments", 0u);
                return false;
            }
            return true;
        }
        case PROTO_VAL_BOUND_METHOD: {
            ProtoBoundMethod *bound = callee.as.bound_method;
            proto_bound_method_retain(bound);
            ProtoFunction *method = proto_bound_method_function(bound);
            ProtoInstance *receiver = proto_bound_method_receiver(bound);

            proto_value_free(callee_slot);
            *callee_slot = proto_value_instance(receiver);
            proto_instance_release(receiver);

            bool ok = call_function(vm, method, &method->bindings, arg_count, error);
            proto_bound_method_release(bound);
            return ok;
        }
        default:
            protoerror_set(error, 0, "Attempted to call non-callable value");
            return false;
    }
}

void protovm_register_stdlib(ProtoVM *vm) {
    vm->rand_state = (uint32_t)time(NULL);
}

void protovm_init(ProtoVM *vm) {
    if (!vm) {
        return;
    }
    vm->stack_top = vm->stack;
    vm->frame_count = 0;
    for (size_t i = 0; i < PROTOHACK_STACK_MAX; ++i) {
        vm->stack[i] = proto_value_null();
    }

    for (size_t i = 0; i < PROTOHACK_STACK_MAX; ++i) {
        vm->stack_generation[i] = 0u;
    }
    for (size_t i = 0; i < PROTOHACK_MAX_GLOBALS; ++i) {
        vm->globals[i] = proto_value_null();
        vm->globals_initialized[i] = false;
    }
    vm->globals_count = 0;
    vm->last_print_value = proto_value_null();
#if PROTOHACK_ENABLE_JIT
    protojit_profiler_init(&vm->profiler);
#endif
    vm->specializations.count = 0;
    protovm_register_stdlib(vm);
}

void protovm_reset(ProtoVM *vm) {
    if (!vm) {
        return;
    }
    while (vm->stack_top != vm->stack) {
        ProtoValue value = stack_pop(vm);
        proto_value_free(&value);
    }
    vm->frame_count = 0;

    for (size_t i = 0; i < PROTOHACK_STACK_MAX; ++i) {
        vm->stack_generation[i] = 0u;
    }
    for (size_t i = 0; i < vm->globals_count; ++i) {
        if (vm->globals_initialized[i]) {
            proto_value_free(&vm->globals[i]);
            vm->globals_initialized[i] = false;
        }
    }
    vm->globals_count = 0;

    proto_value_free(&vm->last_print_value);
    vm->last_print_value = proto_value_null();

    protovm_clear_specializations(vm, true);
}

const ProtoValue *protovm_last_print(const ProtoVM *vm) {
    if (!vm) {
        return NULL;
    }
    return &vm->last_print_value;
}

bool protovm_run(ProtoVM *vm, const ProtoChunk *chunk, ProtoError *error) {
    if (!vm || !chunk || !error) {
        if (error) {
            protoerror_set(error, 0, "Invalid arguments to VM");
        }
        return false;
    }

    protoerror_reset(error);

    protovm_seed_chunk_specializations(vm, chunk);

    ProtoFunction script = {0};
    script.kind = PROTO_FUNC_SCRIPT;
    script.arity = 0;
    script.return_type = PROTO_TYPE_NONE;
    script.name = NULL;
    script.chunk = *chunk;

    vm->stack_top = vm->stack;
    vm->frame_count = 0;
    vm->frames[vm->frame_count++] = (ProtoCallFrame){
        .function = &script,
        .ip = 0,
        .slots = vm->stack,
        .bindings = {
            .count = 0
        }
    };

    while (vm->frame_count > 0) {
        ProtoCallFrame *frame = current_frame(vm);
        const ProtoChunk *active_chunk = &frame->function->chunk;

        if (frame->ip >= active_chunk->code_count) {
            ProtoValue result = proto_value_null();
            while (vm->stack_top > frame->slots) {
                ProtoValue temp = stack_pop(vm);
                proto_value_free(&temp);
            }
            vm->frame_count--;
            if (vm->frame_count == 0) {
                proto_value_free(&result);
                if (!protovm_verify_binding_contracts(vm, chunk, error)) {
                    return false;
                }
                return true;
            }
            vm->stack_top = current_frame(vm)->slots;
            stack_push(vm, result);
            continue;
        }

#if PROTOHACK_ENABLE_JIT
        ProtoChunk *mutable_chunk = (ProtoChunk *)active_chunk;
        int jit_status = protojit_try_dispatch_block(vm, frame, mutable_chunk, error);
        if (jit_status < 0) {
            return false;
        }
        if (jit_status > 0) {
            continue;
        }
#endif

        uint8_t instruction = frame_read_byte(frame);
        size_t line_index = frame->ip > 0 ? frame->ip - 1 : 0;
        size_t line = line_index < active_chunk->lines_count ? active_chunk->lines[line_index] : 0;

#if PROTOHACK_JIT_PROFILE
    protojit_profiler_count(&vm->profiler, (ProtoOpCode)instruction);
#endif

        switch (instruction) {
            case PROTO_OP_CONSTANT: {
                uint16_t index = frame_read_short(frame);
                if (index >= active_chunk->constants_count) {
                    protoerror_set(error, line, "Invalid constant index");
                    return false;
                }
                stack_push(vm, proto_value_copy(&active_chunk->constants[index]));
                break;
            }
            case PROTO_OP_TRUE:
                stack_push(vm, proto_value_bool(true));
                break;
            case PROTO_OP_FALSE:
                stack_push(vm, proto_value_bool(false));
                break;
            case PROTO_OP_NULL:
                stack_push(vm, proto_value_null());
                break;
            case PROTO_OP_GET_GLOBAL: {
                uint16_t slot = frame_read_short(frame);
                if (slot >= active_chunk->globals_count || !vm->globals_initialized[slot]) {
                    protoerror_set(error, line, "Undefined global");
                    return false;
                }
                stack_push(vm, proto_value_copy(&vm->globals[slot]));
                break;
            }
            case PROTO_OP_SET_GLOBAL: {
                uint16_t slot = frame_read_short(frame);
                if (slot >= active_chunk->globals_count) {
                    protoerror_set(error, line, "Invalid global index");
                    return false;
                }
                ProtoValue value = proto_value_copy(stack_peek(vm, 0));
                if (vm->globals_initialized[slot]) {
                    proto_value_free(&vm->globals[slot]);
                }
                vm->globals[slot] = value;
                vm->globals_initialized[slot] = true;
                if (slot + 1 > vm->globals_count) {
                    vm->globals_count = slot + 1;
                }
                break;
            }
            case PROTO_OP_GET_LOCAL: {
                uint8_t slot = frame_read_byte(frame);
                stack_push(vm, proto_value_copy(&frame->slots[slot]));
                break;
            }
            case PROTO_OP_SET_LOCAL: {
                uint8_t slot = frame_read_byte(frame);
                ProtoValue value = proto_value_copy(stack_peek(vm, 0));
                proto_value_free(&frame->slots[slot]);
                frame->slots[slot] = value;
                break;
            }
            case PROTO_OP_ADDR_LOCAL: {
                uint8_t slot = frame_read_byte(frame);
                uint8_t flags = frame_read_byte(frame);
                ProtoValue *target = &frame->slots[slot];
                ptrdiff_t diff = target - vm->stack;
                if (diff < 0 || diff >= (ptrdiff_t)PROTOHACK_STACK_MAX) {
                    protoerror_set(error, line, "Pointer target out of range");
                    return false;
                }
                size_t index = (size_t)diff;
                ProtoPointer pointer = {0};
                pointer.kind = PROTO_POINTER_STACK;
                pointer.is_const = (flags & 1u) != 0u;
                pointer.as.stack.slot = target;
                pointer.as.stack.generation = vm->stack_generation[index];
                stack_push(vm, proto_value_pointer(pointer));
                break;
            }
            case PROTO_OP_ADDR_GLOBAL: {
                uint16_t slot = frame_read_short(frame);
                uint8_t flags = frame_read_byte(frame);
                if (slot >= active_chunk->globals_count || slot >= PROTOHACK_MAX_GLOBALS) {
                    protoerror_set(error, line, "Invalid global index for pointer");
                    return false;
                }
                ProtoPointer pointer = {0};
                pointer.kind = PROTO_POINTER_GLOBAL;
                pointer.is_const = (flags & 1u) != 0u;
                pointer.as.global.slot = &vm->globals[slot];
                pointer.as.global.initialized = &vm->globals_initialized[slot];
                pointer.as.global.index = slot;
                stack_push(vm, proto_value_pointer(pointer));
                break;
            }
            case PROTO_OP_PTR_LOAD: {
                ProtoValue pointer_value = stack_pop(vm);
                if (pointer_value.type != PROTO_VAL_POINTER) {
                    protoerror_set(error, line, "Cannot dereference non-pointer value");
                    proto_value_free(&pointer_value);
                    return false;
                }
                ProtoPointer pointer = pointer_value.as.pointer;
                ProtoValue result = proto_value_null();
                switch (pointer.kind) {
                    case PROTO_POINTER_STACK: {
                        size_t index = 0;
                        if (!stack_pointer_valid(vm, &pointer, &index)) {
                            protoerror_set(error, line, "Dangling pointer dereference");
                            proto_value_free(&pointer_value);
                            return false;
                        }
                        result = proto_value_copy(pointer.as.stack.slot);
                        break;
                    }
                    case PROTO_POINTER_GLOBAL: {
                        if (!pointer.as.global.initialized || !*pointer.as.global.initialized) {
                            protoerror_set(error, line, "Pointer to uninitialized global");
                            proto_value_free(&pointer_value);
                            return false;
                        }
                        result = proto_value_copy(pointer.as.global.slot);
                        break;
                    }
                    default:
                        protoerror_set(error, line, "Unsupported pointer dereference");
                        proto_value_free(&pointer_value);
                        return false;
                }
                proto_value_free(&pointer_value);
                stack_push(vm, result);
                break;
            }
            case PROTO_OP_PTR_STORE: {
                ProtoValue value = stack_pop(vm);
                ProtoValue pointer_value = stack_pop(vm);
                if (pointer_value.type != PROTO_VAL_POINTER) {
                    protoerror_set(error, line, "Cannot assign through non-pointer value");
                    proto_value_free(&pointer_value);
                    proto_value_free(&value);
                    return false;
                }
                ProtoPointer pointer = pointer_value.as.pointer;
                if (pointer.is_const) {
                    protoerror_set(error, line, "Cannot assign through pointer to const");
                    proto_value_free(&pointer_value);
                    proto_value_free(&value);
                    return false;
                }
                switch (pointer.kind) {
                    case PROTO_POINTER_STACK: {
                        size_t index = 0;
                        if (!stack_pointer_valid(vm, &pointer, &index)) {
                            protoerror_set(error, line, "Dangling pointer assignment");
                            proto_value_free(&pointer_value);
                            proto_value_free(&value);
                            return false;
                        }
                        proto_value_free(pointer.as.stack.slot);
                        *pointer.as.stack.slot = proto_value_copy(&value);
                        break;
                    }
                    case PROTO_POINTER_GLOBAL: {
                        if (!pointer.as.global.slot || pointer.as.global.index >= PROTOHACK_MAX_GLOBALS) {
                            protoerror_set(error, line, "Invalid global pointer assignment");
                            proto_value_free(&pointer_value);
                            proto_value_free(&value);
                            return false;
                        }
                        proto_value_free(pointer.as.global.slot);
                        *pointer.as.global.slot = proto_value_copy(&value);
                        if (pointer.as.global.initialized) {
                            *pointer.as.global.initialized = true;
                        }
                        if (pointer.as.global.index + 1 > vm->globals_count) {
                            vm->globals_count = pointer.as.global.index + 1;
                        }
                        break;
                    }
                    default:
                        protoerror_set(error, line, "Unsupported pointer assignment");
                        proto_value_free(&pointer_value);
                        proto_value_free(&value);
                        return false;
                }
                ProtoValue result = proto_value_copy(&value);
                proto_value_free(&pointer_value);
                stack_push(vm, result);
                proto_value_free(&value);
                break;
            }
            case PROTO_OP_ADD: {
                ProtoValue b = stack_pop(vm);
                ProtoValue a = stack_pop(vm);
                if (a.type == PROTO_VAL_STRING || b.type == PROTO_VAL_STRING) {
                    char *left = proto_value_to_cstring(&a);
                    char *right = proto_value_to_cstring(&b);
                    size_t left_len = strlen(left);
                    size_t right_len = strlen(right);
                    char *concat = (char *)malloc(left_len + right_len + 1);
                    if (!concat) {
                        free(left);
                        free(right);
                        proto_value_free(&a);
                        proto_value_free(&b);
                        PROTOHACK_FATAL("Out of memory");
                    }
                    memcpy(concat, left, left_len);
                    memcpy(concat + left_len, right, right_len);
                    concat[left_len + right_len] = '\0';
                    ProtoValue result = proto_value_string(concat, left_len + right_len);
                    free(concat);
                    free(left);
                    free(right);
                    proto_value_free(&a);
                    proto_value_free(&b);
                    stack_push(vm, result);
                } else {
                    if (!ensure_number_operands(&a, &b, error, line)) {
                        proto_value_free(&a);
                        proto_value_free(&b);
                        return false;
                    }
                    ProtoValue result = proto_value_number(a.as.number + b.as.number);
                    proto_value_free(&a);
                    proto_value_free(&b);
                    stack_push(vm, result);
                }
                break;
            }
            case PROTO_OP_SUB: {
                ProtoValue b = stack_pop(vm);
                ProtoValue a = stack_pop(vm);
                if (!ensure_number_operands(&a, &b, error, line)) {
                    proto_value_free(&a);
                    proto_value_free(&b);
                    return false;
                }
                ProtoValue result = proto_value_number(a.as.number - b.as.number);
                proto_value_free(&a);
                proto_value_free(&b);
                stack_push(vm, result);
                break;
            }
            case PROTO_OP_MUL: {
                ProtoValue b = stack_pop(vm);
                ProtoValue a = stack_pop(vm);
                if (!ensure_number_operands(&a, &b, error, line)) {
                    proto_value_free(&a);
                    proto_value_free(&b);
                    return false;
                }
                ProtoValue result = proto_value_number(a.as.number * b.as.number);
                proto_value_free(&a);
                proto_value_free(&b);
                stack_push(vm, result);
                break;
            }
            case PROTO_OP_DIV: {
                ProtoValue b = stack_pop(vm);
                ProtoValue a = stack_pop(vm);
                if (!ensure_number_operands(&a, &b, error, line)) {
                    proto_value_free(&a);
                    proto_value_free(&b);
                    return false;
                }
                if (b.as.number == 0.0) {
                    proto_value_free(&a);
                    proto_value_free(&b);
                    protoerror_set(error, line, "Division by zero");
                    return false;
                }
                ProtoValue result = proto_value_number(a.as.number / b.as.number);
                proto_value_free(&a);
                proto_value_free(&b);
                stack_push(vm, result);
                break;
            }
            case PROTO_OP_NEGATE: {
                ProtoValue value = stack_pop(vm);
                if (!ensure_number_operand(&value, error, line)) {
                    proto_value_free(&value);
                    return false;
                }
                value.as.number = -value.as.number;
                stack_push(vm, value);
                break;
            }
            case PROTO_OP_NOT: {
                ProtoValue value = stack_pop(vm);
                bool truth = is_falsey(&value);
                proto_value_free(&value);
                stack_push(vm, proto_value_bool(truth));
                break;
            }
            case PROTO_OP_EQUAL: {
                ProtoValue b = stack_pop(vm);
                ProtoValue a = stack_pop(vm);
                bool equal = proto_value_equal(&a, &b);
                proto_value_free(&a);
                proto_value_free(&b);
                stack_push(vm, proto_value_bool(equal));
                break;
            }
            case PROTO_OP_GREATER: {
                ProtoValue b = stack_pop(vm);
                ProtoValue a = stack_pop(vm);
                if (!ensure_number_operands(&a, &b, error, line)) {
                    proto_value_free(&a);
                    proto_value_free(&b);
                    return false;
                }
                stack_push(vm, proto_value_bool(a.as.number > b.as.number));
                proto_value_free(&a);
                proto_value_free(&b);
                break;
            }
            case PROTO_OP_LESS: {
                ProtoValue b = stack_pop(vm);
                ProtoValue a = stack_pop(vm);
                if (!ensure_number_operands(&a, &b, error, line)) {
                    proto_value_free(&a);
                    proto_value_free(&b);
                    return false;
                }
                stack_push(vm, proto_value_bool(a.as.number < b.as.number));
                proto_value_free(&a);
                proto_value_free(&b);
                break;
            }
            case PROTO_OP_PRINT: {
                ProtoValue value = stack_pop(vm);
                proto_value_free(&vm->last_print_value);
                vm->last_print_value = proto_value_copy(&value);
                proto_value_print(&value);
                printf("\n");
                proto_value_free(&value);
                break;
            }
            case PROTO_OP_POP: {
                ProtoValue value = stack_pop(vm);
                proto_value_free(&value);
                break;
            }
            case PROTO_OP_JUMP: {
                uint16_t offset = frame_read_short(frame);
                frame->ip += offset;
                break;
            }
            case PROTO_OP_JUMP_IF_FALSE: {
                uint16_t offset = frame_read_short(frame);
                ProtoValue *peek = stack_peek(vm, 0);
                if (is_falsey(peek)) {
                    frame->ip += offset;
                }
                break;
            }
            case PROTO_OP_LOOP: {
                uint16_t offset = frame_read_short(frame);
                frame->ip -= offset;
                break;
            }
            case PROTO_OP_CALL_NATIVE: {
                uint8_t native_index = frame_read_byte(frame);
                uint8_t arg_count = frame_read_byte(frame);
                if (!call_native(vm, native_index, arg_count, error)) {
                    return false;
                }
                break;
            }
            case PROTO_OP_CALL: {
                uint8_t arg_count = frame_read_byte(frame);
                ProtoValue *callee_ptr = stack_peek(vm, arg_count);
                ProtoValue callee = callee_ptr ? *callee_ptr : proto_value_null();
                if (!call_value(vm, callee, arg_count, error)) {
                    return false;
                }
                break;
            }
            case PROTO_OP_ALLOC_TYPED: {
                uint8_t type_code = frame_read_byte(frame);
                ProtoTypeTag type_tag = (ProtoTypeTag)type_code;
                ProtoValue count_value = stack_pop(vm);
                if (count_value.type != PROTO_VAL_NUMBER || count_value.as.number < 0) {
                    protoerror_set(error, line, "Typed memory allocation expects positive count");
                    proto_value_free(&count_value);
                    return false;
                }
                size_t count = (size_t)count_value.as.number;
                proto_value_free(&count_value);
                ProtoTypedMemory memory = proto_memory_allocate(type_tag, count);
                stack_push(vm, proto_value_memory(memory));
                break;
            }
            case PROTO_OP_STORE_TYPED: {
                uint8_t type_code = frame_read_byte(frame);
                ProtoTypeTag type_tag = (ProtoTypeTag)type_code;
                ProtoValue value = stack_pop(vm);
                ProtoValue index_value = stack_pop(vm);
                ProtoValue memory_value = stack_pop(vm);

                if (memory_value.type != PROTO_VAL_MEMORY) {
                    protoerror_set(error, line, "STORE expects memory reference");
                    proto_value_free(&value);
                    proto_value_free(&index_value);
                    proto_value_free(&memory_value);
                    return false;
                }
                if (index_value.type != PROTO_VAL_NUMBER || index_value.as.number < 0) {
                    protoerror_set(error, line, "STORE expects numeric index");
                    proto_value_free(&value);
                    proto_value_free(&index_value);
                    proto_value_free(&memory_value);
                    return false;
                }

                size_t index = (size_t)index_value.as.number;
                if (index >= memory_value.as.memory.count) {
                    protoerror_set(error, line, "Memory index out of range");
                    proto_value_free(&value);
                    proto_value_free(&index_value);
                    proto_value_free(&memory_value);
                    return false;
                }

                switch (type_tag) {
                    case PROTO_TYPE_NUM:
                        if (value.type != PROTO_VAL_NUMBER) {
                            protoerror_set(error, line, "Expected numeric value for num memory");
                            proto_value_free(&value);
                            proto_value_free(&index_value);
                            proto_value_free(&memory_value);
                            return false;
                        }
                        ((double *)memory_value.as.memory.data)[index] = value.as.number;
                        break;
                    case PROTO_TYPE_FLAG: {
                        bool flag = false;
                        if (value.type == PROTO_VAL_BOOL) {
                            flag = value.as.boolean;
                        } else if (value.type == PROTO_VAL_NUMBER) {
                            flag = value.as.number != 0.0;
                        } else {
                            protoerror_set(error, line, "Expected boolean or numeric for flag memory");
                            proto_value_free(&value);
                            proto_value_free(&index_value);
                            proto_value_free(&memory_value);
                            return false;
                        }
                        ((uint8_t *)memory_value.as.memory.data)[index] = flag ? 1u : 0u;
                        break;
                    }
                    case PROTO_TYPE_TEXT: {
                        char ch = 0;
                        if (value.type == PROTO_VAL_STRING && value.as.string && value.as.string[0] != '\0') {
                            ch = value.as.string[0];
                        } else if (value.type == PROTO_VAL_NUMBER) {
                            ch = (char)((int)value.as.number & 0xFF);
                        } else {
                            protoerror_set(error, line, "Expected text-compatible value");
                            proto_value_free(&value);
                            proto_value_free(&index_value);
                            proto_value_free(&memory_value);
                            return false;
                        }
                        ((char *)memory_value.as.memory.data)[index] = ch;
                        break;
                    }
                    case PROTO_TYPE_RAW:
                    case PROTO_TYPE_ANY:
                    case PROTO_TYPE_NONE:
                    default: {
                        uint8_t byte = 0;
                        if (value.type == PROTO_VAL_NUMBER) {
                            double v = value.as.number;
                            if (v < 0.0) {
                                v = 0.0;
                            }
                            if (v > 255.0) {
                                v = 255.0;
                            }
                            byte = (uint8_t)v;
                        } else if (value.type == PROTO_VAL_BOOL) {
                            byte = value.as.boolean ? 1u : 0u;
                        } else {
                            protoerror_set(error, line, "Expected numeric or boolean for raw memory");
                            proto_value_free(&value);
                            proto_value_free(&index_value);
                            proto_value_free(&memory_value);
                            return false;
                        }
                        ((uint8_t *)memory_value.as.memory.data)[index] = byte;
                        break;
                    }
                }

                proto_value_free(&value);
                proto_value_free(&index_value);
                stack_push(vm, memory_value);
                break;
            }
            case PROTO_OP_LOAD_TYPED: {
                uint8_t type_code = frame_read_byte(frame);
                ProtoTypeTag type_tag = (ProtoTypeTag)type_code;
                ProtoValue index_value = stack_pop(vm);
                ProtoValue memory_value = stack_pop(vm);

                if (memory_value.type != PROTO_VAL_MEMORY) {
                    protoerror_set(error, line, "LOAD expects memory reference");
                    proto_value_free(&index_value);
                    proto_value_free(&memory_value);
                    return false;
                }
                if (index_value.type != PROTO_VAL_NUMBER || index_value.as.number < 0) {
                    protoerror_set(error, line, "LOAD expects numeric index");
                    proto_value_free(&index_value);
                    proto_value_free(&memory_value);
                    return false;
                }

                size_t index = (size_t)index_value.as.number;
                if (index >= memory_value.as.memory.count) {
                    protoerror_set(error, line, "Memory index out of range");
                    proto_value_free(&index_value);
                    proto_value_free(&memory_value);
                    return false;
                }

                ProtoValue result = proto_value_null();
                switch (type_tag) {
                    case PROTO_TYPE_NUM:
                        result = proto_value_number(((double *)memory_value.as.memory.data)[index]);
                        break;
                    case PROTO_TYPE_FLAG:
                        result = proto_value_bool(((uint8_t *)memory_value.as.memory.data)[index] != 0u);
                        break;
                    case PROTO_TYPE_TEXT: {
                        char ch_buffer[2];
                        ch_buffer[0] = ((char *)memory_value.as.memory.data)[index];
                        ch_buffer[1] = '\0';
                        result = proto_value_string(ch_buffer, 1);
                        break;
                    }
                    case PROTO_TYPE_RAW:
                    case PROTO_TYPE_ANY:
                    case PROTO_TYPE_NONE:
                    default:
                        result = proto_value_number(((uint8_t *)memory_value.as.memory.data)[index]);
                        break;
                }

                proto_value_free(&index_value);
                proto_value_free(&memory_value);
                stack_push(vm, result);
                break;
            }
            case PROTO_OP_CLASS: {
                uint16_t name_index = frame_read_short(frame);
                if (name_index >= active_chunk->constants_count) {
                    protoerror_set(error, line, "Invalid class name constant index");
                    return false;
                }
                ProtoValue name_value = active_chunk->constants[name_index];
                if (name_value.type != PROTO_VAL_STRING || !name_value.as.string) {
                    protoerror_set(error, line, "Class name must be a string literal");
                    return false;
                }
                ProtoClass *klass = proto_class_new(name_value.as.string);
                ProtoValue class_value = proto_value_class(klass);
                proto_class_release(klass);
                stack_push(vm, class_value);
                break;
            }
            case PROTO_OP_METHOD: {
                uint16_t name_index = frame_read_short(frame);
                if (name_index >= active_chunk->constants_count) {
                    protoerror_set(error, line, "Invalid method name constant index");
                    return false;
                }
                ProtoValue name_value = active_chunk->constants[name_index];
                if (name_value.type != PROTO_VAL_STRING || !name_value.as.string) {
                    protoerror_set(error, line, "Method name must be a string literal");
                    return false;
                }
                ProtoValue method_value = stack_pop(vm);
                if (method_value.type != PROTO_VAL_FUNCTION) {
                    protoerror_set(error, line, "Method body must be a function");
                    proto_value_free(&method_value);
                    return false;
                }
                ProtoValue *class_value = stack_peek(vm, 0);
                if (!class_value || class_value->type != PROTO_VAL_CLASS) {
                    protoerror_set(error, line, "Method declaration missing class receiver");
                    proto_value_free(&method_value);
                    return false;
                }
                proto_class_add_method(class_value->as.klass, name_value.as.string, method_value.as.function);
                proto_value_free(&method_value);
                break;
            }
            case PROTO_OP_GET_PROPERTY: {
                uint16_t name_index = frame_read_short(frame);
                if (name_index >= active_chunk->constants_count) {
                    protoerror_set(error, line, "Invalid property name constant index");
                    return false;
                }
                ProtoValue name_value = active_chunk->constants[name_index];
                if (name_value.type != PROTO_VAL_STRING || !name_value.as.string) {
                    protoerror_set(error, line, "Property name must be a string literal");
                    return false;
                }
                ProtoValue receiver = stack_pop(vm);
                if (receiver.type != PROTO_VAL_INSTANCE) {
                    protoerror_set(error, line, "Only instances have properties");
                    proto_value_free(&receiver);
                    return false;
                }
                ProtoValue result;
                if (proto_instance_get_field(receiver.as.instance, name_value.as.string, &result)) {
                    proto_value_free(&receiver);
                    stack_push(vm, result);
                    break;
                }

                ProtoClass *klass = proto_instance_class(receiver.as.instance);
                ProtoFunction *method = proto_class_find_method(klass, name_value.as.string);
                if (!method) {
                    proto_value_free(&receiver);
                    protoerror_set(error, line, "Undefined property '%s'", name_value.as.string);
                    return false;
                }
                ProtoBoundMethod *bound = proto_bound_method_new(receiver.as.instance, method);
                proto_value_free(&receiver);
                if (!bound) {
                    protoerror_set(error, line, "Failed to bind method");
                    return false;
                }
                ProtoValue bound_value = proto_value_bound_method(bound);
                proto_bound_method_release(bound);
                stack_push(vm, bound_value);
                break;
            }
            case PROTO_OP_SET_PROPERTY: {
                uint16_t name_index = frame_read_short(frame);
                if (name_index >= active_chunk->constants_count) {
                    protoerror_set(error, line, "Invalid property name constant index");
                    return false;
                }
                ProtoValue name_value = active_chunk->constants[name_index];
                if (name_value.type != PROTO_VAL_STRING || !name_value.as.string) {
                    protoerror_set(error, line, "Property name must be a string literal");
                    return false;
                }
                ProtoValue value = stack_pop(vm);
                ProtoValue receiver = stack_pop(vm);
                if (receiver.type != PROTO_VAL_INSTANCE) {
                    protoerror_set(error, line, "Only instances have fields");
                    proto_value_free(&receiver);
                    proto_value_free(&value);
                    return false;
                }
                if (!proto_instance_set_field(receiver.as.instance, name_value.as.string, &value)) {
                    proto_value_free(&receiver);
                    proto_value_free(&value);
                    protoerror_set(error, line, "Failed to set property '%s'", name_value.as.string);
                    return false;
                }
                ProtoValue result = proto_value_copy(&value);
                proto_value_free(&receiver);
                proto_value_free(&value);
                stack_push(vm, result);
                break;
            }
            case PROTO_OP_RETURN: {
                const ProtoFunction *function = frame->function;
                ProtoValue result = proto_value_null();
                if (function && function->kind == PROTO_FUNC_INITIALIZER) {
                    if (vm->stack_top > frame->slots) {
                        ProtoValue temp = stack_pop(vm);
                        proto_value_free(&temp);
                    }
                    result = proto_value_copy(&frame->slots[0]);
                } else if (vm->stack_top > frame->slots) {
                    result = stack_pop(vm);
                }
                while (vm->stack_top > frame->slots) {
                    ProtoValue temp = stack_pop(vm);
                    proto_value_free(&temp);
                }
                vm->frame_count--;
                if (vm->frame_count == 0) {
                    proto_value_free(&result);
                    return true;
                }
                vm->stack_top = current_frame(vm)->slots;
                stack_push(vm, result);
                break;
            }
            default:
                protoerror_set(error, line, "Unknown opcode");
                return false;
        }
    }

    return true;
}

#if PROTOHACK_ENABLE_JIT
static bool protojit_execute_block(ProtoVM *vm, ProtoCallFrame *frame, ProtoChunk *chunk, ProtoJITIR *ir, ProtoError *error, ProtoOpCode *failed_opcode) {
    if (failed_opcode) {
        *failed_opcode = PROTO_OP_COUNT;
    }
    if (!vm || !frame || !chunk || !ir || !ir->supported || ir->count == 0u) {
        return false;
    }

    for (size_t i = 0; i < ir->count; ++i) {
        ProtoJITIROp *op = &ir->ops[i];
        size_t line = op->line;

    if (failed_opcode) {
        *failed_opcode = op->opcode;
    }

#if PROTOHACK_JIT_PROFILE
        protojit_profiler_count(&vm->profiler, op->opcode);
#endif

        switch (op->opcode) {
            case PROTO_OP_CONSTANT: {
                uint16_t index = op->operand_u16;
                if (index >= chunk->constants_count) {
                    protoerror_set(error, line, "Invalid constant index");
                    return false;
                }
                stack_push(vm, proto_value_copy(&chunk->constants[index]));
                break;
            }
            case PROTO_OP_TRUE:
                stack_push(vm, proto_value_bool(true));
                break;
            case PROTO_OP_FALSE:
                stack_push(vm, proto_value_bool(false));
                break;
            case PROTO_OP_NULL:
                stack_push(vm, proto_value_null());
                break;
            case PROTO_OP_GET_GLOBAL: {
                uint16_t slot = op->operand_u16;
                if (slot >= chunk->globals_count || !vm->globals_initialized[slot]) {
                    protoerror_set(error, line, "Undefined global");
                    return false;
                }
                stack_push(vm, proto_value_copy(&vm->globals[slot]));
                break;
            }
            case PROTO_OP_SET_GLOBAL: {
                uint16_t slot = op->operand_u16;
                if (slot >= chunk->globals_count) {
                    protoerror_set(error, line, "Invalid global index");
                    return false;
                }
                ProtoValue value = proto_value_copy(stack_peek(vm, 0));
                if (vm->globals_initialized[slot]) {
                    proto_value_free(&vm->globals[slot]);
                }
                vm->globals[slot] = value;
                vm->globals_initialized[slot] = true;
                if (slot + 1 > vm->globals_count) {
                    vm->globals_count = slot + 1;
                }
                break;
            }
            case PROTO_OP_GET_LOCAL: {
                uint8_t slot = op->operand_u8;
                stack_push(vm, proto_value_copy(&frame->slots[slot]));
                break;
            }
            case PROTO_OP_SET_LOCAL: {
                uint8_t slot = op->operand_u8;
                ProtoValue value = proto_value_copy(stack_peek(vm, 0));
                proto_value_free(&frame->slots[slot]);
                frame->slots[slot] = value;
                break;
            }
            case PROTO_OP_ADD: {
                ProtoValue b = stack_pop(vm);
                ProtoValue a = stack_pop(vm);
                if (a.type == PROTO_VAL_STRING || b.type == PROTO_VAL_STRING) {
                    char *left = proto_value_to_cstring(&a);
                    char *right = proto_value_to_cstring(&b);
                    size_t left_len = strlen(left);
                    size_t right_len = strlen(right);
                    char *concat = (char *)malloc(left_len + right_len + 1);
                    if (!concat) {
                        free(left);
                        free(right);
                        proto_value_free(&a);
                        proto_value_free(&b);
                        PROTOHACK_FATAL("Out of memory");
                    }
                    memcpy(concat, left, left_len);
                    memcpy(concat + left_len, right, right_len);
                    concat[left_len + right_len] = '\0';
                    ProtoValue result = proto_value_string(concat, left_len + right_len);
                    free(concat);
                    free(left);
                    free(right);
                    proto_value_free(&a);
                    proto_value_free(&b);
                    stack_push(vm, result);
                } else {
                    if (!ensure_number_operands(&a, &b, error, line)) {
                        proto_value_free(&a);
                        proto_value_free(&b);
                        return false;
                    }
                    double sum = a.as.number + b.as.number;
                    proto_value_free(&a);
                    proto_value_free(&b);
                    stack_push(vm, proto_value_number(sum));
                }
                break;
            }
            case PROTO_OP_SUB: {
                ProtoValue b = stack_pop(vm);
                ProtoValue a = stack_pop(vm);
                if (!ensure_number_operands(&a, &b, error, line)) {
                    proto_value_free(&a);
                    proto_value_free(&b);
                    return false;
                }
                double diff = a.as.number - b.as.number;
                proto_value_free(&a);
                proto_value_free(&b);
                stack_push(vm, proto_value_number(diff));
                break;
            }
            case PROTO_OP_MUL: {
                ProtoValue b = stack_pop(vm);
                ProtoValue a = stack_pop(vm);
                if (!ensure_number_operands(&a, &b, error, line)) {
                    proto_value_free(&a);
                    proto_value_free(&b);
                    return false;
                }
                double prod = a.as.number * b.as.number;
                proto_value_free(&a);
                proto_value_free(&b);
                stack_push(vm, proto_value_number(prod));
                break;
            }
            case PROTO_OP_DIV: {
                ProtoValue b = stack_pop(vm);
                ProtoValue a = stack_pop(vm);
                if (!ensure_number_operands(&a, &b, error, line)) {
                    proto_value_free(&a);
                    proto_value_free(&b);
                    return false;
                }
                double quotient = a.as.number / b.as.number;
                proto_value_free(&a);
                proto_value_free(&b);
                stack_push(vm, proto_value_number(quotient));
                break;
            }
            case PROTO_OP_NEGATE: {
                ProtoValue value = stack_pop(vm);
                if (value.type != PROTO_VAL_NUMBER) {
                    if (error && error->ok) {
                        protoerror_set(error, line, "Operand must be a number");
                    }
                    proto_value_free(&value);
                    return false;
                }
                double result = -value.as.number;
                proto_value_free(&value);
                stack_push(vm, proto_value_number(result));
                break;
            }
            case PROTO_OP_NOT: {
                ProtoValue value = stack_pop(vm);
                bool truth = is_falsey(&value);
                proto_value_free(&value);
                stack_push(vm, proto_value_bool(truth));
                break;
            }
            case PROTO_OP_EQUAL: {
                ProtoValue b = stack_pop(vm);
                ProtoValue a = stack_pop(vm);
                bool equal = proto_value_equal(&a, &b);
                proto_value_free(&a);
                proto_value_free(&b);
                stack_push(vm, proto_value_bool(equal));
                break;
            }
            case PROTO_OP_GREATER: {
                ProtoValue b = stack_pop(vm);
                ProtoValue a = stack_pop(vm);
                if (!ensure_number_operands(&a, &b, error, line)) {
                    proto_value_free(&a);
                    proto_value_free(&b);
                    return false;
                }
                bool cmp = a.as.number > b.as.number;
                proto_value_free(&a);
                proto_value_free(&b);
                stack_push(vm, proto_value_bool(cmp));
                break;
            }
            case PROTO_OP_LESS: {
                ProtoValue b = stack_pop(vm);
                ProtoValue a = stack_pop(vm);
                if (!ensure_number_operands(&a, &b, error, line)) {
                    proto_value_free(&a);
                    proto_value_free(&b);
                    return false;
                }
                bool cmp = a.as.number < b.as.number;
                proto_value_free(&a);
                proto_value_free(&b);
                stack_push(vm, proto_value_bool(cmp));
                break;
            }
            case PROTO_OP_POP: {
                ProtoValue value = stack_pop(vm);
                proto_value_free(&value);
                break;
            }
            case PROTO_OP_ALLOC_TYPED: {
                ProtoTypeTag type_tag = (ProtoTypeTag)op->operand_u8;
                ProtoValue count_value = stack_pop(vm);
                if (count_value.type != PROTO_VAL_NUMBER || count_value.as.number < 0) {
                    protoerror_set(error, line, "Typed memory allocation expects positive count");
                    proto_value_free(&count_value);
                    return false;
                }
                size_t count = (size_t)count_value.as.number;
                proto_value_free(&count_value);
                ProtoTypedMemory memory = proto_memory_allocate(type_tag, count);
                stack_push(vm, proto_value_memory(memory));
                break;
            }
            case PROTO_OP_STORE_TYPED: {
                ProtoTypeTag type_tag = (ProtoTypeTag)op->operand_u8;
                ProtoValue value = stack_pop(vm);
                ProtoValue index_value = stack_pop(vm);
                ProtoValue memory_value = stack_pop(vm);

                if (memory_value.type != PROTO_VAL_MEMORY) {
                    protoerror_set(error, line, "STORE expects memory reference");
                    proto_value_free(&value);
                    proto_value_free(&index_value);
                    proto_value_free(&memory_value);
                    return false;
                }
                if (index_value.type != PROTO_VAL_NUMBER || index_value.as.number < 0) {
                    protoerror_set(error, line, "STORE expects numeric index");
                    proto_value_free(&value);
                    proto_value_free(&index_value);
                    proto_value_free(&memory_value);
                    return false;
                }

                size_t index = (size_t)index_value.as.number;
                if (index >= memory_value.as.memory.count) {
                    protoerror_set(error, line, "Memory index out of range");
                    proto_value_free(&value);
                    proto_value_free(&index_value);
                    proto_value_free(&memory_value);
                    return false;
                }

                switch (type_tag) {
                    case PROTO_TYPE_NUM:
                        if (value.type != PROTO_VAL_NUMBER) {
                            protoerror_set(error, line, "Expected numeric value for num memory");
                            proto_value_free(&value);
                            proto_value_free(&index_value);
                            proto_value_free(&memory_value);
                            return false;
                        }
                        ((double *)memory_value.as.memory.data)[index] = value.as.number;
                        break;
                    case PROTO_TYPE_FLAG: {
                        bool flag = false;
                        if (value.type == PROTO_VAL_BOOL) {
                            flag = value.as.boolean;
                        } else if (value.type == PROTO_VAL_NUMBER) {
                            flag = value.as.number != 0.0;
                        } else {
                            protoerror_set(error, line, "Expected boolean or numeric for flag memory");
                            proto_value_free(&value);
                            proto_value_free(&index_value);
                            proto_value_free(&memory_value);
                            return false;
                        }
                        ((uint8_t *)memory_value.as.memory.data)[index] = flag ? 1u : 0u;
                        break;
                    }
                    case PROTO_TYPE_TEXT: {
                        char ch = 0;
                        if (value.type == PROTO_VAL_STRING && value.as.string && value.as.string[0] != '\0') {
                            ch = value.as.string[0];
                        } else if (value.type == PROTO_VAL_NUMBER) {
                            ch = (char)((int)value.as.number & 0xFF);
                        } else {
                            protoerror_set(error, line, "Expected text-compatible value");
                            proto_value_free(&value);
                            proto_value_free(&index_value);
                            proto_value_free(&memory_value);
                            return false;
                        }
                        ((char *)memory_value.as.memory.data)[index] = ch;
                        break;
                    }
                    case PROTO_TYPE_RAW:
                    case PROTO_TYPE_ANY:
                    case PROTO_TYPE_NONE:
                    default: {
                        uint8_t byte = 0;
                        if (value.type == PROTO_VAL_NUMBER) {
                            double v = value.as.number;
                            if (v < 0.0) {
                                v = 0.0;
                            }
                            if (v > 255.0) {
                                v = 255.0;
                            }
                            byte = (uint8_t)v;
                        } else if (value.type == PROTO_VAL_BOOL) {
                            byte = value.as.boolean ? 1u : 0u;
                        } else {
                            protoerror_set(error, line, "Expected numeric or boolean for raw memory");
                            proto_value_free(&value);
                            proto_value_free(&index_value);
                            proto_value_free(&memory_value);
                            return false;
                        }
                        ((uint8_t *)memory_value.as.memory.data)[index] = byte;
                        break;
                    }
                }

                proto_value_free(&value);
                proto_value_free(&index_value);
                stack_push(vm, memory_value);
                break;
            }
            case PROTO_OP_LOAD_TYPED: {
                ProtoTypeTag type_tag = (ProtoTypeTag)op->operand_u8;
                ProtoValue index_value = stack_pop(vm);
                ProtoValue memory_value = stack_pop(vm);

                if (memory_value.type != PROTO_VAL_MEMORY) {
                    protoerror_set(error, line, "LOAD expects memory reference");
                    proto_value_free(&index_value);
                    proto_value_free(&memory_value);
                    return false;
                }
                if (index_value.type != PROTO_VAL_NUMBER || index_value.as.number < 0) {
                    protoerror_set(error, line, "LOAD expects numeric index");
                    proto_value_free(&index_value);
                    proto_value_free(&memory_value);
                    return false;
                }

                size_t index = (size_t)index_value.as.number;
                if (index >= memory_value.as.memory.count) {
                    protoerror_set(error, line, "Memory index out of range");
                    proto_value_free(&index_value);
                    proto_value_free(&memory_value);
                    return false;
                }

                ProtoValue result = proto_value_null();
                switch (type_tag) {
                    case PROTO_TYPE_NUM:
                        result = proto_value_number(((double *)memory_value.as.memory.data)[index]);
                        break;
                    case PROTO_TYPE_FLAG:
                        result = proto_value_bool(((uint8_t *)memory_value.as.memory.data)[index] != 0u);
                        break;
                    case PROTO_TYPE_TEXT: {
                        char ch_buffer[2];
                        ch_buffer[0] = ((char *)memory_value.as.memory.data)[index];
                        ch_buffer[1] = '\0';
                        result = proto_value_string(ch_buffer, 1);
                        break;
                    }
                    case PROTO_TYPE_RAW:
                    case PROTO_TYPE_ANY:
                    case PROTO_TYPE_NONE:
                    default:
                        result = proto_value_number(((uint8_t *)memory_value.as.memory.data)[index]);
                        break;
                }

                proto_value_free(&index_value);
                proto_value_free(&memory_value);
                stack_push(vm, result);
                break;
            }
            case PROTO_OP_RETURN: {
                ProtoValue result = proto_value_null();
                if (vm->stack_top > frame->slots) {
                    result = stack_pop(vm);
                }
                while (vm->stack_top > frame->slots) {
                    ProtoValue temp = stack_pop(vm);
                    proto_value_free(&temp);
                }
                vm->frame_count--;
                if (vm->frame_count == 0) {
                    proto_value_free(&result);
                    if (failed_opcode) {
                        *failed_opcode = PROTO_OP_COUNT;
                    }
                    return true;
                }
                vm->stack_top = current_frame(vm)->slots;
                stack_push(vm, result);
                if (failed_opcode) {
                    *failed_opcode = PROTO_OP_COUNT;
                }
                return true;
            }
            case PROTO_OP_PRINT: {
                ProtoValue value = stack_pop(vm);
                proto_value_free(&vm->last_print_value);
                vm->last_print_value = proto_value_copy(&value);
                proto_value_print(&value);
                printf("\n");
                proto_value_free(&value);
                break;
            }
            default:
                return false;
        }

        if (failed_opcode) {
            *failed_opcode = PROTO_OP_COUNT;
        }
    }

    frame->ip = ir->end_offset;
    return true;
}

static int protojit_try_dispatch_block(ProtoVM *vm, ProtoCallFrame *frame, ProtoChunk *chunk, ProtoError *error) {
    if (!vm || !frame || !chunk || frame->ip >= chunk->code_count) {
        return 0;
    }

    protojit_profiler_block_attempt(&vm->profiler);

    ProtoJITIR *ir = protojit_ir_get_or_build(chunk, frame->ip);
    if (!ir || !ir->supported || ir->count == 0u) {
        ProtoOpCode opcode = (ir && !ir->supported) ? ir->bailout_opcode : PROTO_OP_COUNT;
        protojit_profiler_block_bailout_unsupported(&vm->profiler, opcode);
        return 0;
    }

    size_t original_ip = frame->ip;
    ProtoOpCode failed_opcode = PROTO_OP_COUNT;
    if (!protojit_execute_block(vm, frame, chunk, ir, error, &failed_opcode)) {
        frame->ip = original_ip;
        protojit_profiler_block_bailout_runtime(&vm->profiler, failed_opcode);
        if (error && !error->ok) {
            return -1;
        }
        return 0;
    }

    protojit_profiler_block_hit(&vm->profiler);
    return 1;
}
#endif

#if PROTOHACK_ENABLE_JIT
const ProtoJITProfiler *protovm_profiler(const ProtoVM *vm) {
    if (!vm) {
        return NULL;
    }
    return &vm->profiler;
}

void protovm_profiler_reset(ProtoVM *vm) {
    if (!vm) {
        return;
    }
    protojit_profiler_reset(&vm->profiler);
}
#endif
