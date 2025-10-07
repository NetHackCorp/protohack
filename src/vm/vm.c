#include "protohack/vm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "protohack/error.h"
#include "protohack/internal/common.h"
#include "protohack/native.h"
#include "protohack/opcode.h"
#include "protohack/typed_memory.h"
#include "protohack/value.h"
#include "protohack/object.h"
#include "protohack/jit_ir.h"

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
    return *vm->stack_top;
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

static bool call_function(ProtoVM *vm, const ProtoFunction *function, uint8_t arg_count, ProtoError *error) {
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
    return true;
}

static bool call_value(ProtoVM *vm, ProtoValue callee, uint8_t arg_count, ProtoError *error) {
    ProtoValue *callee_slot = stack_peek(vm, arg_count);
    if (!callee_slot) {
        protoerror_set(error, 0, "Invalid call target");
        return false;
    }

    switch (callee.type) {
        case PROTO_VAL_FUNCTION:
            return call_function(vm, callee.as.function, arg_count, error);
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
                return call_function(vm, initializer, arg_count, error);
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

            bool ok = call_function(vm, method, arg_count, error);
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
    for (size_t i = 0; i < PROTOHACK_MAX_GLOBALS; ++i) {
        vm->globals[i] = proto_value_null();
        vm->globals_initialized[i] = false;
    }
    vm->globals_count = 0;
    vm->last_print_value = proto_value_null();
#if PROTOHACK_ENABLE_JIT
    protojit_profiler_init(&vm->profiler);
#endif
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

    for (size_t i = 0; i < vm->globals_count; ++i) {
        if (vm->globals_initialized[i]) {
            proto_value_free(&vm->globals[i]);
            vm->globals_initialized[i] = false;
        }
    }
    vm->globals_count = 0;

    proto_value_free(&vm->last_print_value);
    vm->last_print_value = proto_value_null();
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
        .slots = vm->stack
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
