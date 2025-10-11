#include "protohack/value.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protohack/internal/common.h"
#include "protohack/function.h"

ProtoValue proto_value_null(void) {
    ProtoValue value;
    value.type = PROTO_VAL_NULL;
    value.as.string = NULL;
    return value;
}

ProtoValue proto_value_number(double number) {
    ProtoValue value;
    value.type = PROTO_VAL_NUMBER;
    value.as.number = number;
    return value;
}

ProtoValue proto_value_bool(bool boolean) {
    ProtoValue value;
    value.type = PROTO_VAL_BOOL;
    value.as.boolean = boolean;
    return value;
}

ProtoValue proto_value_string(const char *data, size_t length) {
    ProtoValue value;
    value.type = PROTO_VAL_STRING;
    value.as.string = protohack_copy_string(data ? data : "", data ? length : 0);
    return value;
}

ProtoValue proto_value_function(ProtoFunction *function) {
    ProtoValue value;
    value.type = PROTO_VAL_FUNCTION;
    value.as.function = function;
    return value;
}

ProtoValue proto_value_class(ProtoClass *klass) {
    ProtoValue value;
    value.type = PROTO_VAL_CLASS;
    value.as.klass = klass;
    proto_class_retain(klass);
    return value;
}

ProtoValue proto_value_instance(ProtoInstance *instance) {
    ProtoValue value;
    value.type = PROTO_VAL_INSTANCE;
    value.as.instance = instance;
    proto_instance_retain(instance);
    return value;
}

ProtoValue proto_value_bound_method(ProtoBoundMethod *bound) {
    ProtoValue value;
    value.type = PROTO_VAL_BOUND_METHOD;
    value.as.bound_method = bound;
    proto_bound_method_retain(bound);
    return value;
}

ProtoValue proto_value_memory(ProtoTypedMemory memory) {
    ProtoValue value;
    value.type = PROTO_VAL_MEMORY;
    value.as.memory = memory;
    return value;
}

ProtoValue proto_value_pointer(ProtoPointer pointer) {
    ProtoValue value;
    value.type = PROTO_VAL_POINTER;
    value.as.pointer = pointer;
    return value;
}

ProtoValue proto_value_copy(const ProtoValue *value) {
    if (!value) {
        return proto_value_null();
    }
    switch (value->type) {
        case PROTO_VAL_NULL:
            return proto_value_null();
        case PROTO_VAL_NUMBER:
            return proto_value_number(value->as.number);
        case PROTO_VAL_BOOL:
            return proto_value_bool(value->as.boolean);
        case PROTO_VAL_STRING: {
            const char *string = value->as.string ? value->as.string : "";
            return proto_value_string(string, strlen(string));
        }
        case PROTO_VAL_FUNCTION:
            return proto_value_function(value->as.function);
        case PROTO_VAL_CLASS:
            return proto_value_class(value->as.klass);
        case PROTO_VAL_INSTANCE:
            return proto_value_instance(value->as.instance);
        case PROTO_VAL_BOUND_METHOD:
            return proto_value_bound_method(value->as.bound_method);
        case PROTO_VAL_MEMORY:
            return proto_value_memory(proto_memory_clone(&value->as.memory));
        case PROTO_VAL_POINTER:
            return proto_value_pointer(value->as.pointer);
        default:
            return proto_value_null();
    }
}

void proto_value_free(ProtoValue *value) {
    if (!value) {
        return;
    }
    switch (value->type) {
        case PROTO_VAL_STRING:
            free(value->as.string);
            value->as.string = NULL;
            break;
        case PROTO_VAL_MEMORY:
            proto_memory_free(&value->as.memory);
            break;
        case PROTO_VAL_POINTER:
            /* pointers do not own their targets */
            break;
        case PROTO_VAL_CLASS:
            proto_class_release(value->as.klass);
            value->as.klass = NULL;
            break;
        case PROTO_VAL_INSTANCE:
            proto_instance_release(value->as.instance);
            value->as.instance = NULL;
            break;
        case PROTO_VAL_BOUND_METHOD:
            proto_bound_method_release(value->as.bound_method);
            value->as.bound_method = NULL;
            break;
        default:
            break;
    }
    value->type = PROTO_VAL_NULL;
}

bool proto_value_equal(const ProtoValue *a, const ProtoValue *b) {
    if (!a || !b) {
        return false;
    }
    if (a->type != b->type) {
        return false;
    }
    switch (a->type) {
        case PROTO_VAL_NULL:
            return true;
        case PROTO_VAL_NUMBER:
            return a->as.number == b->as.number;
        case PROTO_VAL_BOOL:
            return a->as.boolean == b->as.boolean;
        case PROTO_VAL_STRING:
            if (!a->as.string || !b->as.string) {
                return false;
            }
            return strcmp(a->as.string, b->as.string) == 0;
        case PROTO_VAL_FUNCTION:
            return a->as.function == b->as.function;
        case PROTO_VAL_CLASS:
            return a->as.klass == b->as.klass;
        case PROTO_VAL_INSTANCE:
            return a->as.instance == b->as.instance;
        case PROTO_VAL_BOUND_METHOD:
            return a->as.bound_method == b->as.bound_method;
        case PROTO_VAL_MEMORY:
            if (a->as.memory.element_type != b->as.memory.element_type || a->as.memory.count != b->as.memory.count) {
                return false;
            }
            if (!a->as.memory.data || !b->as.memory.data) {
                return a->as.memory.data == b->as.memory.data;
            }
            size_t element_size = 0;
            switch (a->as.memory.element_type) {
                case PROTO_TYPE_NUM:
                    element_size = sizeof(double);
                    break;
                case PROTO_TYPE_FLAG:
                    element_size = sizeof(uint8_t);
                    break;
                case PROTO_TYPE_TEXT:
                    element_size = sizeof(char);
                    break;
                case PROTO_TYPE_RAW:
                case PROTO_TYPE_ANY:
                case PROTO_TYPE_NONE:
                default:
                    element_size = sizeof(uint8_t);
                    break;
            }
            return memcmp(a->as.memory.data, b->as.memory.data, a->as.memory.count * element_size) == 0;
        case PROTO_VAL_POINTER: {
            const ProtoPointer *pa = &a->as.pointer;
            const ProtoPointer *pb = &b->as.pointer;
            if (pa->kind != pb->kind || pa->is_const != pb->is_const) {
                return false;
            }
            switch (pa->kind) {
                case PROTO_POINTER_STACK:
                    return pa->as.stack.slot == pb->as.stack.slot && pa->as.stack.generation == pb->as.stack.generation;
                case PROTO_POINTER_GLOBAL:
                    return pa->as.global.slot == pb->as.global.slot && pa->as.global.index == pb->as.global.index;
                default:
                    return false;
            }
        }
        default:
            return false;
    }
}

void proto_value_print(const ProtoValue *value) {
    switch (value->type) {
        case PROTO_VAL_NULL:
            printf("null");
            break;
        case PROTO_VAL_NUMBER:
            printf("%.10g", value->as.number);
            break;
        case PROTO_VAL_BOOL:
            printf(value->as.boolean ? "true" : "false");
            break;
        case PROTO_VAL_STRING:
            printf("%s", value->as.string ? value->as.string : "");
            break;
        case PROTO_VAL_FUNCTION: {
                char *description = proto_function_debug_description(value->as.function);
                if (description) {
                    printf("%s", description);
                    free(description);
                } else {
                    printf("<craft>");
                }
            break;
        }
        case PROTO_VAL_CLASS: {
            const char *name = proto_class_name(value->as.klass);
            printf("<class %s>", name ? name : "");
            break;
        }
        case PROTO_VAL_INSTANCE: {
            const char *name = proto_class_name(proto_instance_class(value->as.instance));
            printf("<%s instance>", name ? name : "");
            break;
        }
        case PROTO_VAL_BOUND_METHOD: {
            ProtoFunction *method = proto_bound_method_function(value->as.bound_method);
            ProtoInstance *instance = proto_bound_method_receiver(value->as.bound_method);
            const char *class_name = proto_class_name(proto_instance_class(instance));
            const char *method_name = method && method->name ? method->name : "<anonymous>";
            printf("<bound %s.%s>", class_name ? class_name : "", method_name);
            break;
        }
        case PROTO_VAL_MEMORY: {
            const char *type_name = proto_type_tag_name(value->as.memory.element_type);
            printf("<memory %s[%zu]>", type_name, value->as.memory.count);
            break;
        }
        case PROTO_VAL_POINTER: {
            const ProtoPointer *pointer = &value->as.pointer;
            const char *kind = pointer->kind == PROTO_POINTER_GLOBAL ? "global" : "stack";
            void *address = pointer->kind == PROTO_POINTER_GLOBAL ? (void *)pointer->as.global.slot : (void *)pointer->as.stack.slot;
            printf("<ptr %s%s %p>", kind, pointer->is_const ? " const" : "", address);
            break;
        }
        default:
            printf("<unknown>");
            break;
    }
}

char *proto_value_to_cstring(const ProtoValue *value) {
    if (!value) {
        return protohack_copy_string("null", 4);
    }
    char buffer[128];
    switch (value->type) {
        case PROTO_VAL_NULL:
            return protohack_copy_string("null", 4);
        case PROTO_VAL_BOOL:
            return protohack_copy_string(value->as.boolean ? "true" : "false", value->as.boolean ? 4 : 5);
        case PROTO_VAL_NUMBER: {
            int written = snprintf(buffer, sizeof buffer, "%.10g", value->as.number);
            if (written < 0) {
                return protohack_copy_string("0", 1);
            }
            return protohack_copy_string(buffer, (size_t)written);
        }
        case PROTO_VAL_STRING:
            if (!value->as.string) {
                return protohack_copy_string("", 0);
            }
            return protohack_copy_string(value->as.string, strlen(value->as.string));
        case PROTO_VAL_FUNCTION: {
                char *description = proto_function_debug_description(value->as.function);
                if (!description) {
                    return protohack_copy_string("<craft>", 7);
                }
                return description;
        }
        case PROTO_VAL_CLASS: {
            char buffer[64];
            const char *name = proto_class_name(value->as.klass);
            int written = snprintf(buffer, sizeof buffer, "<class %s>", name ? name : "");
            if (written < 0) {
                return protohack_copy_string("<class>", 7);
            }
            return protohack_copy_string(buffer, (size_t)written);
        }
        case PROTO_VAL_INSTANCE: {
            char buffer[64];
            const char *name = proto_class_name(proto_instance_class(value->as.instance));
            int written = snprintf(buffer, sizeof buffer, "<%s instance>", name ? name : "");
            if (written < 0) {
                return protohack_copy_string("<instance>", 10);
            }
            return protohack_copy_string(buffer, (size_t)written);
        }
        case PROTO_VAL_BOUND_METHOD: {
            char buffer[96];
            ProtoFunction *method = proto_bound_method_function(value->as.bound_method);
            ProtoInstance *instance = proto_bound_method_receiver(value->as.bound_method);
            const char *class_name = proto_class_name(proto_instance_class(instance));
            const char *method_name = method && method->name ? method->name : "<anonymous>";
            int written = snprintf(buffer, sizeof buffer, "<bound %s.%s>", class_name ? class_name : "", method_name);
            if (written < 0) {
                return protohack_copy_string("<bound>", 7);
            }
            return protohack_copy_string(buffer, (size_t)written);
        }
        case PROTO_VAL_MEMORY: {
            char buffer[64];
            const char *type_name = proto_type_tag_name(value->as.memory.element_type);
            int written = snprintf(buffer, sizeof buffer, "<memory %s[%zu]>", type_name, value->as.memory.count);
            if (written < 0) {
                return protohack_copy_string("<memory>", 8);
            }
            return protohack_copy_string(buffer, (size_t)written);
        }
        case PROTO_VAL_POINTER: {
            char buffer[64];
            const ProtoPointer *pointer = &value->as.pointer;
            const char *kind = pointer->kind == PROTO_POINTER_GLOBAL ? "global" : "stack";
            void *address = pointer->kind == PROTO_POINTER_GLOBAL ? (void *)pointer->as.global.slot : (void *)pointer->as.stack.slot;
            int written = snprintf(buffer, sizeof buffer, "<ptr %s%s %p>", kind, pointer->is_const ? " const" : "", address);
            if (written < 0) {
                return protohack_copy_string("<ptr>", 5);
            }
            return protohack_copy_string(buffer, (size_t)written);
        }
        default:
            return protohack_copy_string("<unknown>", 9);
    }
}
