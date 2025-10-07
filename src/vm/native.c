#include "protohack/native.h"

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "protohack/error.h"
#include "protohack/internal/common.h"
#include "protohack/value.h"
#include "protohack/vm.h"

static uint32_t rand_next(uint32_t state) {
    return state * 1664525u + 1013904223u;
}

static bool native_clock(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    (void)args;
    (void)arg_count;
    (void)error;
    double seconds = (double)clock() / (double)CLOCKS_PER_SEC;
    *result = proto_value_number(seconds);
    return true;
}

static bool native_rand(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)error;
    vm->rand_state = rand_next(vm->rand_state);
    double rnd = (double)vm->rand_state / 4294967295.0;
    if (arg_count == 1) {
        if (args[0].type != PROTO_VAL_NUMBER) {
            return false;
        }
        double max = args[0].as.number;
        rnd = floor(rnd * max);
    }
    *result = proto_value_number(rnd);
    return true;
}

static bool native_sqrt(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    (void)arg_count;
    if (args[0].type != PROTO_VAL_NUMBER) {
        if (error && error->ok) {
            protoerror_set(error, 0, "sqrt expects a number");
        }
        return false;
    }
    if (args[0].as.number < 0.0) {
        if (error && error->ok) {
            protoerror_set(error, 0, "sqrt domain error");
        }
        return false;
    }
    *result = proto_value_number(sqrt(args[0].as.number));
    return true;
}

static bool native_pow(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    (void)arg_count;
    if (args[0].type != PROTO_VAL_NUMBER || args[1].type != PROTO_VAL_NUMBER) {
        if (error && error->ok) {
            protoerror_set(error, 0, "pow expects two numbers");
        }
        return false;
    }
    *result = proto_value_number(pow(args[0].as.number, args[1].as.number));
    return true;
}

static bool native_len(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    (void)arg_count;
    (void)error;
    size_t length = 0;
    switch (args[0].type) {
        case PROTO_VAL_STRING:
            length = args[0].as.string ? strlen(args[0].as.string) : 0;
            break;
        case PROTO_VAL_NULL:
            length = 0;
            break;
        case PROTO_VAL_BOOL:
            length = args[0].as.boolean ? 1 : 0;
            break;
        case PROTO_VAL_NUMBER: {
            char buffer[64];
            int written = snprintf(buffer, sizeof buffer, "%.10g", args[0].as.number);
            if (written > 0) {
                length = (size_t)written;
            }
            break;
        }
        default:
            length = 0;
            break;
    }
    *result = proto_value_number((double)length);
    return true;
}

static bool native_to_string(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    (void)arg_count;
    (void)error;
    char *text = proto_value_to_cstring(&args[0]);
    size_t length = strlen(text);
    *result = proto_value_string(text, length);
    free(text);
    return true;
}

static bool native_upper(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    (void)arg_count;
    if (args[0].type != PROTO_VAL_STRING || !args[0].as.string) {
        if (error && error->ok) {
            protoerror_set(error, 0, "upper expects a string");
        }
        return false;
    }
    size_t length = strlen(args[0].as.string);
    char *buffer = protohack_copy_string(args[0].as.string, length);
    for (size_t i = 0; i < length; ++i) {
        buffer[i] = (char)toupper((unsigned char)buffer[i]);
    }
    *result = proto_value_string(buffer, length);
    free(buffer);
    return true;
}

static bool native_lower(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    (void)arg_count;
    if (args[0].type != PROTO_VAL_STRING || !args[0].as.string) {
        if (error && error->ok) {
            protoerror_set(error, 0, "lower expects a string");
        }
        return false;
    }
    size_t length = strlen(args[0].as.string);
    char *buffer = protohack_copy_string(args[0].as.string, length);
    for (size_t i = 0; i < length; ++i) {
        buffer[i] = (char)tolower((unsigned char)buffer[i]);
    }
    *result = proto_value_string(buffer, length);
    free(buffer);
    return true;
}

static bool native_println(ProtoVM *vm, const ProtoValue *args, uint8_t arg_count, ProtoValue *result, ProtoError *error) {
    (void)vm;
    (void)error;
    for (uint8_t i = 0; i < arg_count; ++i) {
        if (i > 0) {
            printf(" ");
        }
        proto_value_print(&args[i]);
    }
    printf("\n");
    *result = proto_value_null();
    return true;
}

static const ProtoNativeEntry kNativeTable[] = {
    {"clock", native_clock, 0, 0},
    {"rand", native_rand, 0, 1},
    {"sqrt", native_sqrt, 1, 1},
    {"pow", native_pow, 2, 2},
    {"len", native_len, 1, 1},
    {"to_string", native_to_string, 1, 1},
    {"upper", native_upper, 1, 1},
    {"lower", native_lower, 1, 1},
    {"println", native_println, 0, PROTOHACK_MAX_NATIVE_ARGS},
    {NULL, NULL, 0, 0}
};

const ProtoNativeEntry *protonative_table(void) {
    return kNativeTable;
}

size_t protonative_count(void) {
    size_t count = 0;
    while (kNativeTable[count].name) {
        ++count;
    }
    return count;
}

const ProtoNativeEntry *protonative_resolve(const char *name) {
    if (!name) {
        return NULL;
    }
    for (size_t i = 0; kNativeTable[i].name; ++i) {
        if (strcmp(kNativeTable[i].name, name) == 0) {
            return &kNativeTable[i];
        }
    }
    return NULL;
}

int protonative_index(const char *name) {
    if (!name) {
        return -1;
    }
    for (size_t i = 0; kNativeTable[i].name; ++i) {
        if (strcmp(kNativeTable[i].name, name) == 0) {
            return (int)i;
        }
    }
    return -1;
}
