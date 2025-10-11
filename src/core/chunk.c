#include "protohack/chunk.h"

#include <stdlib.h>
#include <string.h>

#include "protohack/internal/common.h"
#include "protohack/function.h"
#include "protohack/serialize.h"
#if PROTOHACK_ENABLE_JIT
#include "protohack/jit_ir.h"
#endif

#if PROTOHACK_ENABLE_JIT
static void protochunk_free_jit_cache(ProtoChunk *chunk) {
    if (!chunk || !chunk->jit_cache) {
        return;
    }
    for (size_t i = 0; i < chunk->jit_cache_count; ++i) {
        if (chunk->jit_cache[i]) {
            protojit_ir_free(chunk->jit_cache[i]);
        }
    }
    free(chunk->jit_cache);
    chunk->jit_cache = NULL;
    chunk->jit_cache_count = 0;
}
#endif

void protochunk_init(ProtoChunk *chunk) {
    if (!chunk) {
        return;
    }
    chunk->code = NULL;
    chunk->code_count = 0;
    chunk->code_capacity = 0;

    chunk->constants = NULL;
    chunk->constants_count = 0;
    chunk->constants_capacity = 0;

    chunk->globals = NULL;
    chunk->globals_count = 0;
    chunk->globals_capacity = 0;

    chunk->lines = NULL;
    chunk->lines_count = 0;
    chunk->lines_capacity = 0;

    chunk->binding_entries = NULL;
    chunk->binding_entry_count = 0;
    chunk->binding_entry_capacity = 0;

    chunk->module_version = PROTOHACK_MODULE_VERSION;
    chunk->module_flags = 0;

    chunk->extensions = NULL;
    chunk->extension_count = 0;
    chunk->extension_capacity = 0;

#if PROTOHACK_ENABLE_JIT
    chunk->jit_cache = NULL;
    chunk->jit_cache_count = 0;
#endif
}

void protochunk_free(ProtoChunk *chunk) {
    if (!chunk) {
        return;
    }

    free(chunk->code);
    chunk->code = NULL;
    chunk->code_count = 0;
    chunk->code_capacity = 0;

    if (chunk->constants) {
        for (size_t i = 0; i < chunk->constants_count; ++i) {
            if (chunk->constants[i].type == PROTO_VAL_FUNCTION && chunk->constants[i].as.function) {
                proto_function_free(chunk->constants[i].as.function);
                chunk->constants[i].as.function = NULL;
            }
            proto_value_free(&chunk->constants[i]);
        }
    }
    free(chunk->constants);
    chunk->constants = NULL;
    chunk->constants_count = 0;
    chunk->constants_capacity = 0;

    if (chunk->globals) {
        for (size_t i = 0; i < chunk->globals_count; ++i) {
            free(chunk->globals[i]);
        }
    }
    free(chunk->globals);
    chunk->globals = NULL;
    chunk->globals_count = 0;
    chunk->globals_capacity = 0;

    free(chunk->lines);
    chunk->lines = NULL;
    chunk->lines_count = 0;
    chunk->lines_capacity = 0;

    free(chunk->binding_entries);
    chunk->binding_entries = NULL;
    chunk->binding_entry_count = 0;
    chunk->binding_entry_capacity = 0;

    chunk->module_version = PROTOHACK_MODULE_VERSION;
    chunk->module_flags = 0;

    if (chunk->extensions) {
        for (size_t i = 0; i < chunk->extension_count; ++i) {
            free(chunk->extensions[i].body_source);
            chunk->extensions[i].body_source = NULL;
        }
    }
    free(chunk->extensions);
    chunk->extensions = NULL;
    chunk->extension_count = 0;
    chunk->extension_capacity = 0;

#if PROTOHACK_ENABLE_JIT
    protochunk_free_jit_cache(chunk);
#endif
}

size_t protochunk_add_constant(ProtoChunk *chunk, ProtoValue value) {
    ENSURE_CAPACITY(chunk->constants, chunk->constants_count, chunk->constants_capacity, ProtoValue);
    chunk->constants[chunk->constants_count] = value;
    return chunk->constants_count++;
}

size_t protochunk_add_number(ProtoChunk *chunk, double value) {
    return protochunk_add_constant(chunk, proto_value_number(value));
}

size_t protochunk_add_string(ProtoChunk *chunk, const char *value, size_t length) {
    return protochunk_add_constant(chunk, proto_value_string(value, length));
}

void protochunk_write(ProtoChunk *chunk, uint8_t byte, size_t line) {
    ENSURE_CAPACITY(chunk->code, chunk->code_count, chunk->code_capacity, uint8_t);
    ENSURE_CAPACITY(chunk->lines, chunk->lines_count, chunk->lines_capacity, size_t);

#if PROTOHACK_ENABLE_JIT
    protochunk_free_jit_cache(chunk);
#endif

    chunk->code[chunk->code_count++] = byte;
    chunk->lines[chunk->lines_count++] = line;
}

void protochunk_write_u16(ProtoChunk *chunk, uint16_t value, size_t line) {
    protochunk_write(chunk, (uint8_t)((value >> 8) & 0xFFu), line);
    protochunk_write(chunk, (uint8_t)(value & 0xFFu), line);
}

int protochunk_find_global(const ProtoChunk *chunk, const char *name) {
    if (!chunk || !name) {
        return -1;
    }
    for (size_t i = 0; i < chunk->globals_count; ++i) {
        if (strcmp(chunk->globals[i], name) == 0) {
            return (int)i;
        }
    }
    return -1;
}

int protochunk_intern_global(ProtoChunk *chunk, const char *name) {
    if (!chunk || !name) {
        return -1;
    }
    int existing = protochunk_find_global(chunk, name);
    if (existing >= 0) {
        return existing;
    }
    if (chunk->globals_count >= PROTOHACK_MAX_GLOBALS) {
        return -1;
    }
    ENSURE_CAPACITY(chunk->globals, chunk->globals_count, chunk->globals_capacity, char *);
    chunk->globals[chunk->globals_count] = protohack_copy_string(name, strlen(name));
    return (int)chunk->globals_count++;
}
