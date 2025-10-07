#ifndef PROTOHACK_CHUNK_H
#define PROTOHACK_CHUNK_H

#include <stddef.h>
#include <stdint.h>

#include "protohack/config.h"
#include "protohack/value.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ProtoJITIR;

typedef struct ProtoChunk {
    uint8_t *code;
    size_t code_count;
    size_t code_capacity;

    ProtoValue *constants;
    size_t constants_count;
    size_t constants_capacity;

    char **globals;
    size_t globals_count;
    size_t globals_capacity;

    size_t *lines;
    size_t lines_count;
    size_t lines_capacity;

#if PROTOHACK_ENABLE_JIT
    struct ProtoJITIR **jit_cache;
    size_t jit_cache_count;
#endif
} ProtoChunk;

void protochunk_init(ProtoChunk *chunk);
void protochunk_free(ProtoChunk *chunk);
size_t protochunk_add_constant(ProtoChunk *chunk, ProtoValue value);
size_t protochunk_add_number(ProtoChunk *chunk, double value);
size_t protochunk_add_string(ProtoChunk *chunk, const char *value, size_t length);
void protochunk_write(ProtoChunk *chunk, uint8_t byte, size_t line);
void protochunk_write_u16(ProtoChunk *chunk, uint16_t value, size_t line);
int protochunk_intern_global(ProtoChunk *chunk, const char *name);
int protochunk_find_global(const ProtoChunk *chunk, const char *name);

#ifdef __cplusplus
}
#endif

#endif
