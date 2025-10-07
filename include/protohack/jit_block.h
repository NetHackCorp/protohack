#ifndef PROTOHACK_JIT_BLOCK_H
#define PROTOHACK_JIT_BLOCK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "protohack/config.h"
#include "protohack/opcode.h"
#include "protohack/chunk.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    size_t start_offset;
    size_t end_offset;
    size_t instruction_count;
    ProtoOpCode opcodes[PROTOHACK_JIT_MAX_BLOCK_OPS];
} ProtoJITBlock;

bool protojit_block_extract(const ProtoChunk *chunk, size_t start_offset, ProtoJITBlock *out_block);
bool protojit_block_is_terminator(ProtoOpCode opcode);
size_t protojit_opcode_operand_width(ProtoOpCode opcode);

#ifdef __cplusplus
}
#endif

#endif
