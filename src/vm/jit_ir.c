#include "protohack/jit_ir.h"

#if PROTOHACK_ENABLE_JIT

#include <stdlib.h>
#include <string.h>

#include "protohack/chunk.h"

static bool protojit_opcode_supported(ProtoOpCode opcode) {
    switch (opcode) {
        case PROTO_OP_CONSTANT:
        case PROTO_OP_TRUE:
        case PROTO_OP_FALSE:
        case PROTO_OP_NULL:
        case PROTO_OP_GET_GLOBAL:
        case PROTO_OP_SET_GLOBAL:
        case PROTO_OP_GET_LOCAL:
        case PROTO_OP_SET_LOCAL:
        case PROTO_OP_ADD:
        case PROTO_OP_SUB:
        case PROTO_OP_MUL:
        case PROTO_OP_DIV:
        case PROTO_OP_NEGATE:
        case PROTO_OP_NOT:
        case PROTO_OP_EQUAL:
        case PROTO_OP_GREATER:
        case PROTO_OP_LESS:
        case PROTO_OP_POP:
        case PROTO_OP_PRINT:
        case PROTO_OP_ALLOC_TYPED:
        case PROTO_OP_STORE_TYPED:
        case PROTO_OP_LOAD_TYPED:
        case PROTO_OP_RETURN:
            return true;
        default:
            return false;
    }
}

static uint16_t protojit_read_u16(const uint8_t *code) {
    return (uint16_t)(((uint16_t)code[0] << 8) | (uint16_t)code[1]);
}

ProtoJITIR *protojit_ir_compile(const ProtoChunk *chunk, const ProtoJITBlock *block) {
    if (!chunk || !block) {
        return NULL;
    }
    ProtoJITIR *ir = (ProtoJITIR *)calloc(1, sizeof(ProtoJITIR));
    if (!ir) {
        return NULL;
    }
    ir->start_offset = block->start_offset;
    ir->end_offset = block->end_offset;
    ir->count = block->instruction_count;
    ir->supported = true;
    ir->bailout_opcode = PROTO_OP_COUNT;

    size_t ip = block->start_offset;
    for (size_t i = 0; i < block->instruction_count; ++i) {
        ProtoOpCode opcode = block->opcodes[i];
        ProtoJITIROp *op = &ir->ops[i];
        op->opcode = opcode;
        op->line = (ip < chunk->lines_count) ? chunk->lines[ip] : 0u;
        op->operand_u16 = 0u;
        op->operand_u8 = 0u;

        size_t operand_width = protojit_opcode_operand_width(opcode);
        if (operand_width > 0u) {
            if (ip + operand_width >= chunk->code_count) {
                ir->supported = false;
                if (ir->bailout_opcode == PROTO_OP_COUNT) {
                    ir->bailout_opcode = opcode;
                }
                break;
            }
            if (operand_width == 2u) {
                op->operand_u16 = protojit_read_u16(&chunk->code[ip + 1u]);
            } else if (operand_width == 1u) {
                op->operand_u8 = chunk->code[ip + 1u];
            } else if (operand_width == 3u) {
                op->operand_u16 = protojit_read_u16(&chunk->code[ip + 1u]);
                op->operand_u8 = chunk->code[ip + 3u];
            }
        }

        if (!protojit_opcode_supported(opcode)) {
            ir->supported = false;
            if (ir->bailout_opcode == PROTO_OP_COUNT) {
                ir->bailout_opcode = opcode;
            }
        }

        ip += 1u + operand_width;
    }

    return ir;
}

void protojit_ir_free(ProtoJITIR *ir) {
    free(ir);
}

ProtoJITIR *protojit_ir_get_or_build(ProtoChunk *chunk, size_t start_offset) {
    if (!chunk || start_offset >= chunk->code_count) {
        return NULL;
    }

    if (!chunk->jit_cache || chunk->jit_cache_count != chunk->code_count) {
        free(chunk->jit_cache);
        chunk->jit_cache = (ProtoJITIR **)calloc(chunk->code_count, sizeof(ProtoJITIR *));
        if (!chunk->jit_cache) {
            chunk->jit_cache_count = 0;
            return NULL;
        }
        chunk->jit_cache_count = chunk->code_count;
    }

    ProtoJITIR *cached = chunk->jit_cache[start_offset];
    if (cached) {
        return cached;
    }

    ProtoJITBlock block;
    if (!protojit_block_extract(chunk, start_offset, &block)) {
        cached = (ProtoJITIR *)calloc(1, sizeof(ProtoJITIR));
        if (!cached) {
            return NULL;
        }
        cached->supported = false;
        cached->start_offset = start_offset;
        cached->end_offset = start_offset;
        cached->bailout_opcode = PROTO_OP_COUNT;
        chunk->jit_cache[start_offset] = cached;
        return cached;
    }

    cached = protojit_ir_compile(chunk, &block);
    chunk->jit_cache[start_offset] = cached;
    return cached;
}

#else

ProtoJITIR *protojit_ir_compile(const ProtoChunk *chunk, const ProtoJITBlock *block) {
    (void)chunk;
    (void)block;
    return NULL;
}

void protojit_ir_free(ProtoJITIR *ir) {
    (void)ir;
}

ProtoJITIR *protojit_ir_get_or_build(ProtoChunk *chunk, size_t start_offset) {
    (void)chunk;
    (void)start_offset;
    return NULL;
}

#endif
