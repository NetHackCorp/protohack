#include "protohack/jit_block.h"

#include <string.h>

size_t protojit_opcode_operand_width(ProtoOpCode opcode) {
    switch (opcode) {
        case PROTO_OP_CONSTANT:
        case PROTO_OP_GET_GLOBAL:
        case PROTO_OP_SET_GLOBAL:
        case PROTO_OP_JUMP:
        case PROTO_OP_JUMP_IF_FALSE:
        case PROTO_OP_LOOP:
            return 2u;
        case PROTO_OP_GET_LOCAL:
        case PROTO_OP_SET_LOCAL:
        case PROTO_OP_CALL:
        case PROTO_OP_ALLOC_TYPED:
        case PROTO_OP_STORE_TYPED:
        case PROTO_OP_LOAD_TYPED:
            return 1u;
        case PROTO_OP_CALL_NATIVE:
        case PROTO_OP_CLASS:
        case PROTO_OP_METHOD:
        case PROTO_OP_GET_PROPERTY:
        case PROTO_OP_SET_PROPERTY:
            return 2u;
        default:
            return 0u;
    }
}

bool protojit_block_is_terminator(ProtoOpCode opcode) {
    switch (opcode) {
        case PROTO_OP_RETURN:
        case PROTO_OP_JUMP:
        case PROTO_OP_JUMP_IF_FALSE:
        case PROTO_OP_LOOP:
        case PROTO_OP_CALL:
        case PROTO_OP_CALL_NATIVE:
            return true;
        default:
            return false;
    }
}

bool protojit_block_extract(const ProtoChunk *chunk, size_t start_offset, ProtoJITBlock *out_block) {
    if (!chunk || !chunk->code || !out_block) {
        return false;
    }
    if (start_offset >= chunk->code_count) {
        return false;
    }

    memset(out_block, 0, sizeof(*out_block));
    out_block->start_offset = start_offset;

    size_t ip = start_offset;
    size_t count = 0u;

    while (ip < chunk->code_count && count < PROTOHACK_JIT_MAX_BLOCK_OPS) {
        ProtoOpCode opcode = (ProtoOpCode)chunk->code[ip++];
        out_block->opcodes[count++] = opcode;

        size_t operand_width = protojit_opcode_operand_width(opcode);
        if (ip + operand_width > chunk->code_count) {
            return false;
        }
        ip += operand_width;

        if (protojit_block_is_terminator(opcode)) {
            break;
        }
    }

    out_block->instruction_count = count;
    out_block->end_offset = ip;

    return count > 0u;
}
