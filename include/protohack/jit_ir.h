    #ifndef PROTOHACK_JIT_IR_H
#define PROTOHACK_JIT_IR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "protohack/config.h"
#include "protohack/opcode.h"
#include "protohack/jit_block.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ProtoChunk;
struct ProtoVM;
struct ProtoCallFrame;
struct ProtoError;

typedef struct {
    ProtoOpCode opcode;
    uint16_t operand_u16;
    uint8_t operand_u8;
    size_t line;
} ProtoJITIROp;

typedef struct ProtoJITIR {
    ProtoJITIROp ops[PROTOHACK_JIT_MAX_BLOCK_OPS];
    size_t count;
    size_t start_offset;
    size_t end_offset;
    bool supported;
    ProtoOpCode bailout_opcode;
} ProtoJITIR;

ProtoJITIR *protojit_ir_compile(const struct ProtoChunk *chunk, const ProtoJITBlock *block);
void protojit_ir_free(ProtoJITIR *ir);
ProtoJITIR *protojit_ir_get_or_build(struct ProtoChunk *chunk, size_t start_offset);

#ifdef __cplusplus
}
#endif

#endif
