#ifndef PROTOHACK_JIT_H
#define PROTOHACK_JIT_H

#include <stdint.h>
#include <stdio.h>

#include "protohack/config.h"
#include "protohack/opcode.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t opcode_counts[PROTO_OP_COUNT];
    uint64_t bailout_opcode_counts[PROTO_OP_COUNT];
    uint64_t total_dispatches;
    uint64_t block_attempts;
    uint64_t block_hits;
    uint64_t block_bailouts_unsupported;
    uint64_t block_bailouts_runtime;
} ProtoJITProfiler;

void protojit_profiler_init(ProtoJITProfiler *profiler);
void protojit_profiler_reset(ProtoJITProfiler *profiler);
void protojit_profiler_count(ProtoJITProfiler *profiler, ProtoOpCode opcode);
void protojit_profiler_merge(ProtoJITProfiler *dst, const ProtoJITProfiler *src);
void protojit_profiler_dump(const ProtoJITProfiler *profiler, FILE *stream);
void protojit_profiler_block_attempt(ProtoJITProfiler *profiler);
void protojit_profiler_block_hit(ProtoJITProfiler *profiler);
void protojit_profiler_block_bailout_unsupported(ProtoJITProfiler *profiler, ProtoOpCode opcode);
void protojit_profiler_block_bailout_runtime(ProtoJITProfiler *profiler, ProtoOpCode opcode);

#ifdef __cplusplus
}
#endif

#endif
