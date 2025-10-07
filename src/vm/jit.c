#include "protohack/jit.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#if PROTOHACK_JIT_PROFILE
static const char *opcode_name(ProtoOpCode opcode) {
    switch (opcode) {
        case PROTO_OP_CONSTANT: return "CONSTANT";
        case PROTO_OP_TRUE: return "TRUE";
        case PROTO_OP_FALSE: return "FALSE";
        case PROTO_OP_NULL: return "NULL";
        case PROTO_OP_GET_GLOBAL: return "GET_GLOBAL";
        case PROTO_OP_SET_GLOBAL: return "SET_GLOBAL";
        case PROTO_OP_ADD: return "ADD";
        case PROTO_OP_SUB: return "SUB";
        case PROTO_OP_MUL: return "MUL";
        case PROTO_OP_DIV: return "DIV";
        case PROTO_OP_NEGATE: return "NEGATE";
        case PROTO_OP_NOT: return "NOT";
        case PROTO_OP_EQUAL: return "EQUAL";
        case PROTO_OP_GREATER: return "GREATER";
        case PROTO_OP_LESS: return "LESS";
        case PROTO_OP_PRINT: return "PRINT";
        case PROTO_OP_POP: return "POP";
        case PROTO_OP_JUMP: return "JUMP";
        case PROTO_OP_JUMP_IF_FALSE: return "JUMP_IF_FALSE";
        case PROTO_OP_LOOP: return "LOOP";
        case PROTO_OP_CALL_NATIVE: return "CALL_NATIVE";
        case PROTO_OP_GET_LOCAL: return "GET_LOCAL";
        case PROTO_OP_SET_LOCAL: return "SET_LOCAL";
        case PROTO_OP_CALL: return "CALL";
        case PROTO_OP_ALLOC_TYPED: return "ALLOC_TYPED";
        case PROTO_OP_STORE_TYPED: return "STORE_TYPED";
        case PROTO_OP_LOAD_TYPED: return "LOAD_TYPED";
        case PROTO_OP_CLASS: return "CLASS";
        case PROTO_OP_METHOD: return "METHOD";
        case PROTO_OP_GET_PROPERTY: return "GET_PROPERTY";
        case PROTO_OP_SET_PROPERTY: return "SET_PROPERTY";
        case PROTO_OP_RETURN: return "RETURN";
        default: return "<UNKNOWN>";
    }
}
#endif

void protojit_profiler_init(ProtoJITProfiler *profiler) {
    if (!profiler) {
        return;
    }
    memset(profiler->opcode_counts, 0, sizeof(profiler->opcode_counts));
    memset(profiler->bailout_opcode_counts, 0, sizeof(profiler->bailout_opcode_counts));
    profiler->total_dispatches = 0u;
    profiler->block_attempts = 0u;
    profiler->block_hits = 0u;
    profiler->block_bailouts_unsupported = 0u;
    profiler->block_bailouts_runtime = 0u;
}

void protojit_profiler_reset(ProtoJITProfiler *profiler) {
    protojit_profiler_init(profiler);
}

void protojit_profiler_count(ProtoJITProfiler *profiler, ProtoOpCode opcode) {
    if (!profiler) {
        return;
    }
#if PROTOHACK_JIT_PROFILE
    if ((int)opcode >= 0 && opcode < PROTO_OP_COUNT) {
        profiler->opcode_counts[opcode]++;
    }
    profiler->total_dispatches++;
#else
    (void)opcode;
#endif
}

void protojit_profiler_merge(ProtoJITProfiler *dst, const ProtoJITProfiler *src) {
    if (!dst || !src) {
        return;
    }
#if PROTOHACK_JIT_PROFILE
    for (int i = 0; i < PROTO_OP_COUNT; ++i) {
        dst->opcode_counts[i] += src->opcode_counts[i];
        dst->bailout_opcode_counts[i] += src->bailout_opcode_counts[i];
    }
    dst->total_dispatches += src->total_dispatches;
    dst->block_attempts += src->block_attempts;
    dst->block_hits += src->block_hits;
    dst->block_bailouts_unsupported += src->block_bailouts_unsupported;
    dst->block_bailouts_runtime += src->block_bailouts_runtime;
#else
    (void)dst;
    (void)src;
#endif
}

void protojit_profiler_dump(const ProtoJITProfiler *profiler, FILE *stream) {
    if (!stream) {
        stream = stdout;
    }
    if (!profiler) {
        fprintf(stream, "[jit] profiler unavailable\n");
        return;
    }
#if PROTOHACK_JIT_PROFILE
    fprintf(stream,
            "[jit] block stats: attempts=%" PRIu64 ", hits=%" PRIu64 ", unsupported=%" PRIu64 ", runtime=%" PRIu64 "\n",
            profiler->block_attempts,
            profiler->block_hits,
            profiler->block_bailouts_unsupported,
            profiler->block_bailouts_runtime);
    fprintf(stream, "[jit] opcode dispatch histogram (total: %" PRIu64 ")\n",
            profiler->total_dispatches);
    if (profiler->total_dispatches == 0u) {
        fprintf(stream, "  <empty>\n");
    } else {
        for (int i = 0; i < PROTO_OP_COUNT; ++i) {
            uint64_t count = profiler->opcode_counts[i];
            if (count == 0u) {
                continue;
            }
            double pct = 100.0 * (double)count / (double)profiler->total_dispatches;
            fprintf(stream, "  %-16s : %" PRIu64 " (%.2f%%)\n",
                    opcode_name((ProtoOpCode)i), count, pct);
        }
    }
    uint64_t total_bailouts = profiler->block_bailouts_unsupported + profiler->block_bailouts_runtime;
    if (total_bailouts > 0u) {
        fprintf(stream, "[jit] bailout opcode histogram\n");
        for (int i = 0; i < PROTO_OP_COUNT; ++i) {
            uint64_t count = profiler->bailout_opcode_counts[i];
            if (count == 0u) {
                continue;
            }
            fprintf(stream, "  %-16s : %" PRIu64 "\n",
                    opcode_name((ProtoOpCode)i), count);
        }
    }
#else
    fprintf(stream, "[jit] profiling disabled (enable with PROTOHACK_ENABLE_JIT)\n");
#endif
}

void protojit_profiler_block_attempt(ProtoJITProfiler *profiler) {
    if (!profiler) {
        return;
    }
#if PROTOHACK_JIT_PROFILE
    profiler->block_attempts++;
#endif
}

void protojit_profiler_block_hit(ProtoJITProfiler *profiler) {
    if (!profiler) {
        return;
    }
#if PROTOHACK_JIT_PROFILE
    profiler->block_hits++;
#endif
}

void protojit_profiler_block_bailout_unsupported(ProtoJITProfiler *profiler, ProtoOpCode opcode) {
    if (!profiler) {
        return;
    }
#if PROTOHACK_JIT_PROFILE
    profiler->block_bailouts_unsupported++;
    if (opcode >= 0 && opcode < PROTO_OP_COUNT) {
        profiler->bailout_opcode_counts[opcode]++;
    }
#else
    (void)opcode;
#endif
}

void protojit_profiler_block_bailout_runtime(ProtoJITProfiler *profiler, ProtoOpCode opcode) {
    if (!profiler) {
        return;
    }
#if PROTOHACK_JIT_PROFILE
    profiler->block_bailouts_runtime++;
    if (opcode >= 0 && opcode < PROTO_OP_COUNT) {
        profiler->bailout_opcode_counts[opcode]++;
    }
#else
    (void)opcode;
#endif
}