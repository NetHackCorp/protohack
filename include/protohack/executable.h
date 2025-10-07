#ifndef PROTOHACK_EXECUTABLE_H
#define PROTOHACK_EXECUTABLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "protohack/serialize.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PROTOHACK_EXE_MAGIC 0x50484B45u /* 'PHKE' */

typedef struct {
    uint32_t magic;
    uint32_t payload_size;
} ProtoExecutableTrailer;

bool protohack_pack_executable(const ProtoChunk *chunk, const char *runner_path, const char *output_path, ProtoError *error);
bool protohack_extract_embedded_program(const char *exe_path, ProtoSerializedBuffer *buffer, ProtoError *error);

#ifdef __cplusplus
}
#endif

#endif
