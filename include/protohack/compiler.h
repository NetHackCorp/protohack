#ifndef PROTOHACK_COMPILER_H
#define PROTOHACK_COMPILER_H

#include <stdbool.h>

#include "protohack/chunk.h"
#include "protohack/error.h"

#ifdef __cplusplus
extern "C" {
#endif

bool protohack_compile_source(const char *source, const char *origin_path, ProtoChunk *chunk, ProtoError *error);

#ifdef __cplusplus
}
#endif

#endif
