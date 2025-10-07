#ifndef PROTOHACK_TYPED_MEMORY_H
#define PROTOHACK_TYPED_MEMORY_H

#include <stddef.h>
#include <stdint.h>

#include "protohack/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    ProtoTypeTag element_type;
    size_t count;
    void *data;
} ProtoTypedMemory;

ProtoTypedMemory proto_memory_allocate(ProtoTypeTag element_type, size_t count);
void proto_memory_free(ProtoTypedMemory *memory);
ProtoTypedMemory proto_memory_clone(const ProtoTypedMemory *memory);

#ifdef __cplusplus
}
#endif

#endif
