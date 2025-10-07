#include "protohack/typed_memory.h"

#include <stdlib.h>
#include <string.h>

#include "protohack/internal/common.h"

ProtoTypedMemory proto_memory_allocate(ProtoTypeTag element_type, size_t count) {
    size_t element_size = 0;
    switch (element_type) {
        case PROTO_TYPE_NUM:
            element_size = sizeof(double);
            break;
        case PROTO_TYPE_FLAG:
            element_size = sizeof(uint8_t);
            break;
        case PROTO_TYPE_TEXT:
            element_size = sizeof(char);
            break;
        case PROTO_TYPE_RAW:
            element_size = sizeof(uint8_t);
            break;
        case PROTO_TYPE_ANY:
        case PROTO_TYPE_NONE:
        default:
            element_size = sizeof(uint8_t);
            break;
    }

    ProtoTypedMemory memory;
    memory.element_type = element_type;
    memory.count = count;
    memory.data = NULL;

    if (count == 0) {
        return memory;
    }

    memory.data = calloc(count, element_size);
    if (!memory.data) {
        PROTOHACK_FATAL("Failed to allocate typed memory block");
    }
    return memory;
}

void proto_memory_free(ProtoTypedMemory *memory) {
    if (!memory) {
        return;
    }
    free(memory->data);
    memory->data = NULL;
    memory->count = 0;
    memory->element_type = PROTO_TYPE_ANY;
}

ProtoTypedMemory proto_memory_clone(const ProtoTypedMemory *memory) {
    if (!memory || memory->count == 0 || !memory->data) {
        ProtoTypedMemory clone;
        clone.element_type = memory ? memory->element_type : PROTO_TYPE_ANY;
        clone.count = 0;
        clone.data = NULL;
        return clone;
    }
    size_t element_size = 0;
    switch (memory->element_type) {
        case PROTO_TYPE_NUM:
            element_size = sizeof(double);
            break;
        case PROTO_TYPE_FLAG:
            element_size = sizeof(uint8_t);
            break;
        case PROTO_TYPE_TEXT:
            element_size = sizeof(char);
            break;
        case PROTO_TYPE_RAW:
            element_size = sizeof(uint8_t);
            break;
        case PROTO_TYPE_ANY:
        case PROTO_TYPE_NONE:
        default:
            element_size = sizeof(uint8_t);
            break;
    }
    ProtoTypedMemory clone = proto_memory_allocate(memory->element_type, memory->count);
    memcpy(clone.data, memory->data, memory->count * element_size);
    return clone;
}
