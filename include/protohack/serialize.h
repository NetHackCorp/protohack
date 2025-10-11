#ifndef PROTOHACK_SERIALIZE_H
#define PROTOHACK_SERIALIZE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "protohack/chunk.h"
#include "protohack/error.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PROTOHACK_BYTECODE_MAGIC "PHK4"
#define PROTOHACK_BYTECODE_MAGIC_LEGACY "PHK3"

#define PROTOHACK_MODULE_VERSION 3u
#define PROTOHACK_MODULE_FLAG_HAS_BINDING_MAP 0x00000001u
#define PROTOHACK_MODULE_FLAG_HAS_EXTENSIONS 0x00000002u

typedef struct {
	uint32_t version;
	uint32_t flags;
	uint32_t code_count;
	uint32_t constants_count;
	uint32_t globals_count;
	uint32_t lines_count;
	uint32_t binding_count;
	uint32_t extension_count;
} ProtoModuleHeader;

bool protochunk_serialize(const ProtoChunk *chunk, const char *path, ProtoError *error);
bool protochunk_deserialize(ProtoChunk *chunk, const char *path, ProtoError *error);

typedef struct {
	uint8_t *data;
	size_t size;
} ProtoSerializedBuffer;

bool protochunk_serialize_to_buffer(const ProtoChunk *chunk, ProtoSerializedBuffer *out, ProtoError *error);
bool protochunk_deserialize_from_memory(ProtoChunk *chunk, const uint8_t *data, size_t size, ProtoError *error);
void protochunk_buffer_free(ProtoSerializedBuffer *buffer);

#ifdef __cplusplus
}
#endif

#endif
