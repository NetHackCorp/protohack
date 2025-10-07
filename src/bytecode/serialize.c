#include "protohack/serialize.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protohack/function.h"
#include "protohack/error.h"
#include "protohack/internal/common.h"

typedef struct {
	uint8_t *data;
	size_t size;
	size_t capacity;
} BufferBuilder;

typedef struct {
	const uint8_t *data;
	size_t size;
	size_t offset;
} BufferReader;

static bool buffer_reserve(BufferBuilder *builder, size_t additional) {
	size_t required = builder->size + additional;
	if (required <= builder->capacity) {
		return true;
	}
	size_t new_capacity = builder->capacity == 0 ? 256 : builder->capacity;
	while (new_capacity < required) {
		new_capacity = GROW_CAPACITY(new_capacity);
	}
	uint8_t *new_data = (uint8_t *)realloc(builder->data, new_capacity);
	if (!new_data) {
		return false;
	}
	builder->data = new_data;
	builder->capacity = new_capacity;
	return true;
}

static bool buffer_append(BufferBuilder *builder, const void *data, size_t length) {
	if (length == 0) {
		return true;
	}
	if (!buffer_reserve(builder, length)) {
		return false;
	}
	memcpy(builder->data + builder->size, data, length);
	builder->size += length;
	return true;
}

static bool buffer_append_u32(BufferBuilder *builder, uint32_t value) {
	return buffer_append(builder, &value, sizeof value);
}

static bool reader_read(BufferReader *reader, void *out, size_t length) {
	if (reader->offset + length > reader->size) {
		return false;
	}
	memcpy(out, reader->data + reader->offset, length);
	reader->offset += length;
	return true;
}

static bool reader_read_u32(BufferReader *reader, uint32_t *value) {
	return reader_read(reader, value, sizeof *value);
}

void protochunk_buffer_free(ProtoSerializedBuffer *buffer) {
	if (!buffer) {
		return;
	}
	free(buffer->data);
	buffer->data = NULL;
	buffer->size = 0;
}

static bool serialize_constants(const ProtoChunk *chunk, BufferBuilder *builder) {
	for (size_t i = 0; i < chunk->constants_count; ++i) {
		const ProtoValue *value = &chunk->constants[i];
		uint8_t type = (uint8_t)value->type;
		if (!buffer_append(builder, &type, sizeof type)) {
			return false;
		}
		switch (value->type) {
			case PROTO_VAL_NULL:
				break;
			case PROTO_VAL_BOOL: {
				uint8_t boolean = value->as.boolean ? 1u : 0u;
				if (!buffer_append(builder, &boolean, sizeof boolean)) {
					return false;
				}
				break;
			}
			case PROTO_VAL_NUMBER:
				if (!buffer_append(builder, &value->as.number, sizeof value->as.number)) {
					return false;
				}
				break;
			case PROTO_VAL_STRING: {
				uint32_t length = value->as.string ? (uint32_t)strlen(value->as.string) : 0u;
				if (!buffer_append_u32(builder, length)) {
					return false;
				}
				if (length > 0 && !buffer_append(builder, value->as.string, length)) {
					return false;
				}
				break;
			}
			case PROTO_VAL_FUNCTION: {
				const ProtoFunction *function = value->as.function;
				uint8_t kind = function ? (uint8_t)function->kind : 0u;
				uint8_t arity = function ? function->arity : 0u;
				uint8_t return_type = function ? (uint8_t)function->return_type : (uint8_t)PROTO_TYPE_NONE;
				if (!buffer_append(builder, &kind, sizeof kind) || !buffer_append(builder, &arity, sizeof arity) || !buffer_append(builder, &return_type, sizeof return_type)) {
					return false;
				}
				for (uint8_t i = 0; i < arity; ++i) {
					uint8_t param_type = function ? (uint8_t)function->param_types[i] : (uint8_t)PROTO_TYPE_ANY;
					if (!buffer_append(builder, &param_type, sizeof param_type)) {
						return false;
					}
				}
				uint32_t name_length = function && function->name ? (uint32_t)strlen(function->name) : 0u;
				if (!buffer_append_u32(builder, name_length)) {
					return false;
				}
				if (name_length > 0 && !buffer_append(builder, function->name, name_length)) {
					return false;
				}
				ProtoSerializedBuffer fn_buffer = {0};
				ProtoError fn_error;
				protoerror_reset(&fn_error);
				if (function && !protochunk_serialize_to_buffer(&function->chunk, &fn_buffer, &fn_error)) {
					return false;
				}
				uint32_t chunk_size = (uint32_t)fn_buffer.size;
				if (!buffer_append_u32(builder, chunk_size)) {
					protochunk_buffer_free(&fn_buffer);
					return false;
				}
				if (chunk_size > 0 && !buffer_append(builder, fn_buffer.data, chunk_size)) {
					protochunk_buffer_free(&fn_buffer);
					return false;
				}
				protochunk_buffer_free(&fn_buffer);
				break;
			}
			default:
				return false;
		}
	}
	return true;
}

static bool serialize_globals(const ProtoChunk *chunk, BufferBuilder *builder) {
	for (size_t i = 0; i < chunk->globals_count; ++i) {
		const char *name = chunk->globals[i];
		uint32_t length = name ? (uint32_t)strlen(name) : 0u;
		if (!buffer_append_u32(builder, length)) {
			return false;
		}
		if (length > 0 && !buffer_append(builder, name, length)) {
			return false;
		}
	}
	return true;
}

bool protochunk_serialize_to_buffer(const ProtoChunk *chunk, ProtoSerializedBuffer *out, ProtoError *error) {
	if (!chunk || !out || !error) {
		if (error) {
			protoerror_set(error, 0, "Invalid arguments to serialize");
		}
		return false;
	}
	protoerror_reset(error);

	BufferBuilder builder = {0};
	bool ok = true;

	size_t magic_len = strlen(PROTOHACK_BYTECODE_MAGIC);
	ok = buffer_append(&builder, PROTOHACK_BYTECODE_MAGIC, magic_len);

	uint32_t code_count = (uint32_t)chunk->code_count;
	uint32_t constants_count = (uint32_t)chunk->constants_count;
	uint32_t globals_count = (uint32_t)chunk->globals_count;
	uint32_t lines_count = (uint32_t)chunk->lines_count;

	if (ok) {
		ok = buffer_append_u32(&builder, code_count) && buffer_append_u32(&builder, constants_count) && buffer_append_u32(&builder, globals_count) && buffer_append_u32(&builder, lines_count);
	}

	if (ok && code_count > 0) {
		ok = buffer_append(&builder, chunk->code, code_count * sizeof(uint8_t));
	}
	if (ok && lines_count > 0) {
		ok = buffer_append(&builder, chunk->lines, lines_count * sizeof(size_t));
	}

	if (ok) {
		ok = serialize_constants(chunk, &builder);
	}
	if (ok) {
		ok = serialize_globals(chunk, &builder);
	}

	if (!ok) {
		free(builder.data);
		protoerror_set(error, 0, "Failed to serialize chunk");
		return false;
	}

	out->data = builder.data;
	out->size = builder.size;
	return true;
}

bool protochunk_serialize(const ProtoChunk *chunk, const char *path, ProtoError *error) {
	if (!path) {
		if (error) {
			protoerror_set(error, 0, "Invalid output path");
		}
		return false;
	}

	ProtoSerializedBuffer buffer = {0};
	if (!protochunk_serialize_to_buffer(chunk, &buffer, error)) {
		return false;
	}

	FILE *file = fopen(path, "wb");
	if (!file) {
		protochunk_buffer_free(&buffer);
		protoerror_set(error, 0, "Unable to open output file");
		return false;
	}

	bool ok = fwrite(buffer.data, sizeof(uint8_t), buffer.size, file) == buffer.size;
	fclose(file);
	protochunk_buffer_free(&buffer);

	if (!ok) {
		protoerror_set(error, 0, "Failed to write bytecode");
		return false;
	}
	return true;
}

static bool deserialize_constants(ProtoChunk *chunk, BufferReader *reader, uint32_t constants_count, ProtoError *error) {
	if (constants_count == 0) {
		return true;
	}
	chunk->constants = (ProtoValue *)calloc(constants_count, sizeof(ProtoValue));
	if (!chunk->constants) {
		protoerror_set(error, 0, "Failed to allocate constants");
		return false;
	}
	chunk->constants_capacity = constants_count;
	chunk->constants_count = constants_count;

	for (uint32_t i = 0; i < constants_count; ++i) {
		uint8_t type = 0;
		if (!reader_read(reader, &type, sizeof type)) {
			protoerror_set(error, 0, "Failed to read constant type");
			return false;
		}
		switch ((ProtoValueType)type) {
			case PROTO_VAL_NULL:
				chunk->constants[i] = proto_value_null();
				break;
			case PROTO_VAL_BOOL: {
				uint8_t boolean = 0;
				if (!reader_read(reader, &boolean, sizeof boolean)) {
					protoerror_set(error, 0, "Failed to read bool constant");
					return false;
				}
				chunk->constants[i] = proto_value_bool(boolean != 0);
				break;
			}
			case PROTO_VAL_NUMBER: {
				double number = 0.0;
				if (!reader_read(reader, &number, sizeof number)) {
					protoerror_set(error, 0, "Failed to read number constant");
					return false;
				}
				chunk->constants[i] = proto_value_number(number);
				break;
			}
			case PROTO_VAL_STRING: {
				uint32_t length = 0;
				if (!reader_read_u32(reader, &length)) {
					protoerror_set(error, 0, "Failed to read string length");
					return false;
				}
				char *buffer = (char *)malloc(length + 1);
				if (!buffer) {
					protoerror_set(error, 0, "Failed to allocate string constant");
					return false;
				}
				if (length > 0 && !reader_read(reader, buffer, length)) {
					free(buffer);
					protoerror_set(error, 0, "Failed to read string constant");
					return false;
				}
				buffer[length] = '\0';
				chunk->constants[i] = proto_value_string(buffer, length);
				free(buffer);
				break;
			}
			case PROTO_VAL_FUNCTION: {
				uint8_t kind = 0;
				uint8_t arity = 0;
				uint8_t return_type = 0;
				if (!reader_read(reader, &kind, sizeof kind) || !reader_read(reader, &arity, sizeof arity) || !reader_read(reader, &return_type, sizeof return_type)) {
					protoerror_set(error, 0, "Failed to read function header");
					return false;
				}
				ProtoFunction *function = proto_function_new((ProtoFunctionKind)kind, NULL);
				function->arity = arity;
				function->return_type = (ProtoTypeTag)return_type;
				for (uint8_t pi = 0; pi < arity; ++pi) {
					uint8_t param_type = 0;
					if (!reader_read(reader, &param_type, sizeof param_type)) {
						proto_function_free(function);
						protoerror_set(error, 0, "Failed to read function parameter type");
						return false;
					}
					function->param_types[pi] = (ProtoTypeTag)param_type;
				}
				uint32_t name_length = 0;
				if (!reader_read_u32(reader, &name_length)) {
					proto_function_free(function);
					protoerror_set(error, 0, "Failed to read function name length");
					return false;
				}
				free(function->name);
				function->name = NULL;
				if (name_length > 0) {
					char *name_buffer = (char *)malloc(name_length + 1);
					if (!name_buffer) {
						proto_function_free(function);
						protoerror_set(error, 0, "Failed to allocate function name");
						return false;
					}
					if (!reader_read(reader, name_buffer, name_length)) {
						free(name_buffer);
						proto_function_free(function);
						protoerror_set(error, 0, "Failed to read function name");
						return false;
					}
					name_buffer[name_length] = '\0';
					function->name = name_buffer;
				}
				uint32_t chunk_size = 0;
				if (!reader_read_u32(reader, &chunk_size)) {
					proto_function_free(function);
					protoerror_set(error, 0, "Failed to read function chunk size");
					return false;
				}
				uint8_t *chunk_data = NULL;
				if (chunk_size > 0) {
					chunk_data = (uint8_t *)malloc(chunk_size);
					if (!chunk_data) {
						proto_function_free(function);
						protoerror_set(error, 0, "Failed to allocate function chunk");
						return false;
					}
					if (!reader_read(reader, chunk_data, chunk_size)) {
						free(chunk_data);
						proto_function_free(function);
						protoerror_set(error, 0, "Failed to read function chunk data");
						return false;
					}
				}
				ProtoError fn_error;
				protoerror_reset(&fn_error);
				if (chunk_size > 0 && !protochunk_deserialize_from_memory(&function->chunk, chunk_data, chunk_size, &fn_error)) {
					free(chunk_data);
					proto_function_free(function);
					protoerror_set(error, 0, "Failed to deserialize function chunk");
					return false;
				}
				free(chunk_data);
				chunk->constants[i] = proto_value_function(function);
				break;
			}
			default:
				protoerror_set(error, 0, "Unknown constant type");
				return false;
		}
	}
	return true;
}

static bool deserialize_globals(ProtoChunk *chunk, BufferReader *reader, uint32_t globals_count, ProtoError *error) {
	if (globals_count == 0) {
		return true;
	}
	chunk->globals = (char **)calloc(globals_count, sizeof(char *));
	if (!chunk->globals) {
		protoerror_set(error, 0, "Failed to allocate globals");
		return false;
	}
	chunk->globals_capacity = globals_count;
	chunk->globals_count = globals_count;

	for (uint32_t i = 0; i < globals_count; ++i) {
		uint32_t length = 0;
		if (!reader_read_u32(reader, &length)) {
			protoerror_set(error, 0, "Failed to read global length");
			return false;
		}
		char *buffer = (char *)malloc(length + 1);
		if (!buffer) {
			protoerror_set(error, 0, "Failed to allocate global name");
			return false;
		}
		if (length > 0 && !reader_read(reader, buffer, length)) {
			free(buffer);
			protoerror_set(error, 0, "Failed to read global name");
			return false;
		}
		buffer[length] = '\0';
		chunk->globals[i] = buffer;
	}
	return true;
}

bool protochunk_deserialize_from_memory(ProtoChunk *chunk, const uint8_t *data, size_t size, ProtoError *error) {
	if (!chunk || !data || size == 0 || !error) {
		if (error) {
			protoerror_set(error, 0, "Invalid arguments to deserialize");
		}
		return false;
	}
	protoerror_reset(error);

	BufferReader reader = {data, size, 0};
	size_t magic_len = strlen(PROTOHACK_BYTECODE_MAGIC);
	char magic[8] = {0};
	if (magic_len >= sizeof magic) {
		protoerror_set(error, 0, "Invalid magic length");
		return false;
	}
	if (!reader_read(&reader, magic, magic_len) || memcmp(magic, PROTOHACK_BYTECODE_MAGIC, magic_len) != 0) {
		protoerror_set(error, 0, "Invalid bytecode magic");
		return false;
	}

	uint32_t code_count = 0;
	uint32_t constants_count = 0;
	uint32_t globals_count = 0;
	uint32_t lines_count = 0;

	if (!reader_read_u32(&reader, &code_count) || !reader_read_u32(&reader, &constants_count) || !reader_read_u32(&reader, &globals_count) || !reader_read_u32(&reader, &lines_count)) {
		protoerror_set(error, 0, "Failed to read chunk header");
		return false;
	}

	protochunk_free(chunk);
	protochunk_init(chunk);

	if (code_count > 0) {
		chunk->code = (uint8_t *)malloc(code_count * sizeof(uint8_t));
		if (!chunk->code || !reader_read(&reader, chunk->code, code_count * sizeof(uint8_t))) {
			protoerror_set(error, 0, "Failed to read code section");
			return false;
		}
		chunk->code_capacity = code_count;
		chunk->code_count = code_count;
	}

	if (lines_count > 0) {
		chunk->lines = (size_t *)malloc(lines_count * sizeof(size_t));
		if (!chunk->lines || !reader_read(&reader, chunk->lines, lines_count * sizeof(size_t))) {
			protoerror_set(error, 0, "Failed to read line table");
			return false;
		}
		chunk->lines_capacity = lines_count;
		chunk->lines_count = lines_count;
	}

	if (!deserialize_constants(chunk, &reader, constants_count, error)) {
		return false;
	}

	if (!deserialize_globals(chunk, &reader, globals_count, error)) {
		return false;
	}

	return true;
}

bool protochunk_deserialize(ProtoChunk *chunk, const char *path, ProtoError *error) {
	if (!chunk || !path || !error) {
		if (error) {
			protoerror_set(error, 0, "Invalid arguments to deserialize");
		}
		return false;
	}
	protoerror_reset(error);

	FILE *file = fopen(path, "rb");
	if (!file) {
		protoerror_set(error, 0, "Unable to open bytecode file");
		return false;
	}

	if (fseek(file, 0, SEEK_END) != 0) {
		fclose(file);
		protoerror_set(error, 0, "Failed to seek bytecode file");
		return false;
	}
	long length = ftell(file);
	if (length < 0) {
		fclose(file);
		protoerror_set(error, 0, "Failed to determine bytecode size");
		return false;
	}
	if (fseek(file, 0, SEEK_SET) != 0) {
		fclose(file);
		protoerror_set(error, 0, "Failed to rewind bytecode file");
		return false;
	}

	uint8_t *data = (uint8_t *)malloc((size_t)length);
	if (!data) {
		fclose(file);
		protoerror_set(error, 0, "Failed to allocate buffer");
		return false;
	}

	size_t read = fread(data, sizeof(uint8_t), (size_t)length, file);
	fclose(file);
	if (read != (size_t)length) {
		free(data);
		protoerror_set(error, 0, "Failed to read bytecode file");
		return false;
	}

	bool ok = protochunk_deserialize_from_memory(chunk, data, (size_t)length, error);
	free(data);
	return ok;
}
