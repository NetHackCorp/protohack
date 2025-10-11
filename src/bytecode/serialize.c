#include "protohack/serialize.h"

#include <limits.h>
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

static bool buffer_append_u8(BufferBuilder *builder, uint8_t value) {
	return buffer_append(builder, &value, sizeof value);
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

static bool reader_read_u8(BufferReader *reader, uint8_t *value) {
	return reader_read(reader, value, sizeof *value);
}

static bool reader_read_i8(BufferReader *reader, int8_t *value) {
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
				int8_t return_binding = function ? function->return_type_param : -1;
				uint8_t type_param_count = function ? function->type_param_count : 0u;
				uint8_t type_argument_count = function ? function->type_argument_count : 0u;
				uint8_t binding_count = function ? function->bindings.count : 0u;
				if (!buffer_append(builder, &kind, sizeof kind) ||
				    !buffer_append(builder, &arity, sizeof arity) ||
				    !buffer_append(builder, &return_type, sizeof return_type) ||
				    !buffer_append(builder, &return_binding, sizeof return_binding) ||
				    !buffer_append(builder, &type_param_count, sizeof type_param_count)) {
					return false;
				}
				for (uint8_t i = 0; i < type_param_count; ++i) {
					uint32_t param_name_length = function && function->type_params[i] ? (uint32_t)strlen(function->type_params[i]) : 0u;
					if (!buffer_append_u32(builder, param_name_length)) {
						return false;
					}
					if (param_name_length > 0 && !buffer_append(builder, function->type_params[i], param_name_length)) {
						return false;
					}
				}
				if (!buffer_append(builder, &type_argument_count, sizeof type_argument_count)) {
					return false;
				}
				for (uint8_t i = 0; i < type_argument_count; ++i) {
					uint8_t argument_tag = function ? (uint8_t)function->type_arguments[i] : (uint8_t)PROTO_TYPE_ANY;
					if (!buffer_append(builder, &argument_tag, sizeof argument_tag)) {
						return false;
					}
				}
				if (!buffer_append(builder, &binding_count, sizeof binding_count)) {
					return false;
				}
				for (uint8_t i = 0; i < binding_count; ++i) {
					uint8_t binding_tag = function ? (uint8_t)function->bindings.entries[i].tag : (uint8_t)PROTO_TYPE_ANY;
					int8_t binding_param = function ? function->bindings.entries[i].param : -1;
					if (!buffer_append(builder, &binding_tag, sizeof binding_tag) ||
					    !buffer_append(builder, &binding_param, sizeof binding_param)) {
						return false;
					}
				}
				for (uint8_t i = 0; i < arity; ++i) {
					uint8_t param_type = function ? (uint8_t)function->param_types[i] : (uint8_t)PROTO_TYPE_ANY;
					int8_t param_binding = function ? function->param_type_params[i] : -1;
					if (!buffer_append(builder, &param_type, sizeof param_type) ||
					    !buffer_append(builder, &param_binding, sizeof param_binding)) {
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

static bool serialize_binding_map(const ProtoChunk *chunk, BufferBuilder *builder) {
	for (size_t i = 0; i < chunk->binding_entry_count; ++i) {
		const ProtoBindingMapEntry *entry = &chunk->binding_entries[i];
		if (!buffer_append_u32(builder, entry->symbol_index)) {
			return false;
		}
		uint8_t binding_count = entry->bindings.count;
		if (!buffer_append_u8(builder, binding_count)) {
			return false;
		}
		for (uint8_t bi = 0; bi < binding_count; ++bi) {
			uint8_t tag = (uint8_t)entry->bindings.entries[bi].tag;
			int8_t param = entry->bindings.entries[bi].param;
			if (!buffer_append_u8(builder, tag) || !buffer_append(builder, &param, sizeof param)) {
				return false;
			}
		}
	}
	return true;
}

static bool serialize_extension_spec(const ProtoExtensionTypeSpec *spec, BufferBuilder *builder) {
	if (!spec) {
		return false;
	}
	uint32_t name_length = (uint32_t)strlen(spec->name);
	if (!buffer_append_u32(builder, name_length)) {
		return false;
	}
	if (name_length > 0 && !buffer_append(builder, spec->name, name_length)) {
		return false;
	}
	uint8_t binding_count = spec->bindings.count;
	if (!buffer_append_u8(builder, binding_count)) {
		return false;
	}
	for (uint8_t i = 0; i < binding_count; ++i) {
		uint8_t tag = (uint8_t)spec->bindings.entries[i].tag;
		int8_t param = spec->bindings.entries[i].param;
		if (!buffer_append_u8(builder, tag) || !buffer_append(builder, &param, sizeof param)) {
			return false;
		}
	}
	uint8_t label_count = spec->label_count;
	if (!buffer_append_u8(builder, label_count)) {
		return false;
	}
	for (uint8_t i = 0; i < label_count; ++i) {
		uint32_t label_length = (uint32_t)strlen(spec->labels[i]);
		if (!buffer_append_u32(builder, label_length)) {
			return false;
		}
		if (label_length > 0 && !buffer_append(builder, spec->labels[i], label_length)) {
			return false;
		}
	}
	return true;
}

static bool serialize_extensions(const ProtoChunk *chunk, BufferBuilder *builder) {
	for (size_t i = 0; i < chunk->extension_count; ++i) {
		const ProtoExtensionDecl *decl = &chunk->extensions[i];
		uint8_t kind = (uint8_t)decl->target_kind;
		if (!buffer_append_u8(builder, kind)) {
			return false;
		}
		if (!serialize_extension_spec(&decl->target, builder)) {
			return false;
		}
		uint8_t trait_count = decl->trait_count;
		if (!buffer_append_u8(builder, trait_count)) {
			return false;
		}
		for (uint8_t t = 0; t < trait_count; ++t) {
			if (!serialize_extension_spec(&decl->traits[t], builder)) {
				return false;
			}
		}
		uint32_t line = (uint32_t)decl->line;
		if (!buffer_append_u32(builder, line)) {
			return false;
		}
		uint32_t body_length = (uint32_t)decl->body_length;
		if (!buffer_append_u32(builder, body_length)) {
			return false;
		}
		if (body_length > 0 && decl->body_source) {
			if (!buffer_append(builder, decl->body_source, body_length)) {
				return false;
			}
		}
	}
	return true;
}

static bool deserialize_extension_spec(BufferReader *reader, ProtoExtensionTypeSpec *spec, ProtoError *error) {
	if (!reader || !spec || !error) {
		return false;
	}
	memset(spec, 0, sizeof *spec);
	uint32_t name_length = 0;
	if (!reader_read_u32(reader, &name_length)) {
		protoerror_set(error, 0, "Failed to read extension name length");
		return false;
	}
	if (name_length >= sizeof spec->name) {
		protoerror_set(error, 0, "Extension name is too long");
		return false;
	}
	if (name_length > 0) {
		if (!reader_read(reader, spec->name, name_length)) {
			protoerror_set(error, 0, "Failed to read extension name");
			return false;
		}
	}
	spec->name[name_length] = '\0';
	uint8_t binding_count = 0;
	if (!reader_read_u8(reader, &binding_count)) {
		protoerror_set(error, 0, "Failed to read extension binding count");
		return false;
	}
	if (binding_count > PROTOHACK_MAX_TYPE_PARAMS) {
		protoerror_set(error, 0, "Extension binding count exceeds limit");
		return false;
	}
	spec->bindings.count = binding_count;
	for (uint8_t i = 0; i < binding_count; ++i) {
		uint8_t tag = 0;
		int8_t param = -1;
		if (!reader_read_u8(reader, &tag) || !reader_read(reader, &param, sizeof param)) {
			protoerror_set(error, 0, "Failed to read extension binding entry");
			return false;
		}
		spec->bindings.entries[i].tag = (ProtoTypeTag)tag;
		spec->bindings.entries[i].param = param;
	}
	uint8_t label_count = 0;
	if (!reader_read_u8(reader, &label_count)) {
		protoerror_set(error, 0, "Failed to read extension label count");
		return false;
	}
	if (label_count > PROTOHACK_MAX_TYPE_PARAMS) {
		protoerror_set(error, 0, "Extension label count exceeds limit");
		return false;
	}
	spec->label_count = label_count;
	for (uint8_t i = 0; i < label_count; ++i) {
		uint32_t label_length = 0;
		if (!reader_read_u32(reader, &label_length)) {
			protoerror_set(error, 0, "Failed to read extension label length");
			return false;
		}
		if (label_length >= sizeof spec->labels[i]) {
			protoerror_set(error, 0, "Extension label is too long");
			return false;
		}
		if (label_length > 0) {
			if (!reader_read(reader, spec->labels[i], label_length)) {
				protoerror_set(error, 0, "Failed to read extension label");
				return false;
			}
		}
		spec->labels[i][label_length] = '\0';
	}
	return true;
}

static bool deserialize_extensions(ProtoChunk *chunk, BufferReader *reader, uint32_t extension_count, ProtoError *error) {
	if (!chunk || !reader || !error) {
		return false;
	}
	if (extension_count == 0) {
		return true;
	}
	ProtoExtensionDecl *entries = (ProtoExtensionDecl *)calloc(extension_count, sizeof *entries);
	if (!entries) {
		protoerror_set(error, 0, "Failed to allocate extension metadata");
		return false;
	}
	for (uint32_t i = 0; i < extension_count; ++i) {
		ProtoExtensionDecl *decl = &entries[i];
		uint8_t kind = 0;
		if (!reader_read_u8(reader, &kind)) {
			protoerror_set(error, 0, "Failed to read extension target kind");
			goto fail;
		}
		decl->target_kind = (ProtoExtensionTargetKind)kind;
		if (!deserialize_extension_spec(reader, &decl->target, error)) {
			goto fail;
		}
		uint8_t trait_count = 0;
		if (!reader_read_u8(reader, &trait_count)) {
			protoerror_set(error, 0, "Failed to read extension trait count");
			goto fail;
		}
		if (trait_count > PROTOHACK_MAX_EXTENSION_TRAITS) {
			protoerror_set(error, 0, "Extension trait count exceeds limit");
			goto fail;
		}
		decl->trait_count = trait_count;
		for (uint8_t t = 0; t < trait_count; ++t) {
			if (!deserialize_extension_spec(reader, &decl->traits[t], error)) {
				goto fail;
			}
		}
		uint32_t line = 0;
		if (!reader_read_u32(reader, &line)) {
			protoerror_set(error, 0, "Failed to read extension line info");
			goto fail;
		}
		decl->line = line;
		uint32_t body_length = 0;
		if (!reader_read_u32(reader, &body_length)) {
			protoerror_set(error, 0, "Failed to read extension body length");
			goto fail;
		}
		decl->body_length = body_length;
		if (body_length > 0) {
			char *body = (char *)malloc(body_length + 1);
			if (!body) {
				protoerror_set(error, 0, "Failed to allocate extension body");
				goto fail;
			}
			if (!reader_read(reader, body, body_length)) {
				free(body);
				protoerror_set(error, 0, "Failed to read extension body");
				goto fail;
			}
			body[body_length] = '\0';
			decl->body_source = body;
		}
	}
	chunk->extensions = entries;
	chunk->extension_count = extension_count;
	chunk->extension_capacity = extension_count;
	return true;

fail:
	for (uint32_t j = 0; j < extension_count; ++j) {
		free(entries[j].body_source);
	}
	free(entries);
	return false;
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

	const size_t max_binding_entries = (size_t)0xFFFFFFFFu;
	if (chunk->binding_entry_count > max_binding_entries) {
		free(builder.data);
		protoerror_set(error, 0, "Binding map too large to serialize");
		return false;
	}
	uint32_t binding_count = (uint32_t)chunk->binding_entry_count;
	if (chunk->extension_count > max_binding_entries) {
		free(builder.data);
		protoerror_set(error, 0, "Extension table too large to serialize");
		return false;
	}
	uint32_t extension_count = (uint32_t)chunk->extension_count;
	uint32_t flags = chunk->module_flags;
	if (binding_count > 0) {
		flags |= PROTOHACK_MODULE_FLAG_HAS_BINDING_MAP;
	} else {
		flags &= ~PROTOHACK_MODULE_FLAG_HAS_BINDING_MAP;
	}
	if (extension_count > 0) {
		flags |= PROTOHACK_MODULE_FLAG_HAS_EXTENSIONS;
	} else {
		flags &= ~PROTOHACK_MODULE_FLAG_HAS_EXTENSIONS;
	}

	ProtoModuleHeader header = {
		.version = PROTOHACK_MODULE_VERSION,
		.flags = flags,
		.code_count = code_count,
		.constants_count = constants_count,
		.globals_count = globals_count,
		.lines_count = lines_count,
		.binding_count = binding_count,
		.extension_count = extension_count
	};

	if (ok) {
		ok = buffer_append_u32(&builder, header.version) &&
		     buffer_append_u32(&builder, header.flags) &&
		     buffer_append_u32(&builder, header.code_count) &&
		     buffer_append_u32(&builder, header.constants_count) &&
		     buffer_append_u32(&builder, header.globals_count) &&
		     buffer_append_u32(&builder, header.lines_count) &&
		     buffer_append_u32(&builder, header.binding_count) &&
		     buffer_append_u32(&builder, header.extension_count);
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
	if (ok) {
		ok = serialize_binding_map(chunk, &builder);
	}
	if (ok) {
		ok = serialize_extensions(chunk, &builder);
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
				int8_t return_binding = -1;
				uint8_t type_param_count = 0;
				uint8_t type_argument_count = 0;
				uint8_t binding_count = 0;
				if (!reader_read(reader, &kind, sizeof kind) ||
				    !reader_read(reader, &arity, sizeof arity) ||
				    !reader_read(reader, &return_type, sizeof return_type) ||
				    !reader_read(reader, &return_binding, sizeof return_binding) ||
				    !reader_read(reader, &type_param_count, sizeof type_param_count)) {
					protoerror_set(error, 0, "Failed to read function header");
					return false;
				}
				if (type_param_count > PROTOHACK_MAX_TYPE_PARAMS) {
					protoerror_set(error, 0, "Function exceeds maximum type parameters");
					return false;
				}
				ProtoFunction *function = proto_function_new((ProtoFunctionKind)kind, NULL);
				function->arity = arity;
				function->return_type = (ProtoTypeTag)return_type;
				function->return_type_param = return_binding;
				char *allocated_names[PROTOHACK_MAX_TYPE_PARAMS] = {0};
				const char *name_views[PROTOHACK_MAX_TYPE_PARAMS] = {0};
				for (uint8_t pi = 0; pi < type_param_count; ++pi) {
					uint32_t name_length = 0;
					if (!reader_read_u32(reader, &name_length)) {
						protoerror_set(error, 0, "Failed to read type parameter name length");
						goto function_read_fail;
					}
					char *name_buffer = (char *)malloc(name_length + 1);
					if (!name_buffer) {
						protoerror_set(error, 0, "Failed to allocate type parameter name");
						goto function_read_fail;
					}
					if (name_length > 0 && !reader_read(reader, name_buffer, name_length)) {
						free(name_buffer);
						protoerror_set(error, 0, "Failed to read type parameter name");
						goto function_read_fail;
					}
					name_buffer[name_length] = '\0';
					allocated_names[pi] = name_buffer;
					name_views[pi] = name_buffer;
				}
				if (!proto_function_set_type_params(function, name_views, type_param_count)) {
					protoerror_set(error, 0, "Failed to record type parameters");
					goto function_read_fail;
				}
				for (uint8_t pi = 0; pi < type_param_count; ++pi) {
					free(allocated_names[pi]);
					allocated_names[pi] = NULL;
				}
				if (!reader_read(reader, &type_argument_count, sizeof type_argument_count)) {
					protoerror_set(error, 0, "Failed to read type argument count");
					goto function_read_fail;
				}
				if (type_argument_count > PROTOHACK_MAX_TYPE_PARAMS) {
					protoerror_set(error, 0, "Function exceeds maximum type arguments");
					goto function_read_fail;
				}
				ProtoTypeTag argument_tags[PROTOHACK_MAX_TYPE_PARAMS] = {0};
				for (uint8_t ai = 0; ai < type_argument_count; ++ai) {
					uint8_t tag = 0;
					if (!reader_read(reader, &tag, sizeof tag)) {
						protoerror_set(error, 0, "Failed to read type argument");
						goto function_read_fail;
					}
					argument_tags[ai] = (ProtoTypeTag)tag;
				}
				if (!proto_function_set_type_arguments(function, argument_tags, type_argument_count)) {
					protoerror_set(error, 0, "Failed to record type arguments");
					goto function_read_fail;
				}
				if (!reader_read(reader, &binding_count, sizeof binding_count)) {
					protoerror_set(error, 0, "Failed to read binding count");
					goto function_read_fail;
				}
				if (binding_count > PROTOHACK_MAX_TYPE_PARAMS) {
					protoerror_set(error, 0, "Function exceeds maximum type bindings");
					goto function_read_fail;
				}
				function->bindings.count = binding_count;
				for (uint8_t bi = 0; bi < PROTOHACK_MAX_TYPE_PARAMS; ++bi) {
					function->bindings.entries[bi].tag = PROTO_TYPE_ANY;
					function->bindings.entries[bi].param = -1;
				}
				for (uint8_t bi = 0; bi < binding_count; ++bi) {
					uint8_t tag = 0;
					int8_t param = -1;
					if (!reader_read(reader, &tag, sizeof tag) ||
					    !reader_read(reader, &param, sizeof param)) {
						protoerror_set(error, 0, "Failed to read type binding");
						goto function_read_fail;
					}
					function->bindings.entries[bi].tag = (ProtoTypeTag)tag;
					function->bindings.entries[bi].param = param;
				}
				for (uint8_t pi = 0; pi < arity; ++pi) {
					uint8_t param_type = 0;
					int8_t param_binding = -1;
					if (!reader_read(reader, &param_type, sizeof param_type) ||
					    !reader_read(reader, &param_binding, sizeof param_binding)) {
						protoerror_set(error, 0, "Failed to read function parameter metadata");
						goto function_read_fail;
					}
					function->param_types[pi] = (ProtoTypeTag)param_type;
					function->param_type_params[pi] = param_binding;
				}
				uint32_t name_length = 0;
				if (!reader_read_u32(reader, &name_length)) {
					protoerror_set(error, 0, "Failed to read function name length");
					goto function_read_fail;
				}
				free(function->name);
				function->name = NULL;
				if (name_length > 0) {
					char *name_buffer = (char *)malloc(name_length + 1);
					if (!name_buffer) {
						protoerror_set(error, 0, "Failed to allocate function name");
						goto function_read_fail;
					}
					if (!reader_read(reader, name_buffer, name_length)) {
						free(name_buffer);
						protoerror_set(error, 0, "Failed to read function name");
						goto function_read_fail;
					}
					name_buffer[name_length] = '\0';
					function->name = name_buffer;
				}
				uint32_t chunk_size = 0;
				if (!reader_read_u32(reader, &chunk_size)) {
					protoerror_set(error, 0, "Failed to read function chunk size");
					goto function_read_fail;
				}
				uint8_t *chunk_data = NULL;
				if (chunk_size > 0) {
					chunk_data = (uint8_t *)malloc(chunk_size);
					if (!chunk_data) {
						protoerror_set(error, 0, "Failed to allocate function chunk");
						goto function_read_fail;
					}
					if (!reader_read(reader, chunk_data, chunk_size)) {
						free(chunk_data);
						protoerror_set(error, 0, "Failed to read function chunk data");
						goto function_read_fail;
					}
				}
				ProtoError fn_error;
				protoerror_reset(&fn_error);
				if (chunk_size > 0 && !protochunk_deserialize_from_memory(&function->chunk, chunk_data, chunk_size, &fn_error)) {
					free(chunk_data);
					protoerror_set(error, 0, "Failed to deserialize function chunk");
					goto function_read_fail;
				}
				free(chunk_data);
				chunk->constants[i] = proto_value_function(function);
				break;
			function_read_fail:
				for (uint8_t ni = 0; ni < PROTOHACK_MAX_TYPE_PARAMS; ++ni) {
					if (allocated_names[ni]) {
						free(allocated_names[ni]);
					}
				}
				proto_function_free(function);
				return false;
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

static bool deserialize_binding_map(ProtoChunk *chunk, BufferReader *reader, uint32_t binding_count, ProtoError *error) {
	if (binding_count == 0) {
		chunk->binding_entries = NULL;
		chunk->binding_entry_count = 0;
		chunk->binding_entry_capacity = 0;
		return true;
	}

	ProtoBindingMapEntry *entries = (ProtoBindingMapEntry *)calloc(binding_count, sizeof(ProtoBindingMapEntry));
	if (!entries) {
		protoerror_set(error, 0, "Failed to allocate binding map");
		return false;
	}

	for (uint32_t i = 0; i < binding_count; ++i) {
		uint32_t symbol_index = 0;
		uint8_t binding_slots = 0;
		if (!reader_read_u32(reader, &symbol_index)) {
			free(entries);
			protoerror_set(error, 0, "Failed to read binding map symbol index");
			return false;
		}
		if (!reader_read_u8(reader, &binding_slots)) {
			free(entries);
			protoerror_set(error, 0, "Failed to read binding count");
			return false;
		}
		if (binding_slots > PROTOHACK_MAX_TYPE_PARAMS) {
			free(entries);
			protoerror_set(error, 0, "Binding count exceeds maximum type parameters");
			return false;
		}
		entries[i].symbol_index = symbol_index;
		entries[i].bindings.count = binding_slots;
		for (uint8_t bi = 0; bi < PROTOHACK_MAX_TYPE_PARAMS; ++bi) {
			entries[i].bindings.entries[bi].tag = PROTO_TYPE_ANY;
			entries[i].bindings.entries[bi].param = -1;
		}
		for (uint8_t bi = 0; bi < binding_slots; ++bi) {
			uint8_t tag = 0;
			int8_t param = -1;
			if (!reader_read_u8(reader, &tag) || !reader_read_i8(reader, &param)) {
				free(entries);
				protoerror_set(error, 0, "Failed to read binding entry");
				return false;
			}
			entries[i].bindings.entries[bi].tag = (ProtoTypeTag)tag;
			entries[i].bindings.entries[bi].param = param;
		}
		if (symbol_index >= chunk->globals_count) {
			free(entries);
			protoerror_set(error, 0, "Binding entry references invalid global index");
			return false;
		}
	}

	chunk->binding_entries = entries;
	chunk->binding_entry_count = binding_count;
	chunk->binding_entry_capacity = binding_count;
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
	if (!reader_read(&reader, magic, magic_len)) {
		protoerror_set(error, 0, "Failed to read bytecode magic");
		return false;
	}

	uint32_t code_count = 0;
	uint32_t constants_count = 0;
	uint32_t globals_count = 0;
	uint32_t lines_count = 0;
	uint32_t binding_count = 0;
	uint32_t extension_count = 0;
	uint32_t module_version = 1;
	uint32_t module_flags = 0;

	if (memcmp(magic, PROTOHACK_BYTECODE_MAGIC, magic_len) == 0) {
		ProtoModuleHeader header = {0};
		if (!reader_read_u32(&reader, &header.version) ||
		    !reader_read_u32(&reader, &header.flags) ||
		    !reader_read_u32(&reader, &header.code_count) ||
		    !reader_read_u32(&reader, &header.constants_count) ||
		    !reader_read_u32(&reader, &header.globals_count) ||
		    !reader_read_u32(&reader, &header.lines_count) ||
		    !reader_read_u32(&reader, &header.binding_count)) {
			protoerror_set(error, 0, "Failed to read module header");
			return false;
		}
		if (header.version >= 3) {
			if (!reader_read_u32(&reader, &header.extension_count)) {
				protoerror_set(error, 0, "Failed to read module extension count");
				return false;
			}
		} else {
			header.extension_count = 0;
		}
		if (header.version > PROTOHACK_MODULE_VERSION) {
			protoerror_set(error, 0, "Unsupported module version");
			return false;
		}
		module_version = header.version;
		module_flags = header.flags;
		code_count = header.code_count;
		constants_count = header.constants_count;
		globals_count = header.globals_count;
		lines_count = header.lines_count;
		binding_count = header.binding_count;
		extension_count = header.extension_count;
	} else if (memcmp(magic, PROTOHACK_BYTECODE_MAGIC_LEGACY, magic_len) == 0) {
		if (!reader_read_u32(&reader, &code_count) ||
		    !reader_read_u32(&reader, &constants_count) ||
		    !reader_read_u32(&reader, &globals_count) ||
		    !reader_read_u32(&reader, &lines_count)) {
			protoerror_set(error, 0, "Failed to read legacy chunk header");
			return false;
		}
		module_version = 1;
		module_flags = 0;
		binding_count = 0;
		extension_count = 0;
	} else {
		protoerror_set(error, 0, "Invalid bytecode magic");
		return false;
	}

	protochunk_free(chunk);
	protochunk_init(chunk);
	chunk->module_version = module_version;
	chunk->module_flags = module_flags;

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

	if (!deserialize_binding_map(chunk, &reader, binding_count, error)) {
		return false;
	}

	if (module_version >= 3) {
		if (!deserialize_extensions(chunk, &reader, extension_count, error)) {
			return false;
		}
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
