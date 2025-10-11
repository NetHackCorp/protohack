#include "protohack/function.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "protohack/error.h"
#include "protohack/internal/common.h"
#include "protohack/serialize.h"

ProtoFunction *proto_function_new(ProtoFunctionKind kind, const char *name) {
    ProtoFunction *function = (ProtoFunction *)calloc(1, sizeof(ProtoFunction));
    if (!function) {
        PROTOHACK_FATAL("Failed to allocate ProtoFunction");
    }
    function->kind = kind;
    function->arity = 0;
    function->return_type = PROTO_TYPE_NONE;
    function->type_param_count = 0;
    function->return_type_param = -1;
    for (size_t i = 0; i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
        function->type_params[i] = NULL;
    }
    for (size_t i = 0; i < PROTOHACK_MAX_PARAMS; ++i) {
        function->param_type_params[i] = -1;
        function->param_types[i] = PROTO_TYPE_ANY;
    }
    function->type_argument_count = 0;
    for (size_t i = 0; i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
        function->type_arguments[i] = PROTO_TYPE_ANY;
    }
    function->bindings.count = 0;
    for (size_t i = 0; i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
        function->bindings.entries[i].tag = PROTO_TYPE_ANY;
        function->bindings.entries[i].param = -1;
    }
    function->template_origin = NULL;
    function->name = name ? protohack_copy_string(name, strlen(name)) : NULL;
    protochunk_init(&function->chunk);
    return function;
}

void proto_function_free(ProtoFunction *function) {
    if (!function) {
        return;
    }
    for (size_t i = 0; i < function->type_param_count && i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
        free(function->type_params[i]);
        function->type_params[i] = NULL;
    }
    function->type_param_count = 0;
    free(function->name);
    function->name = NULL;
    protochunk_free(&function->chunk);
    free(function);
}

ProtoFunction *proto_function_copy(const ProtoFunction *function) {
    if (!function) {
        return NULL;
    }
    ProtoFunction *copy = proto_function_new(function->kind, function->name);
    copy->arity = function->arity;
    copy->return_type = function->return_type;
    memcpy(copy->param_types, function->param_types, sizeof(function->param_types));
    memcpy(copy->param_type_params, function->param_type_params, sizeof(function->param_type_params));
    copy->return_type_param = function->return_type_param;
    copy->bindings = function->bindings;
    copy->template_origin = function->template_origin;
    const char *params[PROTOHACK_MAX_TYPE_PARAMS];
    for (size_t i = 0; i < function->type_param_count && i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
        params[i] = function->type_params[i];
    }
    proto_function_set_type_params(copy, params, function->type_param_count);
    proto_function_set_type_arguments(copy, function->type_arguments, function->type_argument_count);

    // Deep copy the chunk by serializing and deserializing
    ProtoError error;
    protoerror_reset(&error);
    ProtoSerializedBuffer buffer = {0};
    if (!protochunk_serialize_to_buffer(&function->chunk, &buffer, &error)) {
        PROTOHACK_FATAL("Failed to clone function chunk");
    }
    if (!protochunk_deserialize_from_memory(&copy->chunk, buffer.data, buffer.size, &error)) {
        protochunk_buffer_free(&buffer);
        PROTOHACK_FATAL("Failed to deserialize cloned function chunk");
    }
    protochunk_buffer_free(&buffer);
    return copy;
}

bool proto_function_set_type_params(ProtoFunction *function, const char *const *params, uint8_t count) {
    if (!function) {
        return false;
    }
    for (size_t i = 0; i < function->type_param_count && i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
        free(function->type_params[i]);
        function->type_params[i] = NULL;
    }
    function->type_param_count = 0;
    if (!params || count == 0) {
        return true;
    }
    if (count > PROTOHACK_MAX_TYPE_PARAMS) {
        return false;
    }
    for (uint8_t i = 0; i < count; ++i) {
        const char *name = params[i] ? params[i] : "";
        char *copy = protohack_copy_string(name, strlen(name));
        if (!copy) {
            return false;
        }
        function->type_params[i] = copy;
    }
    function->type_param_count = count;
    return true;
}

bool proto_function_set_type_arguments(ProtoFunction *function, const ProtoTypeTag *arguments, uint8_t count) {
    if (!function) {
        return false;
    }
    if (count > PROTOHACK_MAX_TYPE_PARAMS) {
        return false;
    }
    function->type_argument_count = count;
    for (size_t i = 0; i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
        if (i < count && arguments) {
            function->type_arguments[i] = arguments[i];
        } else {
            function->type_arguments[i] = PROTO_TYPE_ANY;
        }
    }
    return true;
}

bool proto_function_set_name(ProtoFunction *function, const char *name) {
    if (!function) {
        return false;
    }
    char *copy = protohack_copy_string(name ? name : "", name ? strlen(name) : 0);
    if (!copy) {
        return false;
    }
    free(function->name);
    function->name = copy;
    return true;
}

bool proto_function_format_specialization_name(const char *base_name,
                                               const ProtoFunction *template_function,
                                               const ProtoTypeBindingSet *bindings,
                                               const char *const *labels,
                                               uint8_t label_count,
                                               char *buffer,
                                               size_t buffer_size) {
    if (!buffer || buffer_size == 0) {
        return false;
    }

    const char *effective_base = base_name && base_name[0] != '\0' ? base_name : NULL;
    if (!effective_base && template_function && template_function->name) {
        effective_base = template_function->name;
    }
    if (!effective_base) {
        effective_base = "<craft>";
    }

    const char *angle = strchr(effective_base, '<');
    size_t base_length = angle ? (size_t)(angle - effective_base) : strlen(effective_base);
    if (base_length >= buffer_size) {
        return false;
    }

    memcpy(buffer, effective_base, base_length);
    size_t offset = base_length;
    buffer[offset] = '\0';

    uint8_t count = bindings ? bindings->count : 0;
    if (count > PROTOHACK_MAX_TYPE_PARAMS) {
        count = PROTOHACK_MAX_TYPE_PARAMS;
    }

    if (count == 0) {
        buffer[offset] = '\0';
        return true;
    }

    if (offset + 1 >= buffer_size) {
        return false;
    }
    buffer[offset++] = '<';

    for (uint8_t i = 0; i < count; ++i) {
        if (i > 0) {
            if (offset + 1 >= buffer_size) {
                return false;
            }
            buffer[offset++] = ',';
        }

        const ProtoTypeBinding *binding = bindings ? &bindings->entries[i] : NULL;
        const char *label = NULL;
        char fallback[32] = {0};

        if (labels && i < label_count && labels[i] && labels[i][0] != '\0') {
            label = labels[i];
        }

        if ((!label || label[0] == '\0') && binding) {
            if (binding->tag != PROTO_TYPE_ANY && binding->param < 0) {
                label = proto_type_tag_name(binding->tag);
            } else if (binding->param >= 0) {
                const char *param_name = NULL;
                if (template_function && (uint8_t)binding->param < template_function->type_param_count) {
                    param_name = template_function->type_params[(uint8_t)binding->param];
                }
                if (param_name && param_name[0] != '\0') {
                    label = param_name;
                } else {
                    snprintf(fallback, sizeof fallback, "T%u", (unsigned)((uint8_t)binding->param));
                    label = fallback;
                }
            }
        }

        if (!label || label[0] == '\0') {
            label = "any";
        }

        size_t label_length = strlen(label);
        if (offset + label_length >= buffer_size) {
            return false;
        }
        memcpy(buffer + offset, label, label_length);
        offset += label_length;
        buffer[offset] = '\0';
    }

    if (offset + 1 >= buffer_size) {
        return false;
    }
    buffer[offset++] = '>';
    if (offset >= buffer_size) {
        return false;
    }
    buffer[offset] = '\0';
    return true;
}

uint8_t proto_function_type_param_count(const ProtoFunction *function) {
    return function ? function->type_param_count : 0u;
}

const char *proto_function_type_param_name(const ProtoFunction *function, uint8_t index) {
    if (!function || index >= function->type_param_count || index >= PROTOHACK_MAX_TYPE_PARAMS) {
        return NULL;
    }
    return function->type_params[index];
}

uint8_t proto_function_type_argument_count(const ProtoFunction *function) {
    return function ? function->type_argument_count : 0u;
}

ProtoTypeTag proto_function_type_argument(const ProtoFunction *function, uint8_t index) {
    if (!function || index >= function->type_argument_count || index >= PROTOHACK_MAX_TYPE_PARAMS) {
        return PROTO_TYPE_ANY;
    }
    return function->type_arguments[index];
}

int8_t proto_function_param_type_binding(const ProtoFunction *function, uint8_t index) {
    if (!function || index >= function->arity || index >= PROTOHACK_MAX_PARAMS) {
        return -1;
    }
    return function->param_type_params[index];
}

int8_t proto_function_return_type_binding(const ProtoFunction *function) {
    return function ? function->return_type_param : -1;
}

typedef struct {
    char *data;
    size_t length;
    size_t capacity;
} ProtoStringBuilder;

static bool proto_string_builder_reserve(ProtoStringBuilder *builder, size_t additional) {
    if (!builder) {
        return false;
    }
    size_t required = builder->length + additional + 1;
    if (required <= builder->capacity) {
        return true;
    }
    size_t new_capacity = builder->capacity == 0 ? 128 : builder->capacity;
    while (new_capacity < required) {
        new_capacity = GROW_CAPACITY(new_capacity);
    }
    char *new_data = (char *)realloc(builder->data, new_capacity);
    if (!new_data) {
        return false;
    }
    builder->data = new_data;
    builder->capacity = new_capacity;
    return true;
}

static bool proto_string_builder_append(ProtoStringBuilder *builder, const char *text) {
    if (!builder || !text) {
        return false;
    }
    size_t len = strlen(text);
    if (!proto_string_builder_reserve(builder, len)) {
        return false;
    }
    memcpy(builder->data + builder->length, text, len);
    builder->length += len;
    builder->data[builder->length] = '\0';
    return true;
}

static bool proto_string_builder_append_char(ProtoStringBuilder *builder, char ch) {
    if (!builder) {
        return false;
    }
    if (!proto_string_builder_reserve(builder, 1)) {
        return false;
    }
    builder->data[builder->length++] = ch;
    builder->data[builder->length] = '\0';
    return true;
}

static bool proto_string_builder_append_format(ProtoStringBuilder *builder, const char *format, ...) {
    if (!builder || !format) {
        return false;
    }
    va_list args;
    va_start(args, format);
    int needed = vsnprintf(NULL, 0, format, args);
    va_end(args);
    if (needed < 0) {
        return false;
    }
    if (!proto_string_builder_reserve(builder, (size_t)needed)) {
        return false;
    }
    va_start(args, format);
    vsnprintf(builder->data + builder->length, builder->capacity - builder->length, format, args);
    va_end(args);
    builder->length += (size_t)needed;
    return true;
}

static const char *proto_function_kind_label(ProtoFunctionKind kind) {
    switch (kind) {
        case PROTO_FUNC_SCRIPT:
            return "script";
        case PROTO_FUNC_CRAFT:
            return "craft";
        case PROTO_FUNC_METHOD:
            return "method";
        case PROTO_FUNC_INITIALIZER:
            return "initializer";
        default:
            return "function";
    }
}

char *proto_function_debug_description(const ProtoFunction *function) {
    if (!function) {
        return protohack_copy_string("<null function>", 15);
    }

    ProtoStringBuilder builder = {0};
    if (!proto_string_builder_reserve(&builder, 128)) {
        return NULL;
    }
    builder.data[0] = '\0';

#define CHECK_APPEND(call)            \
    do {                              \
        if (!(call)) {                \
            free(builder.data);       \
            return NULL;              \
        }                             \
    } while (0)

    const char *kind_label = proto_function_kind_label(function->kind);
    const char *name = function->name ? function->name : "<anonymous>";
    bool name_has_generics = name && strchr(name, '<') != NULL;

    CHECK_APPEND(proto_string_builder_append_format(&builder, "%s %s", kind_label, name));

    uint8_t type_param_count = proto_function_type_param_count(function);
    if (type_param_count > 0 && !name_has_generics) {
        CHECK_APPEND(proto_string_builder_append_char(&builder, '<'));
        for (uint8_t i = 0; i < type_param_count; ++i) {
            if (i > 0) {
                CHECK_APPEND(proto_string_builder_append(&builder, ", "));
            }
            const char *param_name = proto_function_type_param_name(function, i);
            if (param_name) {
                CHECK_APPEND(proto_string_builder_append(&builder, param_name));
            } else {
                char fallback[8];
                snprintf(fallback, sizeof fallback, "T%u", i);
                CHECK_APPEND(proto_string_builder_append(&builder, fallback));
            }
        }
        CHECK_APPEND(proto_string_builder_append_char(&builder, '>'));
    }

    CHECK_APPEND(proto_string_builder_append_char(&builder, '('));
    for (uint8_t i = 0; i < function->arity; ++i) {
        if (i > 0) {
            CHECK_APPEND(proto_string_builder_append(&builder, ", "));
        }
        const char *type_name = proto_type_tag_name(function->param_types[i]);
        CHECK_APPEND(proto_string_builder_append(&builder, type_name ? type_name : "unknown"));
        int8_t binding_index = proto_function_param_type_binding(function, i);
        if (binding_index >= 0) {
            const char *binding_name = proto_function_type_param_name(function, (uint8_t)binding_index);
            char fallback[8];
            if (!binding_name) {
                snprintf(fallback, sizeof fallback, "T%u", (uint8_t)binding_index);
                binding_name = fallback;
            }
            CHECK_APPEND(proto_string_builder_append_format(&builder, " as %s", binding_name));
        }
    }
    CHECK_APPEND(proto_string_builder_append_char(&builder, ')'));

    const char *return_type_name = proto_type_tag_name(function->return_type);
    CHECK_APPEND(proto_string_builder_append_format(&builder, " -> %s", return_type_name ? return_type_name : "unknown"));

    int8_t return_binding = proto_function_return_type_binding(function);
    if (return_binding >= 0) {
        const char *binding_name = proto_function_type_param_name(function, (uint8_t)return_binding);
        char fallback[8];
        if (!binding_name) {
            snprintf(fallback, sizeof fallback, "T%u", (uint8_t)return_binding);
            binding_name = fallback;
        }
        CHECK_APPEND(proto_string_builder_append_format(&builder, " as %s", binding_name));
    }

    uint8_t type_argument_count = proto_function_type_argument_count(function);
    if (type_argument_count > 0) {
        CHECK_APPEND(proto_string_builder_append(&builder, " {"));
        for (uint8_t i = 0; i < type_argument_count; ++i) {
            if (i > 0) {
                CHECK_APPEND(proto_string_builder_append(&builder, ", "));
            }
            const char *param_name = proto_function_type_param_name(function, i);
            char fallback[8];
            if (!param_name) {
                snprintf(fallback, sizeof fallback, "T%u", i);
                param_name = fallback;
            }
            const char *arg_name = proto_type_tag_name(proto_function_type_argument(function, i));
            CHECK_APPEND(proto_string_builder_append_format(&builder, "%s=%s", param_name, arg_name ? arg_name : "any"));
        }
        CHECK_APPEND(proto_string_builder_append_char(&builder, '}'));
    }

    if (function->bindings.count > 0) {
        CHECK_APPEND(proto_string_builder_append(&builder, " [bindings{"));
        for (uint8_t i = 0; i < function->bindings.count; ++i) {
            if (i > 0) {
                CHECK_APPEND(proto_string_builder_append(&builder, ", "));
            }
            const char *slot_name = NULL;
            if (i < function->type_param_count) {
                slot_name = function->type_params[i];
            }
            char slot_fallback[8];
            if (!slot_name || slot_name[0] == '\0') {
                snprintf(slot_fallback, sizeof slot_fallback, "slot%u", i);
                slot_name = slot_fallback;
            }
            CHECK_APPEND(proto_string_builder_append(&builder, slot_name));
            CHECK_APPEND(proto_string_builder_append(&builder, "="));
            const ProtoTypeBinding *binding = &function->bindings.entries[i];
            if (binding->tag != PROTO_TYPE_ANY) {
                const char *tag_name = proto_type_tag_name(binding->tag);
                CHECK_APPEND(proto_string_builder_append(&builder, tag_name ? tag_name : "unknown"));
            } else if (binding->param >= 0) {
                const char *param_name = binding->param < function->type_param_count ? function->type_params[binding->param] : NULL;
                char param_fallback[8];
                if (!param_name || param_name[0] == '\0') {
                    snprintf(param_fallback, sizeof param_fallback, "T%u", (uint8_t)binding->param);
                    param_name = param_fallback;
                }
                CHECK_APPEND(proto_string_builder_append_format(&builder, "&%s", param_name));
            } else {
                CHECK_APPEND(proto_string_builder_append(&builder, "any"));
            }
        }
        CHECK_APPEND(proto_string_builder_append(&builder, "}]"));
    }

    char *result = protohack_copy_string(builder.data ? builder.data : "", builder.length);
    free(builder.data);
#undef CHECK_APPEND
    return result;
}
