#include "protohack/binding.h"

#include <stdio.h>
#include <string.h>

#include "protohack/types.h"

bool proto_binding_set_format(const ProtoTypeBindingSet *set, char *buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0) {
        return false;
    }
    buffer[0] = '\0';

    if (!set || set->count == 0) {
        if (buffer_size > 1) {
            strncpy(buffer, "[]", buffer_size - 1);
            buffer[buffer_size - 1] = '\0';
        }
        return true;
    }

    size_t offset = 0;
    int written = snprintf(buffer + offset, buffer_size - offset, "[");
    if (written < 0) {
        buffer[0] = '\0';
        return false;
    }
    offset += (size_t)written;

    uint8_t count = set->count;
    if (count > PROTOHACK_MAX_TYPE_PARAMS) {
        count = PROTOHACK_MAX_TYPE_PARAMS;
    }

    for (uint8_t i = 0; i < count; ++i) {
        if (offset + 1 >= buffer_size) {
            buffer[buffer_size - 1] = '\0';
            return false;
        }
        if (i > 0) {
            written = snprintf(buffer + offset, buffer_size - offset, ", ");
            if (written < 0) {
                buffer[0] = '\0';
                return false;
            }
            offset += (size_t)written;
        }

        const ProtoTypeBinding *binding = &set->entries[i];
        const char *label = NULL;
        char temp[32];

        if (binding->tag != PROTO_TYPE_ANY && binding->param < 0) {
            label = proto_type_tag_name(binding->tag);
            if (!label) {
                label = "any";
            }
            written = snprintf(buffer + offset, buffer_size - offset, "%s", label);
        } else if (binding->param >= 0) {
            snprintf(temp, sizeof temp, "T%u", (unsigned)binding->param);
            written = snprintf(buffer + offset, buffer_size - offset, "%s", temp);
        } else {
            written = snprintf(buffer + offset, buffer_size - offset, "any");
        }

        if (written < 0) {
            buffer[0] = '\0';
            return false;
        }
        offset += (size_t)written;
        if (offset >= buffer_size) {
            buffer[buffer_size - 1] = '\0';
            return false;
        }
    }

    if (offset + 2 >= buffer_size) {
        buffer[buffer_size - 1] = '\0';
        return false;
    }

    written = snprintf(buffer + offset, buffer_size - offset, "]");
    if (written < 0) {
        buffer[0] = '\0';
        return false;
    }
    offset += (size_t)written;
    if (offset >= buffer_size) {
        buffer[buffer_size - 1] = '\0';
        return false;
    }
    buffer[offset] = '\0';
    return true;
}
