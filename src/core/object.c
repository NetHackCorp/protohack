#include "protohack/object.h"

#include <stdlib.h>
#include <string.h>

#include "protohack/internal/common.h"
#include "protohack/value.h"

struct ProtoClass {
    char *name;
    ProtoMethodEntry *methods;
    size_t method_count;
    size_t method_capacity;
    size_t ref_count;
};

typedef struct ProtoFieldEntry {
    char *name;
    ProtoValue value;
} ProtoFieldEntry;

struct ProtoInstance {
    ProtoClass *klass;
    ProtoFieldEntry *fields;
    size_t field_count;
    size_t field_capacity;
    size_t ref_count;
};

struct ProtoBoundMethod {
    ProtoInstance *instance;
    ProtoFunction *method;
    size_t ref_count;
};

ProtoClass *proto_class_new(const char *name) {
    ProtoClass *klass = (ProtoClass *)calloc(1, sizeof(ProtoClass));
    if (!klass) {
        PROTOHACK_FATAL("Failed to allocate ProtoClass");
    }
    klass->name = protohack_copy_string(name ? name : "", name ? strlen(name) : 0);
    klass->methods = NULL;
    klass->method_count = 0;
    klass->method_capacity = 0;
    klass->ref_count = 1;
    return klass;
}

void proto_class_retain(ProtoClass *klass) {
    if (klass) {
        klass->ref_count++;
    }
}

static void proto_method_entry_free(ProtoMethodEntry *entry) {
    if (!entry) {
        return;
    }
    free(entry->name);
    entry->name = NULL;
    entry->function = NULL;
}

void proto_class_release(ProtoClass *klass) {
    if (!klass) {
        return;
    }
    if (klass->ref_count == 0) {
        return;
    }
    klass->ref_count--;
    if (klass->ref_count > 0) {
        return;
    }
    for (size_t i = 0; i < klass->method_count; ++i) {
        proto_method_entry_free(&klass->methods[i]);
    }
    free(klass->methods);
    klass->methods = NULL;
    klass->method_count = 0;
    klass->method_capacity = 0;
    free(klass->name);
    klass->name = NULL;
    free(klass);
}

const char *proto_class_name(const ProtoClass *klass) {
    return klass && klass->name ? klass->name : "";
}

static ProtoMethodEntry *proto_class_find_entry(const ProtoClass *klass, const char *name) {
    if (!klass || !name) {
        return NULL;
    }
    for (size_t i = 0; i < klass->method_count; ++i) {
        ProtoMethodEntry *entry = &((ProtoClass *)klass)->methods[i];
        if (entry->name && strcmp(entry->name, name) == 0) {
            return entry;
        }
    }
    return NULL;
}

ProtoFunction *proto_class_find_method(const ProtoClass *klass, const char *name) {
    ProtoMethodEntry *entry = proto_class_find_entry(klass, name);
    return entry ? entry->function : NULL;
}

bool proto_class_add_method(ProtoClass *klass, const char *name, ProtoFunction *function) {
    if (!klass || !name || !function) {
        return false;
    }
    ProtoMethodEntry *existing = proto_class_find_entry(klass, name);
    if (existing) {
        existing->function = function;
        return true;
    }

    ENSURE_CAPACITY(klass->methods, klass->method_count, klass->method_capacity, ProtoMethodEntry);
    ProtoMethodEntry *entry = &klass->methods[klass->method_count++];
    entry->name = protohack_copy_string(name, strlen(name));
    entry->function = function;
    return true;
}

ProtoInstance *proto_instance_new(ProtoClass *klass) {
    ProtoInstance *instance = (ProtoInstance *)calloc(1, sizeof(ProtoInstance));
    if (!instance) {
        PROTOHACK_FATAL("Failed to allocate ProtoInstance");
    }
    instance->klass = klass;
    proto_class_retain(klass);
    instance->fields = NULL;
    instance->field_count = 0;
    instance->field_capacity = 0;
    instance->ref_count = 1;
    return instance;
}

void proto_instance_retain(ProtoInstance *instance) {
    if (instance) {
        instance->ref_count++;
    }
}

static void proto_field_entry_free(ProtoFieldEntry *entry) {
    if (!entry) {
        return;
    }
    free(entry->name);
    entry->name = NULL;
    proto_value_free(&entry->value);
}

void proto_instance_release(ProtoInstance *instance) {
    if (!instance) {
        return;
    }
    if (instance->ref_count == 0) {
        return;
    }
    instance->ref_count--;
    if (instance->ref_count > 0) {
        return;
    }
    for (size_t i = 0; i < instance->field_count; ++i) {
        proto_field_entry_free(&instance->fields[i]);
    }
    free(instance->fields);
    instance->fields = NULL;
    instance->field_count = 0;
    instance->field_capacity = 0;
    proto_class_release(instance->klass);
    instance->klass = NULL;
    free(instance);
}

ProtoClass *proto_instance_class(const ProtoInstance *instance) {
    return instance ? instance->klass : NULL;
}

static ProtoFieldEntry *proto_instance_find_field(ProtoInstance *instance, const char *name) {
    if (!instance || !name) {
        return NULL;
    }
    for (size_t i = 0; i < instance->field_count; ++i) {
        ProtoFieldEntry *entry = &instance->fields[i];
        if (entry->name && strcmp(entry->name, name) == 0) {
            return entry;
        }
    }
    return NULL;
}

bool proto_instance_get_field(const ProtoInstance *instance, const char *name, ProtoValue *out_value) {
    if (!instance || !name || !out_value) {
        return false;
    }
    ProtoFieldEntry *entry = proto_instance_find_field((ProtoInstance *)instance, name);
    if (!entry) {
        return false;
    }
    *out_value = proto_value_copy(&entry->value);
    return true;
}

bool proto_instance_set_field(ProtoInstance *instance, const char *name, const ProtoValue *value) {
    if (!instance || !name || !value) {
        return false;
    }
    ProtoFieldEntry *entry = proto_instance_find_field(instance, name);
    if (entry) {
        proto_value_free(&entry->value);
        entry->value = proto_value_copy(value);
        return true;
    }

    ENSURE_CAPACITY(instance->fields, instance->field_count, instance->field_capacity, ProtoFieldEntry);
    entry = &instance->fields[instance->field_count++];
    entry->name = protohack_copy_string(name, strlen(name));
    entry->value = proto_value_copy(value);
    return true;
}

ProtoBoundMethod *proto_bound_method_new(ProtoInstance *instance, ProtoFunction *method) {
    if (!instance || !method) {
        return NULL;
    }
    ProtoBoundMethod *bound = (ProtoBoundMethod *)calloc(1, sizeof(ProtoBoundMethod));
    if (!bound) {
        PROTOHACK_FATAL("Failed to allocate ProtoBoundMethod");
    }
    bound->instance = instance;
    proto_instance_retain(instance);
    bound->method = method;
    bound->ref_count = 1;
    return bound;
}

void proto_bound_method_retain(ProtoBoundMethod *bound) {
    if (bound) {
        bound->ref_count++;
    }
}

void proto_bound_method_release(ProtoBoundMethod *bound) {
    if (!bound) {
        return;
    }
    if (bound->ref_count == 0) {
        return;
    }
    bound->ref_count--;
    if (bound->ref_count > 0) {
        return;
    }
    proto_instance_release(bound->instance);
    bound->instance = NULL;
    bound->method = NULL;
    free(bound);
}

ProtoInstance *proto_bound_method_receiver(const ProtoBoundMethod *bound) {
    return bound ? bound->instance : NULL;
}

ProtoFunction *proto_bound_method_function(const ProtoBoundMethod *bound) {
    return bound ? bound->method : NULL;
}
