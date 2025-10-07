#ifndef PROTOHACK_OBJECT_H
#define PROTOHACK_OBJECT_H

#include <stdbool.h>
#include <stddef.h>

#include "protohack/types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ProtoFunction;
typedef struct ProtoFunction ProtoFunction;

struct ProtoValue;
typedef struct ProtoValue ProtoValue;

typedef struct ProtoClass ProtoClass;
typedef struct ProtoInstance ProtoInstance;
typedef struct ProtoBoundMethod ProtoBoundMethod;

typedef struct ProtoMethodEntry {
    char *name;
    ProtoFunction *function;
} ProtoMethodEntry;

ProtoClass *proto_class_new(const char *name);
void proto_class_retain(ProtoClass *klass);
void proto_class_release(ProtoClass *klass);
const char *proto_class_name(const ProtoClass *klass);
bool proto_class_add_method(ProtoClass *klass, const char *name, ProtoFunction *function);
ProtoFunction *proto_class_find_method(const ProtoClass *klass, const char *name);

ProtoInstance *proto_instance_new(ProtoClass *klass);
void proto_instance_retain(ProtoInstance *instance);
void proto_instance_release(ProtoInstance *instance);
ProtoClass *proto_instance_class(const ProtoInstance *instance);
bool proto_instance_get_field(const ProtoInstance *instance, const char *name, ProtoValue *out_value);
bool proto_instance_set_field(ProtoInstance *instance, const char *name, const ProtoValue *value);

ProtoBoundMethod *proto_bound_method_new(ProtoInstance *instance, ProtoFunction *method);
void proto_bound_method_retain(ProtoBoundMethod *bound);
void proto_bound_method_release(ProtoBoundMethod *bound);
ProtoInstance *proto_bound_method_receiver(const ProtoBoundMethod *bound);
ProtoFunction *proto_bound_method_function(const ProtoBoundMethod *bound);

#ifdef __cplusplus
}
#endif

#endif
