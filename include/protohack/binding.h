#ifndef PROTOHACK_BINDING_H
#define PROTOHACK_BINDING_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "protohack/config.h"
#include "protohack/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ProtoTypeBinding {
    ProtoTypeTag tag;
    int8_t param;
} ProtoTypeBinding;

typedef struct ProtoTypeBindingSet {
    ProtoTypeBinding entries[PROTOHACK_MAX_TYPE_PARAMS];
    uint8_t count;
} ProtoTypeBindingSet;

bool proto_binding_set_format(const ProtoTypeBindingSet *set, char *buffer, size_t buffer_size);

#define PROTO_BINDING_CONCRETE(TAG) ((ProtoTypeBinding){ (ProtoTypeTag)(TAG), -1 })
#define PROTO_BINDING_SYMBOLIC(INDEX) ((ProtoTypeBinding){ PROTO_TYPE_ANY, (int8_t)(INDEX) })

#define PROTO_BINDING_SET_EMPTY() ((ProtoTypeBindingSet){ .count = 0 })
#define PROTO_BINDING_SET1(B0) ((ProtoTypeBindingSet){ .entries = { (B0) }, .count = 1 })
#define PROTO_BINDING_SET2(B0, B1) ((ProtoTypeBindingSet){ .entries = { (B0), (B1) }, .count = 2 })
#define PROTO_BINDING_SET3(B0, B1, B2) ((ProtoTypeBindingSet){ .entries = { (B0), (B1), (B2) }, .count = 3 })
#define PROTO_BINDING_SET4(B0, B1, B2, B3) ((ProtoTypeBindingSet){ .entries = { (B0), (B1), (B2), (B3) }, .count = 4 })

#ifdef __cplusplus
}
#endif

#endif
