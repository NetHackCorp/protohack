#ifndef PROTOHACK_EXTENSION_H
#define PROTOHACK_EXTENSION_H

#include <stddef.h>
#include <stdint.h>

#include "protohack/binding.h"
#include "protohack/config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum ProtoExtensionTargetKind {
    PROTO_EXTENSION_TARGET_CRAFT = 0,
    PROTO_EXTENSION_TARGET_CLASS = 1,
} ProtoExtensionTargetKind;

typedef struct ProtoExtensionTypeSpec {
    char name[PROTOHACK_MAX_IDENTIFIER + 1];
    ProtoTypeBindingSet bindings;
    uint8_t label_count;
    char labels[PROTOHACK_MAX_TYPE_PARAMS][PROTOHACK_MAX_IDENTIFIER + 1];
} ProtoExtensionTypeSpec;

typedef struct ProtoExtensionDecl {
    ProtoExtensionTargetKind target_kind;
    ProtoExtensionTypeSpec target;
    ProtoExtensionTypeSpec traits[PROTOHACK_MAX_EXTENSION_TRAITS];
    uint8_t trait_count;
    char *body_source;
    size_t body_length;
    size_t line;
} ProtoExtensionDecl;

#ifdef __cplusplus
}
#endif

#endif
