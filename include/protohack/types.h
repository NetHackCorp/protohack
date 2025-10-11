#ifndef PROTOHACK_TYPES_H
#define PROTOHACK_TYPES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PROTO_TYPE_ANY = 0,
    PROTO_TYPE_NUM,
    PROTO_TYPE_FLAG,
    PROTO_TYPE_TEXT,
    PROTO_TYPE_RAW,
    PROTO_TYPE_PTR,
    PROTO_TYPE_NONE
} ProtoTypeTag;

static inline const char *proto_type_tag_name(ProtoTypeTag tag) {
    switch (tag) {
        case PROTO_TYPE_ANY: return "any";
        case PROTO_TYPE_NUM: return "num";
        case PROTO_TYPE_FLAG: return "flag";
        case PROTO_TYPE_TEXT: return "text";
        case PROTO_TYPE_RAW: return "raw";
        case PROTO_TYPE_PTR: return "pointer";
        case PROTO_TYPE_NONE: return "none";
        default: return "unknown";
    }
}

#ifdef __cplusplus
}
#endif

#endif
