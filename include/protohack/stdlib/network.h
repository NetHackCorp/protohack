#ifndef PROTOHACK_STDLIB_NETWORK_H
#define PROTOHACK_STDLIB_NETWORK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "protohack/error.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ProtoStdNetInterface {
    char *name;
    char *address;
} ProtoStdNetInterface;

typedef struct ProtoStdNetInterfaces {
    ProtoStdNetInterface *items;
    size_t count;
    size_t capacity;
} ProtoStdNetInterfaces;

bool proto_stdlib_net_ping(const char *host, uint32_t timeout_ms, ProtoError *error);
char *proto_stdlib_net_hostname(void);
char *proto_stdlib_net_resolve(const char *host, ProtoError *error);
ProtoStdNetInterfaces proto_stdlib_net_interfaces(ProtoError *error);
void proto_stdlib_net_interfaces_free(ProtoStdNetInterfaces *interfaces);

#ifdef __cplusplus
}
#endif

#endif
