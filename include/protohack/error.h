#ifndef PROTOHACK_ERROR_H
#define PROTOHACK_ERROR_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool ok;
    char message[256];
    size_t line;
    size_t column;
} ProtoError;

void protoerror_reset(ProtoError *error);
void protoerror_set(ProtoError *error, size_t line, const char *format, ...);
void protoerror_set_with_column(ProtoError *error, size_t line, size_t column, const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif
