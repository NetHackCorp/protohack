#include "protohack/error.h"

#include <stdarg.h>
#include <stdio.h>

void protoerror_reset(ProtoError *error) {
    if (!error) {
        return;
    }
    error->ok = true;
    error->line = 0;
    error->message[0] = '\0';
}

void protoerror_set(ProtoError *error, size_t line, const char *format, ...) {
    if (!error) {
        return;
    }
    error->ok = false;
    error->line = line;

    va_list args;
    va_start(args, format);
#if defined(_MSC_VER)
    vsnprintf_s(error->message, sizeof error->message, _TRUNCATE, format, args);
#else
    vsnprintf(error->message, sizeof error->message, format, args);
#endif
    va_end(args);
}
