#include "protohack/error.h"

#include <stdarg.h>
#include <stdio.h>

void protoerror_reset(ProtoError *error) {
    if (!error) {
        return;
    }
    error->ok = true;
    error->line = 0;
    error->column = 0;
    error->message[0] = '\0';
}

static void protoerror_format_message(ProtoError *error, size_t line, size_t column, const char *format, va_list args) {
    if (!error) {
        return;
    }
    error->ok = false;
    error->line = line;
    error->column = column;

#if defined(_MSC_VER)
    vsnprintf_s(error->message, sizeof error->message, _TRUNCATE, format, args);
#else
    vsnprintf(error->message, sizeof error->message, format, args);
#endif
}

void protoerror_set_with_column(ProtoError *error, size_t line, size_t column, const char *format, ...) {
    if (!error) {
        return;
    }

    va_list args;
    va_start(args, format);
    protoerror_format_message(error, line, column, format, args);
    va_end(args);
}

void protoerror_set(ProtoError *error, size_t line, const char *format, ...) {
    if (!error) {
        return;
    }

    va_list args;
    va_start(args, format);
    protoerror_format_message(error, line, 0, format, args);
    va_end(args);
}
