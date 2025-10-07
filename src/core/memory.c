#include "protohack/internal/common.h"

#include <string.h>

char *protohack_copy_string(const char *start, size_t length) {
    char *buffer = (char *)malloc(length + 1);
    if (!buffer) {
        PROTOHACK_FATAL("Memory allocation failed when copying string");
    }
    memcpy(buffer, start, length);
    buffer[length] = '\0';
    return buffer;
}
