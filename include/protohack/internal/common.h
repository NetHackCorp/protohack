#ifndef PROTOHACK_INTERNAL_COMMON_H
#define PROTOHACK_INTERNAL_COMMON_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#define PROTOHACK_FATAL(msg) \
    do { \
        fprintf(stderr, "[protohack] %s\n", (msg)); \
        exit(EXIT_FAILURE); \
    } while (0)

#define PROTOHACK_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            PROTOHACK_FATAL(msg); \
        } \
    } while (0)

#define GROW_CAPACITY(capacity) ((capacity) < 8 ? 8 : (capacity) * 2)

#define ENSURE_CAPACITY(array, count, capacity, type) \
    do { \
        if ((count) + 1 > (capacity)) { \
            size_t old_capacity = (capacity); \
            (capacity) = GROW_CAPACITY(old_capacity); \
            type *new_array = (type *)realloc((array), sizeof(type) * (capacity)); \
            if (!(new_array)) { \
                PROTOHACK_FATAL("Memory allocation failed"); \
            } \
            (array) = new_array; \
        } \
    } while (0)

char *protohack_copy_string(const char *start, size_t length);

#endif
