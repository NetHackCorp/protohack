#include "protohack/protohack.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <unistd.h>
#else
#include <unistd.h>
#include <limits.h>
#endif

static bool get_self_path(char *buffer, size_t size, const char *argv0) {
#if defined(_WIN32)
    DWORD len = GetModuleFileNameA(NULL, buffer, (DWORD)size);
    if (len > 0 && len < size) {
        return true;
    }
#elif defined(__APPLE__)
    uint32_t len = (uint32_t)size;
    if (_NSGetExecutablePath(buffer, &len) == 0) {
        return true;
    }
#elif defined(__linux__)
    ssize_t len = readlink("/proc/self/exe", buffer, size - 1);
    if (len > 0 && (size_t)len < size) {
        buffer[len] = '\0';
        return true;
    }
#endif

    if (!argv0 || argv0[0] == '\0') {
        return false;
    }

#if defined(_WIN32)
    if (_fullpath(buffer, argv0, size) != NULL) {
        return true;
    }
#else
    if (realpath(argv0, buffer) != NULL) {
        return true;
    }
#endif

    strncpy(buffer, argv0, size - 1);
    buffer[size - 1] = '\0';
    return true;
}

int main(int argc, char **argv) {
    (void)argc;

    char exe_path[4096];
    if (!get_self_path(exe_path, sizeof exe_path, argv && argv[0] ? argv[0] : NULL)) {
        fprintf(stderr, "protohack-runner: unable to determine executable path\n");
        return EXIT_FAILURE;
    }

    ProtoError error;
    protoerror_reset(&error);

    ProtoSerializedBuffer buffer = {0};
    if (!protohack_extract_embedded_program(exe_path, &buffer, &error)) {
        fprintf(stderr, "protohack-runner: %s\n", error.ok ? "missing embedded program" : error.message);
        return EXIT_FAILURE;
    }

    ProtoChunk chunk;
    protochunk_init(&chunk);
    if (!protochunk_deserialize_from_memory(&chunk, buffer.data, buffer.size, &error)) {
        fprintf(stderr, "protohack-runner: failed to deserialize bytecode: %s\n", error.message);
        protochunk_buffer_free(&buffer);
        protochunk_free(&chunk);
        return EXIT_FAILURE;
    }

    ProtoVM vm;
    protovm_init(&vm);
    if (!protovm_run(&vm, &chunk, &error)) {
        fprintf(stderr, "protohack-runner: runtime error (line %zu): %s\n", error.line, error.message);
        protochunk_buffer_free(&buffer);
        protochunk_free(&chunk);
        return EXIT_FAILURE;
    }

    protochunk_buffer_free(&buffer);
    protochunk_free(&chunk);
    return EXIT_SUCCESS;
}
