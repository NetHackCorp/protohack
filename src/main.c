#include "protohack/protohack.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <unistd.h>
#else
#include <unistd.h>
#endif

#define PROTOHACK_PHC_EXTENSION ".phc"

#if defined(_WIN32)
#define PROTOHACK_RUNNER_NAME "protohack-runner.exe"
#define PROTOHACK_EXE_EXTENSION ".exe"
#else
#define PROTOHACK_RUNNER_NAME "protohack-runner"
#define PROTOHACK_EXE_EXTENSION ".bin"
#endif

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [--run] [--exe] [-o output.phc] [--exe-out output%s] [--runner path] <source.phk>\n",
            prog, PROTOHACK_EXE_EXTENSION);
}

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

static char *read_file(const char *path, size_t *out_size) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (length < 0) {
        fclose(file);
        return NULL;
    }

    char *buffer = (char *)malloc((size_t)length + 1);
    if (!buffer) {
        fclose(file);
        return NULL;
    }

    size_t read = fread(buffer, sizeof(char), (size_t)length, file);
    fclose(file);

    if (read != (size_t)length) {
        free(buffer);
        return NULL;
    }

    buffer[length] = '\0';
    if (out_size) {
        *out_size = (size_t)length;
    }
    return buffer;
}

static char *derive_output_with_extension(const char *input, const char *extension) {
    const char *dot = strrchr(input, '.');
    size_t base_length = dot ? (size_t)(dot - input) : strlen(input);
    size_t extension_length = strlen(extension);
    size_t total = base_length + extension_length + 1;
    char *output = (char *)malloc(total);
    if (!output) {
        return NULL;
    }
    memcpy(output, input, base_length);
    memcpy(output + base_length, extension, extension_length);
    output[base_length + extension_length] = '\0';
    return output;
}

static char *derive_runner_path(const char *program_path) {
    if (!program_path) {
        program_path = "";
    }

    const char *slash = strrchr(program_path, '/');
#if defined(_WIN32)
    const char *backslash = strrchr(program_path, '\\');
    if (!slash || (backslash && backslash > slash)) {
        slash = backslash;
    }
#endif

    size_t dir_length = slash ? (size_t)(slash - program_path + 1) : 0;
    size_t runner_length = strlen(PROTOHACK_RUNNER_NAME);
    size_t total = dir_length + runner_length + 1;

    char *result = (char *)malloc(total);
    if (!result) {
        return NULL;
    }

    if (dir_length > 0) {
        memcpy(result, program_path, dir_length);
    }
    memcpy(result + dir_length, PROTOHACK_RUNNER_NAME, runner_length);
    result[dir_length + runner_length] = '\0';
    return result;
}

int main(int argc, char **argv) {
    const char *input_path = NULL;
    char *output_path = NULL;
    bool output_allocated = false;
    bool run_after_compile = false;
    bool emit_executable = false;
    const char *exe_output_path = NULL;
    bool exe_output_allocated = false;
    const char *runner_path = NULL;
    bool runner_allocated = false;

    char self_path[4096] = {0};
    bool have_self_path = get_self_path(self_path, sizeof self_path, (argc > 0) ? argv[0] : NULL);

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--run") == 0) {
            run_after_compile = true;
        } else if (strcmp(argv[i], "--exe") == 0) {
            emit_executable = true;
        } else if (strcmp(argv[i], "--exe-out") == 0) {
            if (i + 1 >= argc) {
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            exe_output_path = argv[++i];
            exe_output_allocated = false;
            emit_executable = true;
        } else if (strcmp(argv[i], "--runner") == 0) {
            if (i + 1 >= argc) {
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            runner_path = argv[++i];
            runner_allocated = false;
        } else if (strcmp(argv[i], "-o") == 0) {
            if (i + 1 >= argc) {
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            output_path = argv[++i];
            output_allocated = false;
        } else if (!input_path) {
            input_path = argv[i];
        } else {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (!input_path) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    int exit_code = EXIT_FAILURE;
    char *source = NULL;
    size_t source_size = 0;
    ProtoChunk chunk;
    bool chunk_initialized = false;
    ProtoError error;

    if (!output_path) {
        output_path = derive_output_with_extension(input_path, PROTOHACK_PHC_EXTENSION);
        if (!output_path) {
            fprintf(stderr, "Failed to allocate output path.\n");
            goto cleanup;
        }
        output_allocated = true;
    }

    if (emit_executable && !exe_output_path) {
        exe_output_path = derive_output_with_extension(input_path, PROTOHACK_EXE_EXTENSION);
        if (!exe_output_path) {
            fprintf(stderr, "Failed to allocate executable output path.\n");
            goto cleanup;
        }
        exe_output_allocated = true;
    }

    if (emit_executable && !runner_path) {
        const char *base = have_self_path ? self_path : (argc > 0 ? argv[0] : NULL);
        char *derived = derive_runner_path(base);
        if (!derived) {
            fprintf(stderr, "Failed to allocate runner path.\n");
            goto cleanup;
        }
        runner_path = derived;
        runner_allocated = true;
    }

    source = read_file(input_path, &source_size);
    if (!source) {
        fprintf(stderr, "Unable to read source file '%s'.\n", input_path);
        goto cleanup;
    }

    protochunk_init(&chunk);
    chunk_initialized = true;
    protoerror_reset(&error);

    if (!protohack_compile_source(source, &chunk, &error)) {
        fprintf(stderr, "Compilation failed (line %zu): %s\n", error.line, error.message);
        goto cleanup;
    }

    if (!protochunk_serialize(&chunk, output_path, &error)) {
        fprintf(stderr, "Failed to write bytecode: %s\n", error.message);
        goto cleanup;
    }

    if (emit_executable) {
        protoerror_reset(&error);
        if (!protohack_pack_executable(&chunk, runner_path, exe_output_path, &error)) {
            fprintf(stderr, "Failed to build executable '%s': %s\n", exe_output_path, error.message);
            goto cleanup;
        }
    }

    if (run_after_compile) {
        ProtoVM vm;
        protovm_init(&vm);
        if (!protovm_run(&vm, &chunk, &error)) {
            fprintf(stderr, "Runtime error (line %zu): %s\n", error.line, error.message);
            goto cleanup;
        }
    }

    exit_code = EXIT_SUCCESS;

cleanup:
    if (chunk_initialized) {
        protochunk_free(&chunk);
    }
    if (source) {
        free(source);
    }
    if (output_allocated && output_path) {
        free(output_path);
    }
    if (exe_output_allocated && exe_output_path) {
        free((void *)exe_output_path);
    }
    if (runner_allocated && runner_path) {
        free((void *)runner_path);
    }
    return exit_code;
}
