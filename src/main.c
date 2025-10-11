#include "protohack/protohack.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>

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

static void usage(FILE *stream, const char *prog) {
    if (!stream) {
        stream = stderr;
    }
    fprintf(stream, "Protohack compiler %s\n", PROTOHACK_VERSION);
    fprintf(stream, "Usage: %s [options] <source.phk>\n\n", prog ? prog : "protohackc");
    fprintf(stream, "Options:\n");
    fprintf(stream, "  -o <file>             Write compiled bytecode to <file> (defaults to source with %s).\n", PROTOHACK_PHC_EXTENSION);
    fprintf(stream, "  --run                 Execute the program immediately after compilation.\n");
    fprintf(stream, "  --exe                 Bundle the program with the runner stub into a standalone executable.\n");
    fprintf(stream, "  --exe-out <file>      Custom output path for the bundled executable.\n");
    fprintf(stream, "  --runner <file>       Override the runner stub used when --exe is set.\n");
#if PROTOHACK_ENABLE_JIT
    fprintf(stream, "  --jit-profile         Execute with the JIT profiler enabled and print statistics.\n");
#endif
    fprintf(stream, "  --version             Print the compiler version and exit.\n");
    fprintf(stream, "  --help                Show this message and exit.\n");
}

static void print_version(void) {
    printf("protohackc %s\n", PROTOHACK_VERSION);
}

static void find_line_bounds(const char *source, size_t target_line, const char **out_start, const char **out_end) {
    if (!out_start || !out_end) {
        return;
    }
    *out_start = NULL;
    *out_end = NULL;
    if (!source || target_line == 0) {
        return;
    }

    const char *line_start = source;
    size_t current_line = 1;
    for (const char *cursor = source; *cursor != '\0'; ++cursor) {
        if (current_line == target_line) {
            break;
        }
        if (*cursor == '\n') {
            current_line++;
            line_start = cursor + 1;
        }
    }

    if (current_line != target_line) {
        return;
    }

    const char *line_end = line_start;
    while (*line_end != '\0' && *line_end != '\n') {
        ++line_end;
    }

    *out_start = line_start;
    *out_end = line_end;
}

static void print_source_fragment(const char *line_start, const char *line_end) {
    if (!line_start || !line_end) {
        return;
    }
    const size_t kTabWidth = 4;
    for (const char *cursor = line_start; cursor < line_end; ++cursor) {
        unsigned char ch = (unsigned char)*cursor;
        if (ch == '\t') {
            for (size_t i = 0; i < kTabWidth; ++i) {
                fputc(' ', stderr);
            }
        } else if (ch < 32 && ch != '\t') {
            fputc(' ', stderr);
        } else {
            fputc(ch, stderr);
        }
    }
}

static size_t caret_visual_offset(const char *line_start, const char *line_end, size_t caret_index) {
    const size_t kTabWidth = 4;
    size_t offset = 0;
    size_t max_index = (size_t)(line_end > line_start ? (line_end - line_start) : 0);
    if (caret_index > max_index) {
        caret_index = max_index;
    }
    for (size_t i = 0; i < caret_index && line_start + i < line_end; ++i) {
        unsigned char ch = (unsigned char)line_start[i];
        if (ch == '\t') {
            offset += kTabWidth;
        } else if (ch < 32 && ch != '\t') {
            offset += 1;
        } else {
            offset += 1;
        }
    }
    return offset;
}

static bool equals_ignore_case(const char *lhs, const char *rhs) {
    if (!lhs || !rhs) {
        return false;
    }
    while (*lhs && *rhs) {
        unsigned char a = (unsigned char)*lhs++;
        unsigned char b = (unsigned char)*rhs++;
        if (toupper(a) != toupper(b)) {
            return false;
        }
    }
    return *lhs == '\0' && *rhs == '\0';
}

static void json_escape_into(const char *input, char *output, size_t output_size) {
    if (!output || output_size == 0) {
        return;
    }
    if (!input) {
        output[0] = '\0';
        return;
    }

    size_t written = 0;
    for (const unsigned char *cursor = (const unsigned char *)input; *cursor != '\0'; ++cursor) {
        const char *escape = NULL;
        char buffer[7] = {0};
        switch (*cursor) {
            case '\\': escape = "\\\\"; break;
            case '"': escape = "\\\""; break;
            case '\b': escape = "\\b"; break;
            case '\f': escape = "\\f"; break;
            case '\n': escape = "\\n"; break;
            case '\r': escape = "\\r"; break;
            case '\t': escape = "\\t"; break;
            default:
                if (*cursor < 0x20) {
                    snprintf(buffer, sizeof buffer, "\\u%04x", (unsigned int)*cursor);
                    escape = buffer;
                }
                break;
        }
        const char *chunk = escape ? escape : (const char *)cursor;
        size_t chunk_len = escape ? strlen(escape) : 1;
        if (written + chunk_len >= output_size) {
            break;
        }
        memcpy(output + written, chunk, chunk_len);
        written += chunk_len;
    }

    if (written < output_size) {
        output[written] = '\0';
    } else {
        output[output_size - 1] = '\0';
    }
}

static void print_error_with_context(const char *phase, const char *path, const ProtoError *error, const char *source) {
    if (!error) {
        return;
    }

    const char *diagnostic_mode = getenv("PROTOHACK_DIAG_FORMAT");
    if (diagnostic_mode && equals_ignore_case(diagnostic_mode, "json")) {
        char escaped_phase[128];
        char escaped_path[512];
        char error_json[1024];
        json_escape_into(phase ? phase : "", escaped_phase, sizeof escaped_phase);
        json_escape_into(path ? path : "", escaped_path, sizeof escaped_path);
        protoerror_to_json(error, error_json, sizeof error_json);
        fprintf(stderr, "{\"phase\":\"%s\",\"path\":\"%s\",\"error\":%s}\n", escaped_phase, escaped_path, error_json);
        return;
    }

    const char *label = phase ? phase : "Error";
    if (path && error->line > 0) {
        if (error->column > 0) {
            fprintf(stderr, "%s:%zu:%zu: %s: %s\n", path, error->line, error->column, label, error->message);
        } else {
            fprintf(stderr, "%s:%zu: %s: %s\n", path, error->line, label, error->message);
        }
    } else if (error->line > 0) {
        if (error->column > 0) {
            fprintf(stderr, "line %zu, column %zu: %s: %s\n", error->line, error->column, label, error->message);
        } else {
            fprintf(stderr, "line %zu: %s: %s\n", error->line, label, error->message);
        }
    } else {
        fprintf(stderr, "%s: %s\n", label, error->message);
    }

    if (!source || error->line == 0) {
        const char *hint = protoerror_get_hint(error);
        if (hint && hint[0] != '\0') {
            fprintf(stderr, "        hint: %s\n", hint);
        }
        ProtoDiagnosticCode code = protoerror_get_code(error);
        if (code != PROTO_DIAG_NONE) {
            fprintf(stderr, "        code: %s (%d)\n", protoerror_code_string(code), (int)code);
        }
        return;
    }

    const char *line_start = NULL;
    const char *line_end = NULL;
    find_line_bounds(source, error->line, &line_start, &line_end);
    if (!line_start || !line_end) {
        return;
    }

    if (line_end > line_start && line_end[-1] == '\r') {
        line_end--;
    }

    fprintf(stderr, " %6zu | ", error->line);
    print_source_fragment(line_start, line_end);
    fprintf(stderr, "\n");

    if (error->column > 0) {
        size_t caret_index = error->column > 0 ? error->column - 1 : 0;
        size_t visual = caret_visual_offset(line_start, line_end, caret_index);
        fprintf(stderr, " %6s | ", "");
        for (size_t i = 0; i < visual; ++i) {
            fputc(' ', stderr);
        }
        fputc('^', stderr);
        fprintf(stderr, "\n");
    }

    const char *hint = protoerror_get_hint(error);
    if (hint && hint[0] != '\0') {
        fprintf(stderr, "        hint: %s\n", hint);
    }

    ProtoDiagnosticCode code = protoerror_get_code(error);
    if (code != PROTO_DIAG_NONE) {
        fprintf(stderr, "        code: %s (%d)\n", protoerror_code_string(code), (int)code);
    }
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
    bool show_help = false;
    bool show_version = false;
#if PROTOHACK_ENABLE_JIT
    bool dump_jit_profile = false;
#else
    const bool dump_jit_profile = false;
#endif

    char self_path[4096] = {0};
    bool have_self_path = get_self_path(self_path, sizeof self_path, (argc > 0) ? argv[0] : NULL);

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--run") == 0) {
            run_after_compile = true;
        } else if (strcmp(argv[i], "--exe") == 0) {
            emit_executable = true;
        } else if (strcmp(argv[i], "--exe-out") == 0) {
            if (i + 1 >= argc) {
                usage(stderr, argv[0]);
                return EXIT_FAILURE;
            }
            exe_output_path = argv[++i];
            exe_output_allocated = false;
            emit_executable = true;
        } else if (strcmp(argv[i], "--runner") == 0) {
            if (i + 1 >= argc) {
                usage(stderr, argv[0]);
                return EXIT_FAILURE;
            }
            runner_path = argv[++i];
            runner_allocated = false;
        } else if (strcmp(argv[i], "-o") == 0) {
            if (i + 1 >= argc) {
                usage(stderr, argv[0]);
                return EXIT_FAILURE;
            }
            output_path = argv[++i];
            output_allocated = false;
#if PROTOHACK_ENABLE_JIT
        } else if (strcmp(argv[i], "--jit-profile") == 0) {
            dump_jit_profile = true;
#endif
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            show_help = true;
        } else if (strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-V") == 0) {
            show_version = true;
        } else if (!input_path) {
            input_path = argv[i];
        } else {
            usage(stderr, argv[0]);
            return EXIT_FAILURE;
        }
    }

#if !PROTOHACK_ENABLE_JIT
    if (dump_jit_profile) {
        fprintf(stderr, "%s: --jit-profile requires building protohackc with JIT support.\n", argv[0] ? argv[0] : "protohackc");
        return EXIT_FAILURE;
    }
#endif

    if (show_version) {
        print_version();
        return EXIT_SUCCESS;
    }

    if (show_help) {
        usage(stdout, argv[0]);
        return EXIT_SUCCESS;
    }

    if (!input_path) {
        usage(stderr, argv[0]);
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

#if PROTOHACK_ENABLE_JIT
    if (dump_jit_profile) {
        run_after_compile = true;
    }
#endif

    source = read_file(input_path, &source_size);
    if (!source) {
        fprintf(stderr, "Unable to read source file '%s'.\n", input_path);
        goto cleanup;
    }

    protochunk_init(&chunk);
    chunk_initialized = true;
    protoerror_reset(&error);

    if (!protohack_compile_source(source, input_path, &chunk, &error)) {
        print_error_with_context("compilation error", input_path, &error, source);
        goto cleanup;
    }

    if (!protochunk_serialize(&chunk, output_path, &error)) {
        fprintf(stderr, "Failed to write bytecode: %s\n", error.message);
        goto cleanup;
    }
    printf("Wrote bytecode to %s\n", output_path);

    if (emit_executable) {
        protoerror_reset(&error);
        if (!protohack_pack_executable(&chunk, runner_path, exe_output_path, &error)) {
            fprintf(stderr, "Failed to build executable '%s': %s\n", exe_output_path, error.message);
            goto cleanup;
        }
        printf("Wrote executable to %s\n", exe_output_path);
    }

    if (run_after_compile) {
        ProtoVM vm;
        protovm_init(&vm);
        if (!protovm_run(&vm, &chunk, &error)) {
            print_error_with_context("runtime error", input_path, &error, source);
            goto cleanup;
        }
#if PROTOHACK_ENABLE_JIT
        if (dump_jit_profile) {
            const ProtoJITProfiler *profiler = protovm_profiler(&vm);
            if (profiler) {
                protojit_profiler_dump(profiler, stdout);
            } else {
                fprintf(stderr, "JIT profiler data unavailable.\n");
            }
        }
#endif
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
