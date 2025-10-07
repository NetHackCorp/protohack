#include "protohack/executable.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protohack/internal/common.h"

static bool copy_file(FILE *src, FILE *dst) {
    uint8_t buffer[4096];
    size_t read = 0;
    while ((read = fread(buffer, 1, sizeof buffer, src)) > 0) {
        if (fwrite(buffer, 1, read, dst) != read) {
            return false;
        }
    }
    return ferror(src) == 0;
}

bool protohack_pack_executable(const ProtoChunk *chunk, const char *runner_path, const char *output_path, ProtoError *error) {
    if (!chunk || !runner_path || !output_path || !error) {
        if (error) {
            protoerror_set(error, 0, "Invalid arguments to pack executable");
        }
        return false;
    }
    protoerror_reset(error);

    FILE *runner = fopen(runner_path, "rb");
    if (!runner) {
        protoerror_set(error, 0, "Unable to open runner executable '%s': %s", runner_path, strerror(errno));
        return false;
    }

    FILE *out = fopen(output_path, "wb");
    if (!out) {
        fclose(runner);
        protoerror_set(error, 0, "Unable to open output executable '%s': %s", output_path, strerror(errno));
        return false;
    }

    bool ok = copy_file(runner, out);
    fclose(runner);
    if (!ok) {
        fclose(out);
        protoerror_set(error, 0, "Failed to copy runner executable: %s", strerror(errno));
        remove(output_path);
        return false;
    }

    ProtoSerializedBuffer buffer = {0};
    if (!protochunk_serialize_to_buffer(chunk, &buffer, error)) {
        fclose(out);
        remove(output_path);
        return false;
    }

    if (buffer.size > 0xFFFFFFFFu) {
        protochunk_buffer_free(&buffer);
        fclose(out);
        remove(output_path);
        protoerror_set(error, 0, "Serialized bytecode is too large to embed (%zu bytes)", buffer.size);
        return false;
    }

    ok = fwrite(buffer.data, sizeof(uint8_t), buffer.size, out) == buffer.size;
    if (ok) {
        ProtoExecutableTrailer trailer;
        trailer.magic = PROTOHACK_EXE_MAGIC;
        trailer.payload_size = (uint32_t)buffer.size;
        ok = fwrite(&trailer, sizeof trailer, 1, out) == 1;
    }

    fclose(out);
    protochunk_buffer_free(&buffer);

    if (!ok) {
        protoerror_set(error, 0, "Failed to write embedded bytecode: %s", strerror(errno));
        remove(output_path);
        return false;
    }

    return true;
}

bool protohack_extract_embedded_program(const char *exe_path, ProtoSerializedBuffer *buffer, ProtoError *error) {
    if (!exe_path || !buffer || !error) {
        if (error) {
            protoerror_set(error, 0, "Invalid arguments to extract executable");
        }
        return false;
    }
    protoerror_reset(error);

    FILE *file = fopen(exe_path, "rb");
    if (!file) {
        protoerror_set(error, 0, "Unable to open executable '%s': %s", exe_path, strerror(errno));
        return false;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        protoerror_set(error, 0, "Failed to seek executable");
        return false;
    }
    long file_size = ftell(file);
    if (file_size < (long)sizeof(ProtoExecutableTrailer)) {
        fclose(file);
        protoerror_set(error, 0, "Executable is too small");
        return false;
    }
    if (fseek(file, -((long)sizeof(ProtoExecutableTrailer)), SEEK_END) != 0) {
        fclose(file);
        protoerror_set(error, 0, "Failed to locate trailer");
        return false;
    }

    ProtoExecutableTrailer trailer;
    if (fread(&trailer, sizeof trailer, 1, file) != 1) {
        fclose(file);
        protoerror_set(error, 0, "Failed to read trailer: %s", strerror(errno));
        return false;
    }
    if (trailer.magic != PROTOHACK_EXE_MAGIC) {
        fclose(file);
        protoerror_set(error, 0, "Executable does not contain protohack payload");
        return false;
    }

    if (trailer.payload_size == 0 || (long)trailer.payload_size > file_size - (long)sizeof(ProtoExecutableTrailer)) {
        fclose(file);
        protoerror_set(error, 0, "Invalid payload size");
        return false;
    }

    long payload_offset = file_size - (long)sizeof(ProtoExecutableTrailer) - (long)trailer.payload_size;
    if (fseek(file, payload_offset, SEEK_SET) != 0) {
        fclose(file);
        protoerror_set(error, 0, "Failed to locate payload");
        return false;
    }

    uint8_t *data = (uint8_t *)malloc(trailer.payload_size);
    if (!data) {
        fclose(file);
        protoerror_set(error, 0, "Failed to allocate payload buffer");
        return false;
    }

    if (fread(data, sizeof(uint8_t), trailer.payload_size, file) != trailer.payload_size) {
        free(data);
        fclose(file);
        protoerror_set(error, 0, "Failed to read payload: %s", strerror(errno));
        return false;
    }

    fclose(file);
    buffer->data = data;
    buffer->size = trailer.payload_size;
    return true;
}
