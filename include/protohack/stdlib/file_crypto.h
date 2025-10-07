#ifndef PROTOHACK_STDLIB_FILE_CRYPTO_H
#define PROTOHACK_STDLIB_FILE_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>

#include "protohack/error.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Encrypts the contents of `input_path` using a repeating-XOR stream built from the
 * provided key. The encrypted output is stored at `output_path`.
 *
 * When `key_hex` is NULL the function generates a random 256-bit key and writes
 * it as a lowercase hexadecimal string to `*out_key_hex`. Callers must free the
 * returned string with `free()`.
 *
 * When a non-NULL `key_hex` is supplied, it must contain an even number of hex
 * digits. The value is validated and used directly; the same pointer is
 * returned via `*out_key_hex`.
 */
bool proto_stdlib_encrypt_file(
    const char *input_path,
    const char *output_path,
    const char *key_hex,
    char **out_key_hex,
    ProtoError *error);

/**
 * Decrypts the contents of `input_path` that were previously encrypted with
 * proto_stdlib_encrypt_file using the same `key_hex`. The resulting plaintext is
 * written to `output_path`.
 */
bool proto_stdlib_decrypt_file(
    const char *input_path,
    const char *output_path,
    const char *key_hex,
    ProtoError *error);

#ifdef __cplusplus
}
#endif

#endif
