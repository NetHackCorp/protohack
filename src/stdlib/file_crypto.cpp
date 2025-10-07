#include "protohack/stdlib/file_crypto.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <limits>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "protohack/error.h"

namespace {

struct FileBuffer {
    std::vector<std::uint8_t> bytes;
    bool ok;
};

static void set_error(ProtoError *error, const char *format, const std::string &detail) {
    if (!error || !error->ok) {
        return;
    }
    protoerror_set(error, 0, format, detail.c_str());
}

static FileBuffer read_file(const char *path, ProtoError *error) {
    if (!path) {
        set_error(error, "%s", "Missing input path");
        return {{}, false};
    }

    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) {
        set_error(error, "Failed to open file: %s", path);
        return {{}, false};
    }

    const std::streamsize size = stream.tellg();
    if (size < 0) {
        set_error(error, "Unable to determine size for file: %s", path);
        return {{}, false};
    }
    stream.seekg(0, std::ios::beg);

    FileBuffer buffer;
    buffer.bytes.resize(static_cast<std::size_t>(size));
    if (!stream.read(reinterpret_cast<char *>(buffer.bytes.data()), size)) {
        set_error(error, "Failed to read file: %s", path);
        buffer.bytes.clear();
        buffer.ok = false;
        return buffer;
    }

    buffer.ok = true;
    return buffer;
}

static bool write_file(const char *path, const std::vector<std::uint8_t> &bytes, ProtoError *error) {
    if (!path) {
        set_error(error, "%s", "Missing output path");
        return false;
    }

    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) {
        set_error(error, "Failed to open file for writing: %s", path);
        return false;
    }

    if (!bytes.empty()) {
        stream.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!stream) {
            set_error(error, "Failed to write file: %s", path);
            return false;
        }
    }

    return true;
}

static std::vector<std::uint8_t> hex_to_bytes(std::string_view hex, ProtoError *error) {
    std::vector<std::uint8_t> out;
    if (hex.empty()) {
        set_error(error, "%s", "Key must not be empty");
        return out;
    }
    if ((hex.size() & 1u) != 0u) {
        set_error(error, "%s", "Key must contain an even number of hex digits");
        return out;
    }

    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        auto decode = [](char c) -> int {
            if (c >= '0' && c <= '9') {
                return c - '0';
            }
            if (c >= 'a' && c <= 'f') {
                return c - 'a' + 10;
            }
            if (c >= 'A' && c <= 'F') {
                return c - 'A' + 10;
            }
            return -1;
        };

        const int hi = decode(hex[i]);
        const int lo = decode(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            set_error(error, "%s", "Key contains non-hex characters");
            out.clear();
            return out;
        }
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

static std::string bytes_to_hex(const std::vector<std::uint8_t> &bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (const auto byte : bytes) {
        oss << std::setw(2) << static_cast<unsigned>(byte);
    }
    return oss.str();
}

static std::vector<std::uint8_t> generate_key(std::size_t length) {
    std::vector<std::uint8_t> key(length);
    std::random_device rd;
    std::seed_seq seed{rd(), rd(), rd(), rd()};
    std::mt19937_64 rng(seed);
    std::uniform_int_distribution<int> dist(0, 255);
    std::generate(key.begin(), key.end(), [&]() { return static_cast<std::uint8_t>(dist(rng)); });
    return key;
}

static void xor_cipher(std::vector<std::uint8_t> &data, const std::vector<std::uint8_t> &key) {
    if (data.empty() || key.empty()) {
        return;
    }
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] ^= key[i % key.size()];
    }
}

} // namespace

extern "C" bool proto_stdlib_encrypt_file(
    const char *input_path,
    const char *output_path,
    const char *key_hex,
    char **out_key_hex,
    ProtoError *error) {
    if (error) {
        protoerror_reset(error);
    }

    if (!out_key_hex || !input_path || !output_path) {
        set_error(error, "%s", "Invalid arguments");
        return false;
    }

    const FileBuffer plaintext = read_file(input_path, error);
    if (!plaintext.ok) {
        return false;
    }

    std::vector<std::uint8_t> key_bytes;
    std::string owned_key_hex;

    if (key_hex && key_hex[0] != '\0') {
        key_bytes = hex_to_bytes(key_hex, error);
        if (key_bytes.empty()) {
            return false;
        }
        owned_key_hex.assign(key_hex);
    } else {
        constexpr std::size_t kDefaultKeyLength = 32u;
        key_bytes = generate_key(kDefaultKeyLength);
        owned_key_hex = bytes_to_hex(key_bytes);
    }

    std::vector<std::uint8_t> ciphertext = plaintext.bytes;
    xor_cipher(ciphertext, key_bytes);

    if (!write_file(output_path, ciphertext, error)) {
        return false;
    }

    char *buffer = static_cast<char *>(std::malloc(owned_key_hex.size() + 1));
    if (!buffer) {
        set_error(error, "%s", "Out of memory while returning key");
        return false;
    }
    std::memcpy(buffer, owned_key_hex.c_str(), owned_key_hex.size() + 1);
    *out_key_hex = buffer;
    return true;
}

extern "C" bool proto_stdlib_decrypt_file(
    const char *input_path,
    const char *output_path,
    const char *key_hex,
    ProtoError *error) {
    if (error) {
        protoerror_reset(error);
    }

    if (!key_hex) {
        set_error(error, "%s", "Key is required for decryption");
        return false;
    }

    const FileBuffer ciphertext = read_file(input_path, error);
    if (!ciphertext.ok) {
        return false;
    }

    const std::vector<std::uint8_t> key_bytes = hex_to_bytes(key_hex, error);
    if (key_bytes.empty()) {
        return false;
    }

    std::vector<std::uint8_t> plaintext = ciphertext.bytes;
    xor_cipher(plaintext, key_bytes);

    return write_file(output_path, plaintext, error);
}
