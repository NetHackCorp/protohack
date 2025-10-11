#include "protohack/stdlib/network.h"

#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "protohack/internal/common.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {

#ifdef _WIN32
using SocketHandle = SOCKET;
constexpr SocketHandle kInvalidSocket = INVALID_SOCKET;
#else
using SocketHandle = int;
constexpr SocketHandle kInvalidSocket = -1;
#endif

struct SocketCloser {
    void operator()(SocketHandle sock) const {
#ifdef _WIN32
        if (sock != kInvalidSocket) {
            closesocket(sock);
        }
#else
        if (sock != kInvalidSocket) {
            close(sock);
        }
#endif
    }
};

class SocketGuard {
public:
    explicit SocketGuard(SocketHandle handle = kInvalidSocket) : handle_(handle) {}
    ~SocketGuard() { reset(); }

    SocketGuard(const SocketGuard &) = delete;
    SocketGuard &operator=(const SocketGuard &) = delete;

    SocketGuard(SocketGuard &&other) noexcept : handle_(other.handle_) {
        other.handle_ = kInvalidSocket;
    }

    SocketGuard &operator=(SocketGuard &&other) noexcept {
        if (this != &other) {
            reset();
            handle_ = other.handle_;
            other.handle_ = kInvalidSocket;
        }
        return *this;
    }

    SocketHandle get() const { return handle_; }
    bool valid() const { return handle_ != kInvalidSocket; }

    void reset(SocketHandle new_handle = kInvalidSocket) {
        if (handle_ != kInvalidSocket) {
            SocketCloser{}(handle_);
        }
        handle_ = new_handle;
    }

private:
    SocketHandle handle_;
};

#ifdef _WIN32
bool ensure_wsa(ProtoError *error) {
    static bool initialized = false;
    static int status = 0;
    if (!initialized) {
        WSADATA data;
        status = WSAStartup(MAKEWORD(2, 2), &data);
        initialized = true;
    }
    if (status != 0) {
        if (error && error->ok) {
            protoerror_set(error, 0, "WSAStartup failed (%d)", status);
        }
        return false;
    }
    return true;
}
#else
bool ensure_wsa(ProtoError *error) {
    (void)error;
    return true;
}
#endif

bool set_non_blocking(SocketHandle socket, bool non_blocking) {
#ifdef _WIN32
    u_long mode = non_blocking ? 1u : 0u;
    return ioctlsocket(socket, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(socket, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    if (non_blocking) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }
    return fcntl(socket, F_SETFL, flags) == 0;
#endif
}

bool wait_for_connect(SocketHandle socket, uint32_t timeout_ms, int &out_error) {
    fd_set write_set;
    FD_ZERO(&write_set);
    FD_SET(socket, &write_set);

    struct timeval tv;
    struct timeval *tv_ptr = nullptr;
    if (timeout_ms > 0) {
        tv.tv_sec = static_cast<long>(timeout_ms / 1000u);
        tv.tv_usec = static_cast<long>((timeout_ms % 1000u) * 1000u);
        tv_ptr = &tv;
    }

    int ready = select(static_cast<int>(socket + 1), nullptr, &write_set, nullptr, tv_ptr);
    if (ready <= 0) {
#ifdef _WIN32
        out_error = (ready == 0) ? WSAETIMEDOUT : WSAGetLastError();
#else
        out_error = (ready == 0) ? ETIMEDOUT : errno;
#endif
        return false;
    }

    if (!FD_ISSET(socket, &write_set)) {
#ifdef _WIN32
        out_error = WSAEWOULDBLOCK;
#else
        out_error = EWOULDBLOCK;
#endif
        return false;
    }

    int so_error = 0;
    socklen_t len = static_cast<socklen_t>(sizeof(so_error));
    if (getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&so_error), &len) != 0) {
#ifdef _WIN32
        so_error = WSAGetLastError();
#else
        so_error = errno;
#endif
    }

    out_error = so_error;
    return so_error == 0;
}

bool error_is_connection_refused(int error_code) {
#ifdef _WIN32
    return error_code == WSAECONNREFUSED;
#else
    return error_code == ECONNREFUSED;
#endif
}

bool error_is_would_block(int error_code) {
#ifdef _WIN32
    return error_code == WSAEWOULDBLOCK || error_code == WSAEINPROGRESS || error_code == WSAEINVAL;
#else
    return error_code == EINPROGRESS || error_code == EALREADY;
#endif
}

std::string addrinfo_to_string(const struct addrinfo *info) {
    if (!info) {
        return {};
    }

    std::array<char, INET6_ADDRSTRLEN> buffer{};
    const void *address_ptr = nullptr;

    if (info->ai_family == AF_INET) {
        address_ptr = &reinterpret_cast<const struct sockaddr_in *>(info->ai_addr)->sin_addr;
    } else if (info->ai_family == AF_INET6) {
        address_ptr = &reinterpret_cast<const struct sockaddr_in6 *>(info->ai_addr)->sin6_addr;
    }

    if (!address_ptr) {
        return {};
    }

#ifdef _WIN32
    void *mutable_ptr = const_cast<void *>(address_ptr);
    const char *converted = inet_ntop(info->ai_family, mutable_ptr, buffer.data(), static_cast<socklen_t>(buffer.size()));
#else
    const char *converted = inet_ntop(info->ai_family, address_ptr, buffer.data(), static_cast<socklen_t>(buffer.size()));
#endif
    if (!converted) {
        return {};
    }
    return std::string(converted);
}

} // namespace

extern "C" {

bool proto_stdlib_net_ping(const char *host, uint32_t timeout_ms, ProtoError *error) {
    if (!host || host[0] == '\0') {
        if (error && error->ok) {
            protoerror_set(error, 0, "net_ping expects a hostname");
        }
        return false;
    }

    if (!ensure_wsa(error)) {
        return false;
    }

    struct addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *resolved = nullptr;
    int status = getaddrinfo(host, "80", &hints, &resolved);
    if (status != 0 || !resolved) {
        if (error && error->ok) {
#ifdef _WIN32
            protoerror_set(error, 0, "net_ping failed to resolve '%s' (%d)", host, status);
#else
            protoerror_set(error, 0, "net_ping failed to resolve '%s' (%s)", host, gai_strerror(status));
#endif
        }
        return false;
    }

    std::unique_ptr<struct addrinfo, decltype(&freeaddrinfo)> resolver_guard(resolved, freeaddrinfo);

    if (timeout_ms == 0) {
        timeout_ms = 1000u;
    }

    bool attempted = false;
    bool recorded_error = false;
    bool timed_out = false;
    int last_error_code = 0;

    for (struct addrinfo *entry = resolved; entry != nullptr; entry = entry->ai_next) {
        attempted = true;

        SocketHandle raw_socket = socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
        if (raw_socket == kInvalidSocket) {
#ifdef _WIN32
            last_error_code = WSAGetLastError();
#else
            last_error_code = errno;
#endif
            recorded_error = true;
            continue;
        }

        SocketGuard socket_guard(raw_socket);

        if (!set_non_blocking(raw_socket, true)) {
#ifdef _WIN32
            last_error_code = WSAGetLastError();
#else
            last_error_code = errno;
#endif
            recorded_error = true;
            continue;
        }

        int connect_result = connect(raw_socket, entry->ai_addr, static_cast<int>(entry->ai_addrlen));
        if (connect_result == 0) {
            return true;
        }

#ifdef _WIN32
        int last_error = WSAGetLastError();
#else
        int last_error = errno;
#endif

        if (!error_is_would_block(last_error)) {
            if (error_is_connection_refused(last_error)) {
                return true;
            }
            recorded_error = true;
            last_error_code = last_error;
            continue;
        }

        int wait_error = 0;
        if (wait_for_connect(raw_socket, timeout_ms, wait_error)) {
            return true;
        }
        if (error_is_connection_refused(wait_error)) {
            return true;
        }

        recorded_error = true;
        last_error_code = wait_error;
#ifdef _WIN32
        if (wait_error == WSAETIMEDOUT) {
            timed_out = true;
        }
#else
        if (wait_error == ETIMEDOUT) {
            timed_out = true;
        }
#endif
    }

    if (error && error->ok) {
        if (!attempted) {
            protoerror_set(error, 0, "net_ping could not create a socket for '%s'", host);
        } else if (timed_out) {
            protoerror_set(error, 0, "net_ping timed out connecting to '%s'", host);
        } else if (recorded_error && last_error_code != 0) {
#ifdef _WIN32
            protoerror_set(error, 0, "net_ping failed for '%s' (WSA error %d)", host, last_error_code);
#else
            protoerror_set(error, 0, "net_ping failed for '%s' (errno %d)", host, last_error_code);
#endif
        } else {
            protoerror_set(error, 0, "net_ping could not reach '%s'", host);
        }
    }

    return false;
}

char *proto_stdlib_net_hostname(void) {
#ifdef _WIN32
    ensure_wsa(nullptr);
#endif
    std::array<char, 256> buffer{};
    if (gethostname(buffer.data(), static_cast<int>(buffer.size())) != 0) {
        return protohack_copy_string("", 0);
    }
    buffer.back() = '\0';
    return protohack_copy_string(buffer.data(), strlen(buffer.data()));
}

char *proto_stdlib_net_resolve(const char *host, ProtoError *error) {
    if (!host || host[0] == '\0') {
        if (error && error->ok) {
            protoerror_set(error, 0, "net_resolve expects a hostname");
        }
        return nullptr;
    }

    if (!ensure_wsa(error)) {
        return nullptr;
    }

    struct addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *resolved = nullptr;
    int status = getaddrinfo(host, nullptr, &hints, &resolved);
    if (status != 0 || !resolved) {
        if (error && error->ok) {
#ifdef _WIN32
            protoerror_set(error, 0, "net_resolve failed for '%s' (%d)", host, status);
#else
            protoerror_set(error, 0, "net_resolve failed for '%s' (%s)", host, gai_strerror(status));
#endif
        }
        return nullptr;
    }

    std::unique_ptr<struct addrinfo, decltype(&freeaddrinfo)> resolver_guard(resolved, freeaddrinfo);
    std::string address = addrinfo_to_string(resolved);
    if (address.empty()) {
        if (error && error->ok) {
            protoerror_set(error, 0, "net_resolve could not extract address for '%s'", host);
        }
        return nullptr;
    }

    return protohack_copy_string(address.c_str(), address.size());
}

ProtoStdNetInterfaces proto_stdlib_net_interfaces(ProtoError *error) {
    ProtoStdNetInterfaces result{nullptr, 0, 0};

#ifdef _WIN32
    if (!ensure_wsa(error)) {
        return result;
    }

    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG family = AF_UNSPEC;
    ULONG buffer_length = 32 * 1024u;
    std::vector<unsigned char> buffer(buffer_length);

    IP_ADAPTER_ADDRESSES *addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data());
    ULONG ret = GetAdaptersAddresses(family, flags, nullptr, addresses, &buffer_length);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(buffer_length);
        addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data());
        ret = GetAdaptersAddresses(family, flags, nullptr, addresses, &buffer_length);
    }

    if (ret != NO_ERROR) {
        if (error && error->ok) {
            protoerror_set(error, 0, "GetAdaptersAddresses failed (%lu)", ret);
        }
        return result;
    }

    std::vector<std::pair<std::string, std::string>> entries;
    for (IP_ADAPTER_ADDRESSES *adapter = addresses; adapter != nullptr; adapter = adapter->Next) {
        int name_length = WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName, -1, nullptr, 0, nullptr, nullptr);
        std::string adapter_name;
        if (name_length > 0) {
            std::vector<char> name_buffer(static_cast<size_t>(name_length));
            WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName, -1, name_buffer.data(), name_length, nullptr, nullptr);
            adapter_name.assign(name_buffer.data());
        }

        for (IP_ADAPTER_UNICAST_ADDRESS *u = adapter->FirstUnicastAddress; u != nullptr; u = u->Next) {
            int family = u->Address.lpSockaddr->sa_family;
            if (family != AF_INET && family != AF_INET6) {
                continue;
            }

            std::array<char, NI_MAXHOST> host_buffer{};
            int status = getnameinfo(u->Address.lpSockaddr,
                                     static_cast<socklen_t>(u->Address.iSockaddrLength),
                                     host_buffer.data(), static_cast<socklen_t>(host_buffer.size()),
                                     nullptr, 0, NI_NUMERICHOST);
            if (status != 0) {
                continue;
            }

            entries.emplace_back(adapter_name, std::string(host_buffer.data()));
        }
    }
#else
    struct ifaddrs *interfaces = nullptr;
    if (getifaddrs(&interfaces) != 0) {
        if (error && error->ok) {
            protoerror_set(error, 0, "getifaddrs failed");
        }
        return result;
    }

    std::unique_ptr<struct ifaddrs, decltype(&freeifaddrs)> guard(interfaces, freeifaddrs);
    std::vector<std::pair<std::string, std::string>> entries;

    for (struct ifaddrs *ifa = interfaces; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) {
            continue;
        }
        int family = ifa->ifa_addr->sa_family;
        if (family != AF_INET && family != AF_INET6) {
            continue;
        }

        std::array<char, NI_MAXHOST> host_buffer{};
        int status = getnameinfo(ifa->ifa_addr,
                                 (family == AF_INET) ? static_cast<socklen_t>(sizeof(struct sockaddr_in))
                                                     : static_cast<socklen_t>(sizeof(struct sockaddr_in6)),
                                 host_buffer.data(), static_cast<socklen_t>(host_buffer.size()),
                                 nullptr, 0, NI_NUMERICHOST);
        if (status != 0) {
            continue;
        }

        entries.emplace_back(std::string(ifa->ifa_name), std::string(host_buffer.data()));
    }
#endif

    if (entries.empty()) {
        return result;
    }

    result.count = entries.size();
    result.capacity = entries.size();
    result.items = static_cast<ProtoStdNetInterface *>(calloc(result.count, sizeof(ProtoStdNetInterface)));
    if (!result.items) {
        if (error && error->ok) {
            protoerror_set(error, 0, "net_interfaces allocation failed");
        }
        result.count = 0;
        result.capacity = 0;
        return result;
    }

    for (size_t i = 0; i < entries.size(); ++i) {
        const auto &entry = entries[i];
        result.items[i].name = protohack_copy_string(entry.first.c_str(), entry.first.size());
        result.items[i].address = protohack_copy_string(entry.second.c_str(), entry.second.size());
    }

    return result;
}

void proto_stdlib_net_interfaces_free(ProtoStdNetInterfaces *interfaces) {
    if (!interfaces) {
        return;
    }
    if (interfaces->items) {
        for (size_t i = 0; i < interfaces->count; ++i) {
            free(interfaces->items[i].name);
            free(interfaces->items[i].address);
        }
        free(interfaces->items);
        interfaces->items = nullptr;
    }
    interfaces->count = 0;
    interfaces->capacity = 0;
}

} // extern "C"
