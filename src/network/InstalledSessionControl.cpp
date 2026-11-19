#define __STDC_WANT_LIB_EXT1__ 1
#include "InstalledSessionControl.hpp"

#include <CommonCrypto/CommonCrypto.h>
#include <Security/SecRandom.h>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstring>

namespace interceptor {
namespace {

constexpr std::string_view probePrefix = "/.llm-interceptor/readiness/v1/";
constexpr size_t probeMaximumResponseBytes = 1024;

void hexAppend(const unsigned char *data, size_t length, std::string *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t index = 0; index < length; ++index) {
        out->push_back(digits[data[index] >> 4]);
        out->push_back(digits[data[index] & 0xf]);
    }
}

void wipe(std::vector<unsigned char> &bytes) noexcept {
    if (!bytes.empty())
        (void)memset_s(bytes.data(), bytes.size(), 0, bytes.size());
    bytes.clear();
}

bool interfaceOwnsAddress(const std::string &interfaceName, const std::string &listenAddress) {
    struct ifaddrs *addresses = nullptr;
    if (getifaddrs(&addresses) != 0)
        return false;
    struct sockaddr_in parsed{};
    if (inet_pton(AF_INET, listenAddress.c_str(), &parsed.sin_addr) != 1) {
        freeifaddrs(addresses);
        return false;
    }
    bool found = false;
    for (struct ifaddrs *entry = addresses; entry; entry = entry->ifa_next) {
        if (!entry->ifa_addr || entry->ifa_addr->sa_family != AF_INET ||
            entry->ifa_name != interfaceName)
            continue;
        const auto *address = reinterpret_cast<const struct sockaddr_in *>(entry->ifa_addr);
        if (address->sin_addr.s_addr == parsed.sin_addr.s_addr &&
            (entry->ifa_flags & IFF_UP) != 0 && (entry->ifa_flags & IFF_RUNNING) != 0 &&
            (entry->ifa_flags & IFF_LOOPBACK) == 0)
            found = true;
        break;
    }
    freeifaddrs(addresses);
    return found;
}

bool probeValid(const InstalledSessionTuple &tuple, const std::vector<unsigned char> &secret,
                int timeoutMs) {
    return secret.size() == xpcSessionControlCapabilityBytes && timeoutMs >= 1 &&
           timeoutMs <= 3000 && tuple.upstreamPort >= 1 && tuple.upstreamPort <= 65535 &&
           tuple.listenerPort >= 1 && tuple.listenerPort <= 65535 && !tuple.interfaceName.empty();
}

} // namespace

bool verifyTransparentListenerProbe(const InstalledSessionTuple &tuple,
                                    const std::vector<unsigned char> &secret, int timeoutMs,
                                    std::string *error) {
    const auto fail = [error](const char *reason) {
        if (error)
            *error = reason;
        return false;
    };
    if (error)
        error->clear();
    if (!probeValid(tuple, secret, timeoutMs) ||
        !interfaceOwnsAddress(tuple.interfaceName, tuple.listenAddress))
        return fail("invalid_probe_target");

    unsigned char nonce[xpcSessionControlCapabilityBytes];
    if (SecRandomCopyBytes(kSecRandomDefault, sizeof(nonce), nonce) != errSecSuccess)
        return fail("probe_nonce_unavailable");

    // HMAC-SHA256 over the version-1 probe message; identical semantics to the Qt verifier.
    std::string message = "llm-interceptor-probe-v1\n";
    const std::string nonceHex = [&]() -> std::string {
        std::string value;
        value.reserve(64);
        for (const unsigned char byte : nonce) {
            char pair[3] = {};
            pair[0] = "0123456789abcdef"[byte >> 4];
            pair[1] = "0123456789abcdef"[byte & 0xf];
            value.append(pair, 2);
        }
        return value;
    }();
    message += nonceHex + '\n' + tuple.interfaceName + '\n' + tuple.clientIpv4 + '\n' +
               tuple.upstreamIpv4 + '\n' + std::to_string(tuple.upstreamPort) + '\n' +
               std::to_string(tuple.listenerPort) + '\n' + tuple.listenAddress + '\n';
    unsigned char mac[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, secret.data(), secret.size(), message.data(), message.size(), mac);
    std::string expected;
    expected.reserve(CC_SHA256_DIGEST_LENGTH * 2);
    hexAppend(mac, sizeof(mac), &expected);

    // Note: hexAppend duplication with nonceHex intentional for nonce secrecy; wipe locals.
    (void)memset_s(nonce, sizeof(nonce), 0, sizeof(nonce));
    (void)memset_s(mac, sizeof(mac), 0, sizeof(mac));

    const auto started = std::chrono::steady_clock::now();
    const auto remainingMs = [&]() {
        return timeoutMs - static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                std::chrono::steady_clock::now() - started)
                                                .count());
    };

    int descriptor = ::socket(AF_INET, SOCK_STREAM, 0);
    if (descriptor < 0)
        return fail("probe_socket_failed");
    struct sockaddr_in source{};
    source.sin_family = AF_INET;
    source.sin_port = 0;
    if (inet_pton(AF_INET, tuple.listenAddress.c_str(), &source.sin_addr) != 1 ||
        ::bind(descriptor, reinterpret_cast<const struct sockaddr *>(&source), sizeof(source)) !=
            0 ||
        ::fcntl(descriptor, F_SETFL, O_NONBLOCK) < 0) {
        (void)::close(descriptor);
        return fail("probe_bind_failed");
    }
    struct sockaddr_in destination = source;
    destination.sin_port = htons(static_cast<uint16_t>(tuple.listenerPort));
    if (::connect(descriptor, reinterpret_cast<const struct sockaddr *>(&destination),
                  sizeof(destination)) != 0 &&
        errno != EINPROGRESS) {
        (void)::close(descriptor);
        return fail("probe_connect_failed");
    }
    pollfd outgoing{descriptor, POLLOUT, 0};
    if (::poll(&outgoing, 1, remainingMs()) <= 0) {
        (void)::close(descriptor);
        return fail("probe_connect_failed");
    }
    const std::string request = "GET " + std::string(probePrefix) + nonceHex +
                                " HTTP/1.1\r\nHost: " + tuple.listenAddress +
                                "\r\nConnection: close\r\n\r\n";
    for (size_t sent = 0; sent < request.size() && remainingMs() > 0;) {
        pollfd pending{descriptor, POLLOUT, 0};
        if (::poll(&pending, 1, remainingMs() <= 0 ? 0 : remainingMs()) <= 0)
            break;
        const ssize_t written = ::send(descriptor, request.data() + sent, request.size() - sent, 0);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        sent += static_cast<size_t>(written);
    }
    std::string response;
    response.reserve(256);
    bool closed = false;
    while (!closed && response.size() < probeMaximumResponseBytes && remainingMs() > 0) {
        pollfd incoming{descriptor, POLLIN, 0};
        const int polled = ::poll(&incoming, 1, remainingMs() <= 0 ? 0 : remainingMs());
        if (polled < 0) {
            if (errno != EINTR)
                break;
            continue;
        }
        if (polled == 0)
            break;
        char fragment[256];
        const ssize_t received = ::recv(descriptor, fragment, sizeof(fragment), 0);
        if (received < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (received == 0) {
            closed = true;
            break;
        }
        response.append(fragment, static_cast<size_t>(received));
        const size_t separator = response.find("\r\n\r\n");
        if (separator != std::string::npos && response.size() == separator + 4 + expected.size())
            break;
    }
    (void)::close(descriptor);
    if (response.size() > probeMaximumResponseBytes)
        return fail("probe_response_invalid");
    if (response.compare(0, 13, "HTTP/1.1 200 ") != 0)
        return fail("probe_response_invalid");
    const size_t separator = response.find("\r\n\r\n");
    if (separator == std::string::npos)
        return fail("probe_response_incomplete");
    const std::string body = response.substr(separator + 4);
    if (body.size() != expected.size() ||
        timingsafe_bcmp(body.data(), expected.data(), body.size()) != 0)
        return fail("probe_authentication_failed");
    return true;
}

InstalledSessionControlCore::InstalledSessionControlCore(InstalledSessionControlBackend &backend,
                                                         std::function<int64_t()> monotonicClockMs,
                                                         std::string serviceStateName)
    : backend_(backend), clockMs_(std::move(monotonicClockMs)),
      state_(xpcSessionControlStateReady) {
    (void)serviceStateName;
}

InstalledSessionControlCore::~InstalledSessionControlCore() {
    if (state_ == xpcSessionControlStateActive || state_ == xpcSessionControlStateCleanupPending) {
        bool cleaned = false;
        (void)backend_.stopOwnedOperations(&cleaned, nullptr);
    }
    wipe(capability_);
}

bool InstalledSessionControlCore::clockNow(int64_t *nowMs) const {
    if (!clockMs_ || !nowMs)
        return false;
    try {
        const int64_t value = clockMs_();
        if (value < 0)
            return false;
        *nowMs = value;
        return true;
    } catch (...) {
        return false;
    }
}

XpcSessionControlReply
InstalledSessionControlCore::handleControlRequest(const XpcControlRequest &request) {
    XpcSessionControlReply reply;
    reply.state.assign(state_);
    const auto reject = [&reply](std::string_view reason) {
        reply.reason.assign(reason);
        return reply;
    };
    switch (request.operation) {
    case XpcControlOperation::Start:
        return startSession(request);
    case XpcControlOperation::Heartbeat:
    case XpcControlOperation::Stop:
        return dispatchSessionCommand(request);
    case XpcControlOperation::Probe:
    case XpcControlOperation::Status:
    case XpcControlOperation::Invalid:
    default:
        // Probe/status is answered by the read-only surface of the same endpoint.
        return reject("operation_unsupported");
    }
}

XpcSessionControlReply InstalledSessionControlCore::startSession(const XpcControlRequest &request) {
    XpcSessionControlReply reply;
    reply.state.assign(state_);
    const auto reject = [&reply](std::string_view reason) {
        reply.reason.assign(reason);
        return reply;
    };
    if (state_ == xpcSessionControlStateActive || state_ == xpcSessionControlStateCleanupPending)
        return reject("duplicate_start");
    if (state_ == xpcSessionControlStateStopped)
        return reject("lifecycle_stopped");
    if (!backend_.effectiveRoot())
        return reject("session_start_unavailable");
    const InstalledSessionTuple tuple{request.sessionInterface,
                                      request.sessionClientIpv4,
                                      request.sessionUpstreamIpv4,
                                      request.sessionListenAddress,
                                      static_cast<int>(request.sessionUpstreamPort),
                                      static_cast<int>(request.sessionListenerPort)};
    // Fresh cross-process listener verification against the handed-off tuple/secret: nothing
    // else may run first, and no historical evidence substitutes for it.
    std::vector<unsigned char> secret = request.probeSecret;
    const bool verified = backend_.freshListenerVerification(tuple, secret);
    wipe(secret);
    if (!verified)
        return reject("listener_readiness_unverified");

    std::string startError;
    if (!backend_.startOwnedOperations(tuple, &startError))
        return reject("session_start_failed");
    int64_t nowMs = 0;
    if (!clockNow(&nowMs))
        nowMs = 0;
    lastHeartbeatMs_ = nowMs;

    // One-time session identity + capability: SecRandom-backed, delivered only here.
    unsigned char identifier[8], randomCapability[xpcSessionControlCapabilityBytes];
    if (SecRandomCopyBytes(kSecRandomDefault, sizeof(identifier), identifier) != errSecSuccess ||
        SecRandomCopyBytes(kSecRandomDefault, sizeof(randomCapability), randomCapability) !=
            errSecSuccess)
        return reject("session_credentials_unavailable");
    sessionId_.clear();
    sessionId_.reserve(2 + 2 * sizeof(identifier));
    hexAppend(identifier, sizeof(identifier), &sessionId_);
    capability_.assign(randomCapability, randomCapability + sizeof(randomCapability));
    (void)memset_s(identifier, sizeof(identifier), 0, sizeof(identifier));
    (void)memset_s(randomCapability, sizeof(randomCapability), 0, sizeof(randomCapability));
    if (capability_.size() != xpcSessionControlCapabilityBytes)
        return reject("session_credentials_unavailable");

    state_ = xpcSessionControlStateActive;
    reply.state.assign(state_);
    reply.ok = true;
    reply.sessionId = sessionId_;
    reply.sessionCapability = capability_;
    capabilityDelivered_ = true;
    return reply;
}

XpcSessionControlReply
InstalledSessionControlCore::dispatchSessionCommand(const XpcControlRequest &request) {
    XpcSessionControlReply reply;
    reply.state.assign(state_);
    const auto reject = [&reply](std::string_view reason) {
        reply.reason.assign(reason);
        return reply;
    };
    if (state_ != xpcSessionControlStateActive && state_ != xpcSessionControlStateCleanupPending)
        return reject("session_binding_mismatch");
    if (request.sessionId != sessionId_ || request.sessionCapability.size() != capability_.size() ||
        timingsafe_bcmp(request.sessionCapability.data(), capability_.data(), capability_.size()) !=
            0)
        return reject("session_binding_mismatch");

    int64_t nowMs = 0;
    if (request.operation == XpcControlOperation::Heartbeat) {
        if (state_ != xpcSessionControlStateActive)
            return reject("heartbeat_rejected");
        if (!clockNow(&nowMs) || nowMs < lastHeartbeatMs_)
            return reject("heartbeat_rejected");
        lastHeartbeatMs_ = nowMs;
        backend_.heartbeatOwnedOperations();
        reply.ok = true;
        reply.sessionId = sessionId_;
        return reply;
    }
    bool cleaned = false;
    std::string stopError;
    if (!backend_.stopOwnedOperations(&cleaned, &stopError) && !cleaned) {
        state_ = xpcSessionControlStateCleanupPending;
        reply.state.assign(state_);
        return reject("cleanup_pending");
    }
    state_ = xpcSessionControlStateStopped;
    wipe(capability_);
    reply.state.assign(state_);
    reply.ok = true;
    return reply;
}

bool InstalledSessionControlCore::watchdogTick() {
    if (state_ != xpcSessionControlStateActive)
        return true;
    int64_t nowMs = 0;
    if (!clockNow(&nowMs))
        return false;
    if (nowMs - lastHeartbeatMs_ < watchdogTimeoutMs)
        return true;
    bool cleaned = false;
    (void)backend_.stopOwnedOperations(&cleaned, nullptr);
    state_ = cleaned ? xpcSessionControlStateStopped : xpcSessionControlStateCleanupPending;
    if (cleaned)
        wipe(capability_);
    return false;
}

} // namespace interceptor
