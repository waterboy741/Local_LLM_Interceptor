#pragma once

#include "XpcControlRequestGate.hpp"
#include "XpcSessionControlReply.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace interceptor {

// Versioned listener-verification tuple carried by an authenticated installed Start. It mirrors
// the transparent probe target exactly: the strings are already gate-validated bounded IPv4 /
// interface values.
struct InstalledSessionTuple {
    std::string interfaceName;
    std::string clientIpv4;
    std::string upstreamIpv4;
    std::string listenAddress;
    int upstreamPort = 0;
    int listenerPort = 0;
};

// Qt-free implementation of the existing transparent listener readiness probe (same request
// line, same HMAC-SHA256 message, same bounded response rules as src/proxy's verifier). A
// success is point-in-time listener possession at the probed instant, not traffic readiness.
bool verifyTransparentListenerProbe(const InstalledSessionTuple &tuple,
                                    const std::vector<unsigned char> &secret, int timeoutMs,
                                    std::string *error = nullptr);

// Backend operations driven by the installed session-control core. The production installed
// service composes the real listener verification with a fail-closed owned-operations stub
// (the scoped PF/ARP backend port remains backlog work); tests and later the real backend
// inject implementations of startOwnedOperations/heartbeat/stop.
class InstalledSessionControlBackend {
  public:
    virtual ~InstalledSessionControlBackend() = default;
    virtual bool effectiveRoot() = 0;
    // Fresh cross-process verification against the handed-off tuple/secret. Runs before any
    // other operation; historical evidence is never authority.
    virtual bool freshListenerVerification(const InstalledSessionTuple &tuple,
                                           const std::vector<unsigned char> &secret) = 0;
    // Begin the scoped owned operations for a verified session (PF/ARP in the real backend).
    virtual bool startOwnedOperations(const InstalledSessionTuple &tuple, std::string *error) = 0;
    virtual void heartbeatOwnedOperations() = 0;
    // Stops owned operations; reports cleaned=true only when every owned resource was
    // verifiably released. An uncertain result keeps the cleanup obligation.
    virtual bool stopOwnedOperations(bool *cleaned, std::string *error) = 0;
};

// Qt-free decision core mirrored from the HelperLifecycleRuntime contract semantics: phases,
// fresh-verification-before-mutation, one-time capability delivery (SecRandom), replay and
// one-session-per-process rules, Stop retry while cleanup is pending, and the bounded,
// non-sensitive reason vocabulary. Single-threaded: the installed service drives it from one
// dispatch queue; the watchdog is a caller-invoked tick using the injected monotonic clock.
class InstalledSessionControlCore final {
  public:
    static constexpr int64_t watchdogTimeoutMs = 5000;

    InstalledSessionControlCore(InstalledSessionControlBackend &backend,
                                std::function<int64_t()> monotonicClockMs,
                                std::string serviceStateName = "ready");
    ~InstalledSessionControlCore();

    InstalledSessionControlCore(const InstalledSessionControlCore &) = delete;
    InstalledSessionControlCore &operator=(const InstalledSessionControlCore &) = delete;

    // Handles one gate-parsed, sender-authenticated control request. Capability bytes in the
    // accepted Start reply are owned by the caller and must be wiped after use.
    XpcSessionControlReply handleControlRequest(const XpcControlRequest &request);
    // Owner-loop watchdog tick; false when it stopped the session (cleanup may be pending).
    bool watchdogTick();

    std::string_view state() const noexcept { return state_; }
    bool sessionActive() const noexcept { return state_ == xpcSessionControlStateActive; }

  private:
    XpcSessionControlReply startSession(const XpcControlRequest &request);
    XpcSessionControlReply dispatchSessionCommand(const XpcControlRequest &request);
    bool clockNow(int64_t *nowMs) const;

    InstalledSessionControlBackend &backend_;
    std::function<int64_t()> clockMs_;
    std::string_view state_;
    std::string sessionId_;
    std::vector<unsigned char> capability_;
    int64_t lastHeartbeatMs_ = 0;
    bool capabilityDelivered_ = false;
};

} // namespace interceptor
