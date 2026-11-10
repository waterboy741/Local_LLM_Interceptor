#pragma once

#include <xpc/xpc.h>

#include <QString>

#include <cstdint>

namespace interceptor {

enum class XpcReadOnlyClientOperation { Probe, Status };

enum class XpcReadOnlyClientStatus {
    Success,
    InvalidTimeout,
    ConnectionFailed,
    TimedOut,
    ServiceUnavailable,
    InvalidReply,
};

struct XpcReadOnlyClientResult {
    XpcReadOnlyClientStatus status = XpcReadOnlyClientStatus::ConnectionFailed;
    bool ok = false;
    QString service;
    QString state;
    std::uint64_t protocolVersion = 0;

    bool succeeded() const { return status == XpcReadOnlyClientStatus::Success; }
};

// Bounded read-only client for the fixed launchd helper service. It can issue
// only probe/status and accepts only the listener's exact fixed reply shapes.
class XpcReadOnlyServiceClient final {
  public:
    static constexpr int defaultTimeoutMs = 1500;
    static constexpr int maximumTimeoutMs = 5000;

    XpcReadOnlyClientResult probe(int timeoutMs = defaultTimeoutMs) const;
    XpcReadOnlyClientResult status(int timeoutMs = defaultTimeoutMs) const;

  private:
    friend class M6XpcReadOnlyServiceClientTestAccess;

    static XpcReadOnlyClientResult
    requestWithEndpointForTesting(xpc_endpoint_t endpoint, XpcReadOnlyClientOperation operation,
                                  int timeoutMs);
    static XpcReadOnlyClientResult request(XpcReadOnlyClientOperation operation, int timeoutMs,
                                           xpc_endpoint_t testEndpoint);
};

} // namespace interceptor
