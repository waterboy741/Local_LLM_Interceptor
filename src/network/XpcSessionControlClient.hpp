#pragma once

#include <xpc/xpc.h>

#include <QByteArray>
#include <QString>

#include <cstdint>

namespace interceptor {

// Mirrors the installed session-control 9-key Start grammar and the shared
// Heartbeat/Stop grammar over the fixed privileged Mach service. Every call pins the helper's
// cdhash requirement (XPC_CONNECTION_MACH_SERVICE_PRIVILEGED plus the peer code-signing
// requirement) and fails closed when verification is unavailable.
struct XpcSessionControlClientTuple {
    QString interfaceName;
    QString clientIpv4;
    QString upstreamIpv4;
    QString listenAddress;
    quint16 upstreamPort = 0;
    quint16 listenerPort = 0;
};

enum class XpcSessionControlClientStatus {
    Success,
    InvalidTimeout,
    InvalidRequest,
    InvalidPeerRequirement,
    ConnectionFailed,
    PeerVerificationSetupFailed,
    PeerIdentityMismatch,
    TimedOut,
    ServiceUnavailable,
    InvalidReply,
};

struct XpcSessionControlClientResult {
    XpcSessionControlClientStatus status = XpcSessionControlClientStatus::ConnectionFailed;
    bool ok = false;
    QString state;
    QString sessionId;
    QByteArray sessionCapability;
    QString reason;

    bool succeeded() const { return status == XpcSessionControlClientStatus::Success; }
};

class XpcSessionControlClient final {
  public:
    static constexpr int defaultTimeoutMs = 2500;
    static constexpr int maximumTimeoutMs = 10000;
    static constexpr qsizetype capabilityBytes = 32;

    // One-time probe secret is moved into the request and wiped after use by the caller.
    static XpcSessionControlClientResult start(const XpcSessionControlClientTuple &tuple,
                                               const QByteArray &probeSecret,
                                               const QByteArray &helperRequirement,
                                               int timeoutMs = defaultTimeoutMs);
    static XpcSessionControlClientResult heartbeat(const QString &sessionId,
                                                   const QByteArray &capability,
                                                   const QByteArray &helperRequirement,
                                                   int timeoutMs = defaultTimeoutMs);
    static XpcSessionControlClientResult stop(const QString &sessionId,
                                              const QByteArray &capability,
                                              const QByteArray &helperRequirement,
                                              int timeoutMs = defaultTimeoutMs);
    static XpcSessionControlClientResult status(const QByteArray &helperRequirement,
                                                int timeoutMs = defaultTimeoutMs);

  private:
    friend class M6XpcSessionControlClientTestAccess;

    enum class Operation { Start, Heartbeat, Stop, Status };

    static XpcSessionControlClientResult
    request(Operation operation, int timeoutMs, const QByteArray &helperRequirement,
            xpc_endpoint_t testEndpoint = nullptr,
            const XpcSessionControlClientTuple *tuple = nullptr,
            const QByteArray *probeSecret = nullptr, const QString *sessionId = nullptr,
            const QByteArray *capability = nullptr);
    static XpcSessionControlClientResult
    startWithEndpointForTesting(xpc_endpoint_t endpoint, const XpcSessionControlClientTuple &tuple,
                                const QByteArray &probeSecret, const QByteArray &helperRequirement,
                                int timeoutMs);
    static XpcSessionControlClientResult
    sessionWithEndpointForTesting(xpc_endpoint_t endpoint, Operation operation,
                                  const QString &sessionId, const QByteArray &capability,
                                  const QByteArray &helperRequirement, int timeoutMs);
    static XpcSessionControlClientResult
    statusWithEndpointForTesting(xpc_endpoint_t endpoint, const QByteArray &helperRequirement,
                                 int timeoutMs);
};

} // namespace interceptor
