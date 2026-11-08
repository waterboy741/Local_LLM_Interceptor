#pragma once

#include "TransparentProxyProbe.hpp"
#include "network/LabPreflight.hpp"
#include "network/NetworkSession.hpp"
#include "network/PfDiagnostics.hpp"
#include "network/RouteNeighborDiagnostics.hpp"

#include <optional>

namespace interceptor {

struct ObservedNeighborIdentity {
    QString interfaceName;
    QString ipv4;
    QString mac;
    bool resolved = false;
};

class NeighborIdentityVerifier {
  public:
    virtual ~NeighborIdentityVerifier() = default;
    virtual std::optional<ObservedNeighborIdentity> observe(const QString &interfaceName,
                                                            const QString &ipv4) = 0;
};

class TransparentListenerVerifier {
  public:
    virtual ~TransparentListenerVerifier() = default;
    virtual bool verify(const TransparentProxyProbeTarget &target, const QByteArray &secret,
                        int timeoutMs) = 0;
};

class SystemTransparentListenerVerifier final : public TransparentListenerVerifier {
  public:
    bool verify(const TransparentProxyProbeTarget &target, const QByteArray &secret,
                int timeoutMs) override;
};

struct HelperPreMutationResult {
    bool ready = false;
    QString statusCode;
};

// Read-only, point-in-time gate. It must run on the helper immediately before any PF mutation;
// the caller must not cache a successful result. No mutation occurs in this class. Historical
// facts from the handoff are compared against fresh observations and never used as authority.
class HelperPreMutationGate final {
  public:
    static HelperPreMutationResult
    verify(const SessionSnapshot &snapshot, const QByteArray &probeSecret, LabProbe &labProbe,
           NetworkCommandRunner &networkRunner, PfCommandRunner &pfRunner,
           NeighborIdentityVerifier &neighbors, TransparentListenerVerifier &listener);
};

} // namespace interceptor
