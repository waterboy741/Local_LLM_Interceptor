#pragma once

#include "HelperPreMutationGate.hpp"

namespace interceptor {

// Uses the existing bounded macOS arp runner. A result is a fresh neighbor-table observation,
// not proof that a remote host currently owns or accepts the claimed MAC address.
class MacNeighborIdentityVerifier final : public NeighborIdentityVerifier {
  public:
    explicit MacNeighborIdentityVerifier(NetworkCommandRunner &runner) : runner_(runner) {}
    std::optional<ObservedNeighborIdentity> observe(const QString &interfaceName,
                                                    const QString &ipv4) override;

    static constexpr int timeoutMs = 1500;
    static constexpr qsizetype maximumOutputBytes = 4096;

  private:
    NetworkCommandRunner &runner_;
};

MacNeighborIdentityVerifier &systemMacNeighborIdentityVerifier();

} // namespace interceptor
