#pragma once

#include "NetworkSession.hpp"

#include <QByteArray>

#include <optional>

namespace interceptor {

// Implementations must attest the connected Unix peer's executable/signature through a
// kernel-bound identity and enforce their own deadline. UID/GID-only implementations are insufficient. No production
// implementation is provided by this offline protocol slice.
class BootstrapPeerAuthenticator {
  public:
    virtual ~BootstrapPeerAuthenticator() = default;
    virtual bool authenticate(int connectedSocketFd, const QByteArray &expectedCodeIdentity) = 0;
};

class TrustedBootstrapHandoff final {
  public:
    TrustedBootstrapHandoff(const TrustedBootstrapHandoff &) = delete;
    TrustedBootstrapHandoff &operator=(const TrustedBootstrapHandoff &) = delete;
    TrustedBootstrapHandoff(TrustedBootstrapHandoff &&other) noexcept;
    TrustedBootstrapHandoff &operator=(TrustedBootstrapHandoff &&) = delete;
    ~TrustedBootstrapHandoff();

    const SessionSnapshot &snapshot() const noexcept { return snapshot_; }
    QByteArray takeProbeSecret() noexcept;

  private:
    TrustedBootstrapHandoff(SessionSnapshot snapshot, QByteArray probeSecret)
        : snapshot_(std::move(snapshot)), probeSecret_(std::move(probeSecret)) {}
    SessionSnapshot snapshot_;
    QByteArray probeSecret_;
    friend std::optional<TrustedBootstrapHandoff>
    receiveTrustedBootstrapHandoff(int, BootstrapPeerAuthenticator &, const QByteArray &,
                                   QString *);
};

// Each side owns and closes its connected Unix socket. Both calls are one-shot and bounded to
// three seconds after successful peer attestation. The writer copies the secret; its owner must
// wipe the original when the GUI session ends.
bool writeBootstrapHandoff(int connectedSocketFd, BootstrapPeerAuthenticator &authenticator,
                           const QByteArray &expectedHelperCodeIdentity,
                           const SessionSnapshot &snapshot, const QByteArray &probeSecret,
                           QString *error = nullptr);
std::optional<TrustedBootstrapHandoff>
receiveTrustedBootstrapHandoff(int connectedSocketFd, BootstrapPeerAuthenticator &authenticator,
                               const QByteArray &expectedGuiCodeIdentity, QString *error = nullptr);

} // namespace interceptor
