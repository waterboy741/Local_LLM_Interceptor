#include "InstalledHelperProcessBootstrap.hpp"

#include "UnixPeerCredentials.hpp"

#include <unistd.h>

namespace interceptor {

InstalledHelperProcessBootstrap::InstalledHelperProcessBootstrap(
    InstalledHelperStateDirectory directory, std::unique_ptr<LeasedHelperHost> host)
    : directory_(std::move(directory)), host_(std::move(host)) {}

InstalledHelperProcessBootstrap::~InstalledHelperProcessBootstrap() = default;

std::unique_ptr<InstalledHelperProcessBootstrap> InstalledHelperProcessBootstrap::create(
    const QString &stateDirectoryPath, int connectedBootstrapSocketFd,
    BootstrapPeerAuthenticator &authenticator, const QByteArray &expectedGuiCodeIdentity,
    const BootstrapOperationsFactory &operationsFactory, MonotonicClock monotonicClock,
    QString *error) {
    const auto fail =
        [error](const QString &reason) -> std::unique_ptr<InstalledHelperProcessBootstrap> {
        if (error)
            *error = reason;
        return {};
    };
    if (error)
        error->clear();
    if (::geteuid() != 0)
        return fail(QStringLiteral("effective_root_required"));

    QString directoryError;
    auto directory = InstalledHelperStateDirectory::open(stateDirectoryPath, 0, &directoryError);
    if (!directory)
        return fail(directoryError.isEmpty() ? QStringLiteral("unsafe_state_directory")
                                             : directoryError);

    QString handoffError;
    auto bootstrap = receiveTrustedBootstrapHandoff(connectedBootstrapSocketFd, authenticator,
                                                    expectedGuiCodeIdentity, &handoffError);
    if (!bootstrap)
        return fail(handoffError.isEmpty() ? QStringLiteral("trusted_bootstrap_unavailable")
                                           : handoffError);

    // The signer check above and this kernel credential query use the same connected socket.
    QString peerError;
    auto peer = verifiedPeerForUnixSocket(connectedBootstrapSocketFd, &peerError);
    if (!peer)
        return fail(peerError.isEmpty() ? QStringLiteral("bootstrap_peer_unavailable") : peerError);

    QString hostError;
    auto host = LeasedHelperHost::createFromBootstrap(
        directory->descriptor(), std::move(*bootstrap), *peer, operationsFactory,
        std::move(monotonicClock), &hostError);
    if (!host)
        return fail(hostError.isEmpty() ? QStringLiteral("helper_host_unavailable") : hostError);

    return std::unique_ptr<InstalledHelperProcessBootstrap>(
        new InstalledHelperProcessBootstrap(std::move(*directory), std::move(host)));
}

bool InstalledHelperProcessBootstrap::start(QString *error) { return host_ && host_->start(error); }

std::optional<HelperHostCredentials> InstalledHelperProcessBootstrap::takeCredentials() {
    return host_ ? host_->takeCredentials() : std::nullopt;
}

} // namespace interceptor
