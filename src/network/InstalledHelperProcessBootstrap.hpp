#pragma once

#include "InstalledHelperBootstrap.hpp"
#include "LeasedHelperHost.hpp"

#include <memory>

namespace interceptor {

// One-process bootstrap for the installed helper. Authentication and peer credentials are both
// evaluated against the same connected handoff socket. Production callers must supply a fixed
// installation identity and an operations factory whose startup path requires the fresh
// pre-mutation gate. This does not create a control listener or provide either production piece.
class InstalledHelperProcessBootstrap final {
  public:
    using BootstrapOperationsFactory = LeasedHelperHost::BootstrapOperationsFactory;
    using MonotonicClock = LeasedHelperHost::MonotonicClock;

    static std::unique_ptr<InstalledHelperProcessBootstrap>
    create(const QString &stateDirectoryPath, int connectedBootstrapSocketFd,
           BootstrapPeerAuthenticator &authenticator, const QByteArray &expectedGuiCodeIdentity,
           const BootstrapOperationsFactory &operationsFactory, MonotonicClock monotonicClock,
           QString *error = nullptr);

    InstalledHelperProcessBootstrap(const InstalledHelperProcessBootstrap &) = delete;
    InstalledHelperProcessBootstrap &operator=(const InstalledHelperProcessBootstrap &) = delete;
    ~InstalledHelperProcessBootstrap();

    int stateDirectoryDescriptor() const noexcept { return directory_.descriptor(); }
    LeasedHelperHost &host() noexcept { return *host_; }
    const LeasedHelperHost &host() const noexcept { return *host_; }
    bool start(QString *error = nullptr);
    std::optional<HelperHostCredentials> takeCredentials();

  private:
    InstalledHelperProcessBootstrap(InstalledHelperStateDirectory directory,
                                    std::unique_ptr<LeasedHelperHost> host);

    // Reverse destruction order keeps the directory descriptor open through host teardown.
    InstalledHelperStateDirectory directory_;
    std::unique_ptr<LeasedHelperHost> host_;
};

} // namespace interceptor
