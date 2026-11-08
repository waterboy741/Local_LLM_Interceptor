#pragma once

#include "HelperDispatcher.hpp"
#include "HostSessionLease.hpp"
#include "PfAnchorRecoverySystemOperations.hpp"
#include "TrustedBootstrapHandoff.hpp"

#include <functional>
#include <memory>
#include <optional>

namespace interceptor {

class HelperHostCredentials final {
  public:
    HelperHostCredentials(const HelperHostCredentials &) = delete;
    HelperHostCredentials &operator=(const HelperHostCredentials &) = delete;
    HelperHostCredentials(HelperHostCredentials &&other) noexcept;
    HelperHostCredentials &operator=(HelperHostCredentials &&) = delete;
    ~HelperHostCredentials();

    const QString &sessionId() const { return sessionId_; }
    const QByteArray &capability() const { return capability_; }

  private:
    HelperHostCredentials(QString sessionId, QByteArray capability)
        : sessionId_(std::move(sessionId)), capability_(std::move(capability)) {}
    void wipeCapability() noexcept;

    QString sessionId_;
    QByteArray capability_;
    friend class LeasedHelperHost;
};

// Same-process offline host bootstrap. A trusted outer authenticator must supply `bootstrapPeer`;
// this class does not install a listener, establish app identity, or verify signing. Keep the host
// on its creating thread. Cross-thread destruction is deferred to that thread's running Qt event
// loop; if that thread has already stopped, state is retained until process exit rather than
// destructed unsafely. Create/start it on the ProxyServer owner thread. The trusted directory fd
// must remain valid through create(); objects captured by the operations factory and PF journals
// must outlive the host. The factory must assemble the backend without invoking mutations.
class LeasedHelperHost final {
  public:
    using OperationsFactory = std::function<std::unique_ptr<PfAnchorRecoverySystemOperations>(
        const HostSessionLease &, const SessionSnapshot &)>;
    using BootstrapOperationsFactory =
        std::function<std::unique_ptr<PfAnchorRecoverySystemOperations>(
            const HostSessionLease &, const SessionSnapshot &, const QByteArray &)>;
    using MonotonicClock = HelperDispatcher::MonotonicClock;

    static std::unique_ptr<LeasedHelperHost>
    create(int trustedDirectoryFd, const SessionConfig &config, const NetworkFacts &facts,
           const TransparentProxyReadiness &readiness, const VerifiedPeer &bootstrapPeer,
           const OperationsFactory &operationsFactory, MonotonicClock monotonicClock,
           QString *error = nullptr);

    // Helper-process bootstrap from a handoff already authenticated by the outer launcher.
    // The caller must bind bootstrapPeer to the same GUI peer authenticated on the handoff socket;
    // this API cannot establish that binding itself. The transferred snapshot is immutable input,
    // and this overload cannot recheck GUI-owned ProxyServer readiness. The factory gets the
    // one-time proxy probe secret only while assembling operations. It must not retain a copy
    // unless it owns and wipes that copy; this host wipes its local copy on return.
    // Production callers must make the pre-mutation gate a mandatory part of their operations
    // composition. This overload does not itself establish readiness or authorize live mutation.
    static std::unique_ptr<LeasedHelperHost>
    createFromBootstrap(int trustedDirectoryFd, TrustedBootstrapHandoff bootstrap,
                        const VerifiedPeer &bootstrapPeer,
                        const BootstrapOperationsFactory &operationsFactory,
                        MonotonicClock monotonicClock, QString *error = nullptr);

    LeasedHelperHost(const LeasedHelperHost &) = delete;
    LeasedHelperHost &operator=(const LeasedHelperHost &) = delete;
    LeasedHelperHost(LeasedHelperHost &&other) = delete;
    LeasedHelperHost &operator=(LeasedHelperHost &&) = delete;
    ~LeasedHelperHost();

    bool start(QString *error = nullptr);
    bool stop(QString *error = nullptr);
    bool dispatchOne(int connectedSocketFd, QString *error = nullptr);
    std::optional<HelperHostCredentials> takeCredentials();
    bool watchdogRunning() const;
    NetworkSession::State state() const;
    const SessionSnapshot &snapshot() const;

  private:
    struct State;
    explicit LeasedHelperHost(std::unique_ptr<State> state);
    std::unique_ptr<State> state_;
};

} // namespace interceptor
