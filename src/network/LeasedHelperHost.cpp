#define __STDC_WANT_LIB_EXT1__ 1
#include "LeasedHelperHost.hpp"

#include "HelperSessionIdentity.hpp"
#include "HelperWatchdog.hpp"
#include "LeasedUnixSocketCommandTransport.hpp"

#include <QThread>

#include <string.h>

namespace interceptor {
namespace {
void wipe(QByteArray &bytes) noexcept {
    if (!bytes.isEmpty())
        (void)memset_s(bytes.data(), static_cast<rsize_t>(bytes.size()), 0,
                       static_cast<rsize_t>(bytes.size()));
    bytes.clear();
}

QByteArray secureClone(const QByteArray &bytes) {
    return QByteArray(bytes.constData(), bytes.size());
}

struct WipeOnExit final {
    QByteArray &bytes;
    ~WipeOnExit() { wipe(bytes); }
};

bool validPeer(const VerifiedPeer &peer) {
    return peer.transportAuthenticated && !peer.auditIdentity.isEmpty() &&
           peer.auditIdentity.size() <= 256;
}

} // namespace

HelperHostCredentials::HelperHostCredentials(HelperHostCredentials &&other) noexcept
    : sessionId_(std::move(other.sessionId_)), capability_(std::move(other.capability_)) {}

HelperHostCredentials::~HelperHostCredentials() { wipeCapability(); }

void HelperHostCredentials::wipeCapability() noexcept { wipe(capability_); }

struct LeasedHelperHost::State final : QObject {
    HostSessionLease lease;
    std::optional<TransparentProxyReadiness> readiness;
    VerifiedPeer trustedPeer;
    SessionSnapshot permittedSnapshot;
    std::unique_ptr<PfAnchorRecoverySystemOperations> operations;
    std::unique_ptr<HelperDispatcher> dispatcher;
    std::unique_ptr<HelperWatchdog> watchdog;
    QByteArray controlCapability;
    QByteArray clientCapability;
    Qt::HANDLE ownerThreadId = QThread::currentThreadId();
    bool startAttempted = false;
    bool started = false;
    bool credentialsTaken = false;

    State(HostSessionLease hostLease, TransparentProxyReadiness proxyReadiness, VerifiedPeer peer,
          SessionSnapshot snapshot)
        : lease(std::move(hostLease)), readiness(std::move(proxyReadiness)),
          trustedPeer(std::move(peer)), permittedSnapshot(std::move(snapshot)) {}

    State(HostSessionLease hostLease, VerifiedPeer peer, SessionSnapshot snapshot)
        : lease(std::move(hostLease)), trustedPeer(std::move(peer)),
          permittedSnapshot(std::move(snapshot)) {}

    ~State() {
        Q_ASSERT(onOwnerThread());
        if (watchdog)
            watchdog.reset();
        if (dispatcher && dispatcher->state() != NetworkSession::State::Idle &&
            !controlCapability.isEmpty()) {
            HelperCommand command;
            command.type = HelperCommand::Type::Stop;
            command.capability = controlCapability;
            command.anchor = permittedSnapshot.anchor();
            if (const auto nowMs = dispatcher->trustedMonotonicNowMs())
                command.nowMs = *nowMs;
            (void)dispatcher->dispatch(trustedPeer, command);
        }
        dispatcher.reset();
        operations.reset();
        wipe(controlCapability);
        wipe(clientCapability);
    }

    bool onOwnerThread() const noexcept { return QThread::currentThreadId() == ownerThreadId; }
};

std::unique_ptr<LeasedHelperHost> LeasedHelperHost::create(
    int trustedDirectoryFd, const SessionConfig &config, const NetworkFacts &facts,
    const TransparentProxyReadiness &readiness, const VerifiedPeer &bootstrapPeer,
    const OperationsFactory &operationsFactory, MonotonicClock monotonicClock, QString *error) {
    const auto fail = [error](const QString &reason) -> std::unique_ptr<LeasedHelperHost> {
        if (error)
            *error = reason;
        return {};
    };
    if (error)
        error->clear();
    if (!validPeer(bootstrapPeer))
        return fail(QStringLiteral("trusted_bootstrap_peer_required"));
    if (!operationsFactory || !monotonicClock)
        return fail(QStringLiteral("helper_bootstrap_dependency_missing"));
    if (!readiness.isCurrent())
        return fail(QStringLiteral("transparent_proxy_not_current"));

    auto lease = HostSessionLease::acquire(trustedDirectoryFd);
    if (!lease.acquired() || !lease.descriptorHasCloseOnExec())
        return fail(QStringLiteral("host_session_lease_unavailable"));

    auto identity = HelperSessionIdentity::create();
    if (!identity)
        return fail(QStringLiteral("helper_identity_unavailable"));
    QString snapshotError;
    auto snapshot =
        SessionSnapshot::create(config, facts, readiness, identity->sessionId(), &snapshotError);
    if (!snapshot)
        return fail(snapshotError.isEmpty() ? QStringLiteral("session_snapshot_mismatch")
                                            : snapshotError);
    if (!readiness.isCurrent())
        return fail(QStringLiteral("transparent_proxy_not_current"));

    std::unique_ptr<State> state;
    try {
        state = std::make_unique<State>(std::move(lease), readiness, bootstrapPeer, *snapshot);
        state->operations = operationsFactory(state->lease, state->permittedSnapshot);
    } catch (...) {
        return fail(QStringLiteral("helper_operations_creation_failed"));
    }
    if (!state->operations)
        return fail(QStringLiteral("helper_operations_unavailable"));

    QByteArray clientCapability = std::move(*identity).takeCapability();
    if (clientCapability.size() != HelperSessionIdentity::capabilityRandomBytes) {
        wipe(clientCapability);
        return fail(QStringLiteral("helper_capability_unavailable"));
    }
    QByteArray dispatcherCapability;
    try {
        state->controlCapability = secureClone(clientCapability);
        state->clientCapability = secureClone(clientCapability);
        dispatcherCapability = secureClone(state->controlCapability);
        state->dispatcher = std::make_unique<HelperDispatcher>(
            *state->operations, state->permittedSnapshot, state->trustedPeer,
            std::move(dispatcherCapability), nullptr, std::move(monotonicClock));
        state->watchdog = std::make_unique<HelperWatchdog>(*state->dispatcher);
    } catch (...) {
        wipe(dispatcherCapability);
        wipe(clientCapability);
        return fail(QStringLiteral("helper_dispatcher_creation_failed"));
    }
    wipe(clientCapability);
    if (!state->dispatcher->ready())
        return fail(QStringLiteral("helper_dispatcher_not_ready"));
    return std::unique_ptr<LeasedHelperHost>(new LeasedHelperHost(std::move(state)));
}

std::unique_ptr<LeasedHelperHost>
LeasedHelperHost::createFromBootstrap(int trustedDirectoryFd, TrustedBootstrapHandoff bootstrap,
                                      const VerifiedPeer &bootstrapPeer,
                                      const BootstrapOperationsFactory &operationsFactory,
                                      MonotonicClock monotonicClock, QString *error) {
    const auto fail = [error](const QString &reason) -> std::unique_ptr<LeasedHelperHost> {
        if (error)
            *error = reason;
        return {};
    };
    if (error)
        error->clear();
    if (!validPeer(bootstrapPeer))
        return fail(QStringLiteral("trusted_bootstrap_peer_required"));
    if (!operationsFactory || !monotonicClock)
        return fail(QStringLiteral("helper_bootstrap_dependency_missing"));

    const SessionSnapshot permittedSnapshot = bootstrap.snapshot();
    QByteArray probeSecret = bootstrap.takeProbeSecret();
    const WipeOnExit wipeProbeSecret{probeSecret};
    if (probeSecret.size() != HelperSessionIdentity::capabilityRandomBytes) {
        return fail(QStringLiteral("bootstrap_secret_invalid"));
    }
    auto lease = HostSessionLease::acquire(trustedDirectoryFd);
    if (!lease.acquired() || !lease.descriptorHasCloseOnExec())
        return fail(QStringLiteral("host_session_lease_unavailable"));

    auto identity = HelperSessionIdentity::create();
    if (!identity)
        return fail(QStringLiteral("helper_identity_unavailable"));
    std::unique_ptr<State> state;
    try {
        state = std::make_unique<State>(std::move(lease), bootstrapPeer, permittedSnapshot);
        state->operations = operationsFactory(state->lease, state->permittedSnapshot, probeSecret);
    } catch (...) {
        return fail(QStringLiteral("helper_operations_creation_failed"));
    }
    if (!state->operations)
        return fail(QStringLiteral("helper_operations_unavailable"));

    QByteArray clientCapability = std::move(*identity).takeCapability();
    if (clientCapability.size() != HelperSessionIdentity::capabilityRandomBytes) {
        wipe(clientCapability);
        return fail(QStringLiteral("helper_capability_unavailable"));
    }
    QByteArray dispatcherCapability;
    try {
        state->controlCapability = secureClone(clientCapability);
        state->clientCapability = secureClone(clientCapability);
        dispatcherCapability = secureClone(state->controlCapability);
        state->dispatcher = std::make_unique<HelperDispatcher>(
            *state->operations, state->permittedSnapshot, state->trustedPeer,
            std::move(dispatcherCapability), nullptr, std::move(monotonicClock));
        state->watchdog = std::make_unique<HelperWatchdog>(*state->dispatcher);
    } catch (...) {
        wipe(dispatcherCapability);
        wipe(clientCapability);
        return fail(QStringLiteral("helper_dispatcher_creation_failed"));
    }
    wipe(clientCapability);
    if (!state->dispatcher->ready())
        return fail(QStringLiteral("helper_dispatcher_not_ready"));
    return std::unique_ptr<LeasedHelperHost>(new LeasedHelperHost(std::move(state)));
}

LeasedHelperHost::LeasedHelperHost(std::unique_ptr<State> state) : state_(std::move(state)) {}
LeasedHelperHost::~LeasedHelperHost() {
    if (!state_)
        return;
    if (state_->onOwnerThread()) {
        state_.reset();
        return;
    }
    auto *deferredState = state_.release();
    if (deferredState->thread()->isRunning()) {
        deferredState->deleteLater();
        return;
    }
    qCritical("LeasedHelperHost retained until process exit after owner thread stopped");
}

bool LeasedHelperHost::start(QString *error) {
    if (error)
        error->clear();
    if (!state_ || !state_->onOwnerThread()) {
        if (error)
            *error = QStringLiteral("helper_owner_thread_required");
        return false;
    }
    if (state_->startAttempted || !state_->lease.acquired() || !state_->dispatcher->ready()) {
        if (error)
            *error = QStringLiteral("helper_start_unavailable");
        return false;
    }
    state_->startAttempted = true;
    if (state_->readiness && !state_->readiness->isCurrent()) {
        if (error)
            *error = QStringLiteral("transparent_proxy_not_current");
        return false;
    }
    const auto nowMs = state_->dispatcher->trustedMonotonicNowMs();
    if (!nowMs) {
        if (error)
            *error = QStringLiteral("trusted_clock_unavailable");
        return false;
    }
    if (state_->readiness && !state_->readiness->isCurrent()) {
        if (error)
            *error = QStringLiteral("transparent_proxy_not_current");
        return false;
    }
    HelperCommand command;
    command.type = HelperCommand::Type::Start;
    command.capability = state_->controlCapability;
    command.anchor = state_->permittedSnapshot.anchor();
    command.snapshot = state_->permittedSnapshot;
    command.nowMs = *nowMs;
    state_->started = state_->dispatcher->dispatch(state_->trustedPeer, command);
    if (!state_->started && error)
        *error = QStringLiteral("helper_session_start_failed");
    return state_->started;
}

bool LeasedHelperHost::stop(QString *error) {
    if (error)
        error->clear();
    if (!state_ || !state_->onOwnerThread()) {
        if (error)
            *error = QStringLiteral("helper_owner_thread_required");
        return false;
    }
    if (state_->dispatcher->state() == NetworkSession::State::Idle) {
        wipe(state_->controlCapability);
        wipe(state_->clientCapability);
        return true;
    }
    if (!state_->lease.acquired() || state_->controlCapability.isEmpty()) {
        if (error)
            *error = QStringLiteral("helper_cleanup_unavailable");
        return false;
    }
    const auto nowMs = state_->dispatcher->trustedMonotonicNowMs();
    if (!nowMs) {
        if (error)
            *error = QStringLiteral("trusted_clock_unavailable");
        return false;
    }
    HelperCommand command;
    command.type = HelperCommand::Type::Stop;
    command.capability = state_->controlCapability;
    command.anchor = state_->permittedSnapshot.anchor();
    command.nowMs = *nowMs;
    const bool stopped = state_->dispatcher->dispatch(state_->trustedPeer, command);
    if (!stopped && error)
        *error = QStringLiteral("helper_cleanup_pending");
    if (state_->dispatcher->state() == NetworkSession::State::Idle) {
        wipe(state_->controlCapability);
        wipe(state_->clientCapability);
    }
    return stopped;
}

bool LeasedHelperHost::dispatchOne(int connectedSocketFd, QString *error) {
    if (error)
        error->clear();
    if (!state_ || !state_->onOwnerThread() || !state_->startAttempted) {
        if (error)
            *error = QStringLiteral("helper_not_started_or_wrong_thread");
        return false;
    }
    if (state_->readiness && !state_->readiness->isCurrent()) {
        if (error)
            *error = QStringLiteral("transparent_proxy_not_current");
        (void)stop(nullptr);
        return false;
    }
    const bool accepted = dispatchOneLeasedUnixSocketCommand(connectedSocketFd, state_->lease,
                                                             *state_->dispatcher, error);
    if (state_->dispatcher->state() == NetworkSession::State::Idle) {
        wipe(state_->controlCapability);
        wipe(state_->clientCapability);
    }
    return accepted;
}

std::optional<HelperHostCredentials> LeasedHelperHost::takeCredentials() {
    if (!state_ || !state_->onOwnerThread() || !state_->started || state_->credentialsTaken ||
        state_->dispatcher->state() != NetworkSession::State::Active ||
        state_->clientCapability.size() != HelperSessionIdentity::capabilityRandomBytes)
        return std::nullopt;
    state_->credentialsTaken = true;
    return HelperHostCredentials(state_->permittedSnapshot.sessionId(),
                                 std::move(state_->clientCapability));
}

bool LeasedHelperHost::watchdogRunning() const {
    return state_ && state_->onOwnerThread() && state_->watchdog && state_->watchdog->isRunning();
}

NetworkSession::State LeasedHelperHost::state() const {
    return state_ && state_->onOwnerThread() ? state_->dispatcher->state()
                                             : NetworkSession::State::CleanupPending;
}

const SessionSnapshot &LeasedHelperHost::snapshot() const {
    Q_ASSERT(state_ && state_->onOwnerThread());
    return state_->permittedSnapshot;
}

} // namespace interceptor
