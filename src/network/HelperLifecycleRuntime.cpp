#define __STDC_WANT_LIB_EXT1__ 1
#include "HelperLifecycleRuntime.hpp"

#include "HelperSessionIdentity.hpp"

#include <QThread>

#include <string.h>
#include <string_view>

namespace interceptor {

static_assert(HelperSessionIdentity::capabilityRandomBytes == xpcSessionControlCapabilityBytes,
              "session-control capability length must match the helper capability size");

namespace {

constexpr int maximumPhaseDetailChars = 256;

void wipe(QByteArray &bytes) noexcept {
    if (!bytes.isEmpty())
        (void)memset_s(bytes.data(), static_cast<rsize_t>(bytes.size()), 0,
                       static_cast<rsize_t>(bytes.size()));
    bytes.clear();
}

std::string_view stateName(HelperLifecyclePhase phase) {
    switch (phase) {
    case HelperLifecyclePhase::NotInitialized:
        return xpcSessionControlStateUninitialized;
    case HelperLifecyclePhase::InitializationFailed:
        return xpcSessionControlStateInitFailed;
    case HelperLifecyclePhase::RecoveryPending:
        return xpcSessionControlStateRecoveryPending;
    case HelperLifecyclePhase::Ready:
        return xpcSessionControlStateReady;
    case HelperLifecyclePhase::Active:
        return xpcSessionControlStateActive;
    case HelperLifecyclePhase::CleanupPending:
        return xpcSessionControlStateCleanupPending;
    case HelperLifecyclePhase::Stopped:
        return xpcSessionControlStateStopped;
    }
    return xpcSessionControlStateUninitialized;
}

// Fixed, bounded, non-sensitive reason vocabulary (at most xpcSessionControlMaximumReasonBytes).
constexpr std::string_view reasonOwnerThreadRequired = "lifecycle_owner_thread_required";
constexpr std::string_view reasonNotInitialized = "lifecycle_not_initialized";
constexpr std::string_view reasonNotReady = "lifecycle_not_ready";
constexpr std::string_view reasonRecoveryPending = "lifecycle_recovery_pending";
constexpr std::string_view reasonStopped = "lifecycle_stopped";
constexpr std::string_view reasonDuplicateStart = "duplicate_start";
constexpr std::string_view reasonControlPeerMismatch = "control_peer_mismatch";
constexpr std::string_view reasonBindingMismatch = "session_binding_mismatch";
constexpr std::string_view reasonStartFailed = "session_start_failed";
constexpr std::string_view reasonStartUnverified = "session_start_unverified";
constexpr std::string_view reasonCredentialsUnavailable = "session_credentials_unavailable";
constexpr std::string_view reasonStartUnavailable = "session_start_unavailable";
constexpr std::string_view reasonHeartbeatRejected = "heartbeat_rejected";
constexpr std::string_view reasonCleanupPending = "cleanup_pending";
constexpr std::string_view reasonClockUnavailable = "clock_unavailable";
constexpr std::string_view reasonOperationUnsupported = "operation_unsupported";

bool samePeer(const VerifiedPeer &candidate, const VerifiedPeer &bound) {
    return bound.transportAuthenticated && candidate.transportAuthenticated &&
           candidate.uid == bound.uid && candidate.auditIdentity == bound.auditIdentity;
}

QByteArray capabilityCopy(const XpcControlRequest &request) {
    const auto &bytes = request.sessionCapability;
    return QByteArray(reinterpret_cast<const char *>(bytes.data()),
                      static_cast<qsizetype>(bytes.size()));
}

} // namespace

HelperLifecycleRuntime::HelperLifecycleRuntime(int trustedDirectoryFd, Seams &&seams)
    : directoryFd_(trustedDirectoryFd), seams_(std::move(seams)),
      ownerThreadId_(QThread::currentThreadId()) {}

HelperLifecycleRuntime::~HelperLifecycleRuntime() {
    // LeasedHelperHost defers its own QObject state to its owner thread or retains it until
    // process exit, so resetting from any thread keeps teardown safe.
    host_.reset();
}

std::unique_ptr<HelperLifecycleRuntime>
HelperLifecycleRuntime::create(int trustedDirectoryFd, Seams seams, QString *error) {
    const auto fail = [error](const QString &reason) -> std::unique_ptr<HelperLifecycleRuntime> {
        if (error)
            *error = reason;
        return {};
    };
    if (error)
        error->clear();
    if (trustedDirectoryFd < 0)
        return fail(QStringLiteral("trusted_directory_descriptor_required"));
    if (!seams.handoffReceiver || !seams.journalRecovery || !seams.listenerReadiness ||
        !seams.operationsFactory || !seams.monotonicClock)
        return fail(QStringLiteral("lifecycle_seams_required"));
    return std::unique_ptr<HelperLifecycleRuntime>(
        new HelperLifecycleRuntime(trustedDirectoryFd, std::move(seams)));
}

bool HelperLifecycleRuntime::initialize(QString *error) {
    const auto fail = [error](const QString &reason) {
        if (error)
            *error = reason;
        return false;
    };
    if (error)
        error->clear();
    if (QThread::currentThreadId() != ownerThreadId_)
        return fail(QStringLiteral("lifecycle_owner_thread_required"));
    if (phase_ != HelperLifecyclePhase::NotInitialized)
        return fail(QStringLiteral("lifecycle_already_initialized"));

    // Step 1: authenticate the handoff on the trusted rendezvous seam.
    QString handoffError;
    auto handoff = seams_.handoffReceiver(&handoffError);
    if (!handoff) {
        phase_ = HelperLifecyclePhase::InitializationFailed;
        phaseDetail_ = handoffError.left(maximumPhaseDetailChars);
        return fail(handoffError.isEmpty() ? QStringLiteral("authenticated_handoff_unavailable")
                                           : handoffError);
    }

    // Steps 2 and 3a: validate and freeze the snapshot, acquire the exclusive host lease, and
    // compose the journaled operations. LeasedHelperHost::createFromBootstrap enforces that
    // order and rejects an invalid peer or malformed one-time secret before any operation runs.
    QString hostError;
    auto host = LeasedHelperHost::createFromBootstrap(directoryFd_, std::move(handoff->handoff),
                                                      handoff->peer, seams_.operationsFactory,
                                                      seams_.monotonicClock, &hostError);
    if (!host) {
        phase_ = HelperLifecyclePhase::InitializationFailed;
        phaseDetail_ = hostError.left(maximumPhaseDetailChars);
        return fail(hostError.isEmpty() ? QStringLiteral("helper_host_unavailable") : hostError);
    }
    host_ = std::move(host);
    controlPeer_ = handoff->peer;

    // Step 3b: recover the durable journals. Pending obligations block readiness fail-closed;
    // Start is rejected and the obligations stay retained by the journal owners.
    QString recoveryDetail;
    if (!seams_.journalRecovery(&recoveryDetail)) {
        phase_ = HelperLifecyclePhase::RecoveryPending;
        phaseDetail_ = recoveryDetail.left(maximumPhaseDetailChars);
        return fail(QStringLiteral("journal_recovery_pending"));
    }

    // Step 4: confirm listener readiness with a fresh proof. Historical snapshot readiness is
    // never authority; without this confirmation the runtime does not expose a control endpoint.
    QString readinessDetail;
    if (!seams_.listenerReadiness(&readinessDetail)) {
        phase_ = HelperLifecyclePhase::InitializationFailed;
        phaseDetail_ = readinessDetail.left(maximumPhaseDetailChars);
        return fail(QStringLiteral("listener_readiness_unconfirmed"));
    }

    // Step 5: expose the control endpoint for exactly one authenticated Start.
    phase_ = HelperLifecyclePhase::Ready;
    return true;
}

HelperLifecyclePhase HelperLifecycleRuntime::phase() const {
    Q_ASSERT(QThread::currentThreadId() == ownerThreadId_);
    return phase_;
}

const QString &HelperLifecycleRuntime::phaseDetail() const {
    Q_ASSERT(QThread::currentThreadId() == ownerThreadId_);
    return phaseDetail_;
}

NetworkSession::State HelperLifecycleRuntime::sessionState() const {
    Q_ASSERT(QThread::currentThreadId() == ownerThreadId_);
    return host_ ? host_->state() : NetworkSession::State::CleanupPending;
}

const QString &HelperLifecycleRuntime::sessionId() const {
    Q_ASSERT(QThread::currentThreadId() == ownerThreadId_);
    return sessionId_;
}

const SessionSnapshot *HelperLifecycleRuntime::snapshot() const {
    Q_ASSERT(QThread::currentThreadId() == ownerThreadId_);
    return host_ ? &host_->snapshot() : nullptr;
}

bool HelperLifecycleRuntime::watchdogRunning() const {
    Q_ASSERT(QThread::currentThreadId() == ownerThreadId_);
    return host_ && host_->watchdogRunning();
}

std::optional<qint64> HelperLifecycleRuntime::trustedNowMs() const {
    try {
        const qint64 nowMs = seams_.monotonicClock();
        if (nowMs < 0)
            return std::nullopt;
        return nowMs;
    } catch (...) {
        return std::nullopt;
    }
}

XpcSessionControlReply
HelperLifecycleRuntime::handleControlRequest(const VerifiedPeer &transportPeer,
                                             const XpcControlRequest &request) {
    XpcSessionControlReply reply;
    reply.state.assign(xpcSessionControlStateUninitialized);
    if (QThread::currentThreadId() != ownerThreadId_) {
        reply.reason.assign(reasonOwnerThreadRequired);
        return reply;
    }
    // Reconcile the phase with the verified session state: the owner-loop watchdog may have
    // stopped the session since the last command. There is no cross-thread writer, and the
    // Starting/Cleaning states are transient inside synchronous dispatch, so this read is safe.
    if (host_ && (phase_ == HelperLifecyclePhase::Active ||
                  phase_ == HelperLifecyclePhase::CleanupPending)) {
        const auto sessionState = host_->state();
        if (sessionState == NetworkSession::State::Idle)
            phase_ = HelperLifecyclePhase::Stopped;
        else if (sessionState == NetworkSession::State::CleanupPending)
            phase_ = HelperLifecyclePhase::CleanupPending;
    }
    reply.state.assign(stateName(phase_));
    switch (request.operation) {
    case XpcControlOperation::Start:
        return startSession(transportPeer);
    case XpcControlOperation::Heartbeat:
    case XpcControlOperation::Stop:
        return dispatchSessionCommand(transportPeer, request);
    case XpcControlOperation::Probe:
    case XpcControlOperation::Status:
    case XpcControlOperation::Invalid:
        // Read-only probe/status is answered by the read-only adapter on the installed endpoint;
        // this runtime never answers it and never interprets an unparseable request.
        reply.reason.assign(reasonOperationUnsupported);
        return reply;
    }
    reply.reason.assign(reasonOperationUnsupported);
    return reply;
}

XpcSessionControlReply HelperLifecycleRuntime::startSession(const VerifiedPeer &transportPeer) {
    XpcSessionControlReply reply;
    reply.state.assign(stateName(phase_));
    const auto reject = [&reply](std::string_view reason) {
        reply.reason.assign(reason);
        return reply;
    };
    switch (phase_) {
    case HelperLifecyclePhase::NotInitialized:
        // No control peer is bound until a host is adopted; report the lifecycle reason.
        return reject(reasonNotInitialized);
    case HelperLifecyclePhase::InitializationFailed:
        return reject(reasonNotReady);
    case HelperLifecyclePhase::RecoveryPending:
        return reject(reasonRecoveryPending);
    case HelperLifecyclePhase::Stopped:
        return reject(reasonStopped);
    case HelperLifecyclePhase::Active:
    case HelperLifecyclePhase::CleanupPending:
        // One session per process: a duplicate Start never re-sends the capability.
        return reject(reasonDuplicateStart);
    case HelperLifecyclePhase::Ready:
        break;
    }

    // The peer that authenticated the bootstrap handoff is the only control peer of the
    // session this Start would create.
    if (!samePeer(transportPeer, controlPeer_))
        return reject(reasonControlPeerMismatch);
    if (!host_ || host_->state() != NetworkSession::State::Idle)
        return reject(reasonStartUnavailable);

    const auto nowMs = trustedNowMs();
    if (!nowMs || *nowMs < 0)
        return reject(reasonClockUnavailable);

    // Step 6: start the synthetic/injected operations. Any failure retains its cleanup
    // obligation and reports the real state.
    QString startError;
    if (!host_->start(&startError)) {
        phaseDetail_ = startError.left(maximumPhaseDetailChars);
        if (host_->state() == NetworkSession::State::CleanupPending) {
            phase_ = HelperLifecyclePhase::CleanupPending;
            reply.state.assign(stateName(phase_));
        }
        return reject(reasonStartFailed);
    }

    // Verified Active only: the owned operations completed and the dispatcher confirms the
    // session state. There is no Active claim before this point.
    if (host_->state() != NetworkSession::State::Active) {
        if (host_->state() == NetworkSession::State::CleanupPending) {
            phase_ = HelperLifecyclePhase::CleanupPending;
            reply.state.assign(stateName(phase_));
        }
        return reject(reasonStartUnverified);
    }
    phase_ = HelperLifecyclePhase::Active;
    reply.state.assign(stateName(phase_));

    // Step 7: release the capability. Delivery happens exactly once and only after verified
    // Active; the runtime never retains a delivered capability copy.
    auto credentials = host_->takeCredentials();
    if (!credentials)
        return reject(reasonCredentialsUnavailable);
    sessionId_ = credentials->sessionId();
    reply.ok = true;
    reply.sessionId = sessionId_.toStdString();
    reply.sessionCapability.assign(credentials->capability().constData(),
                                   credentials->capability().constData() +
                                       credentials->capability().size());
    return reply;
}

XpcSessionControlReply
HelperLifecycleRuntime::dispatchSessionCommand(const VerifiedPeer &transportPeer,
                                               const XpcControlRequest &request) {
    XpcSessionControlReply reply;
    reply.state.assign(stateName(phase_));
    const auto reject = [&reply](std::string_view reason) {
        reply.reason.assign(reason);
        return reply;
    };
    switch (phase_) {
    case HelperLifecyclePhase::NotInitialized:
        return reject(reasonNotInitialized);
    case HelperLifecyclePhase::InitializationFailed:
        return reject(reasonNotReady);
    case HelperLifecyclePhase::RecoveryPending:
        return reject(reasonRecoveryPending);
    case HelperLifecyclePhase::Ready:
    case HelperLifecyclePhase::Stopped:
        // No session is bound; a session id alone is never authorization, and a session that
        // stopped cleanly has its capability revoked by the host.
        return reject(reasonBindingMismatch);
    case HelperLifecyclePhase::Active:
    case HelperLifecyclePhase::CleanupPending:
        break;
    }
    if (!samePeer(transportPeer, controlPeer_))
        return reject(reasonControlPeerMismatch);
    if (!host_ || QString::fromStdString(request.sessionId) != sessionId_)
        return reject(reasonBindingMismatch);

    const auto nowMs = trustedNowMs();
    if (!nowMs || *nowMs < 0)
        return reject(reasonClockUnavailable);

    HelperCommand command;
    command.type = request.operation == XpcControlOperation::Heartbeat
                       ? HelperCommand::Type::Heartbeat
                       : HelperCommand::Type::Stop;
    command.capability = capabilityCopy(request);
    command.anchor = host_->snapshot().anchor();
    command.nowMs = *nowMs;
    const bool accepted = host_->dispatchControlCommand(transportPeer, command);
    wipe(command.capability);

    // Reflect the verified post-dispatch state. Cleanup obligations stay retryable while
    // cleanup is pending: the endpoint keeps accepting bound Stop retries.
    const auto sessionState = host_->state();
    if (sessionState == NetworkSession::State::Idle)
        phase_ = HelperLifecyclePhase::Stopped;
    else if (sessionState == NetworkSession::State::CleanupPending)
        phase_ = HelperLifecyclePhase::CleanupPending;
    else if (sessionState == NetworkSession::State::Active)
        phase_ = HelperLifecyclePhase::Active;
    reply.state.assign(stateName(phase_));

    if (request.operation == XpcControlOperation::Stop) {
        if (sessionState == NetworkSession::State::Idle) {
            reply.ok = true;
        } else {
            reply.reason.assign(reasonCleanupPending);
        }
        return reply;
    }
    if (accepted && sessionState == NetworkSession::State::Active) {
        reply.ok = true;
        reply.sessionId = sessionId_.toStdString();
        return reply;
    }
    reply.reason.assign(reasonHeartbeatRejected);
    return reply;
}

} // namespace interceptor
