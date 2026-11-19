#pragma once

#include "LeasedHelperHost.hpp"
#include "TrustedBootstrapHandoff.hpp"
#include "XpcControlRequestGate.hpp"
#include "XpcSessionControlReply.hpp"

#include <QString>

#include <functional>
#include <memory>
#include <optional>

namespace interceptor {

// Authenticated result of the bootstrap rendezvous seam: the validated immutable snapshot with
// its one-time probe secret, plus the kernel-verified peer identity from the same connection.
struct HelperLifecycleHandoff final {
    TrustedBootstrapHandoff handoff;
    VerifiedPeer peer;
};

// Lifecycle phases of one helper process. A process owns at most one session: after a verified
// stop the capability is spent and the runtime never returns to Ready.
enum class HelperLifecyclePhase {
    NotInitialized,
    InitializationFailed,
    RecoveryPending,
    Ready,
    Active,
    CleanupPending,
    Stopped,
};

// Owner-thread lifecycle runtime for one installed-service-shaped helper process. This class is
// the offline fixture for backlog package B: no production entrypoint constructs it, and the
// installed --mach-service path is unchanged. It composes the reviewed pieces (LeasedHelperHost,
// HelperDispatcher, NetworkSession, HelperWatchdog) behind injectable seams in the exact
// production startup order:
//
//   initialize(): authenticate handoff -> validate/freeze snapshot -> acquire lease and recover
//                 journals -> confirm listener readiness -> expose the control endpoint,
//   then per session: authenticated Start -> verify owned operations completed -> release the
//   one-time session capability -> Heartbeat/Stop on the same owner loop.
//
// A failed step reports the real state and retains any cleanup obligation; the session is only
// reported Active after the owned operations complete and the dispatcher verifies the session
// state; Stop and watchdog recovery remain available while cleanup is pending. Every method must
// run on the thread that created the object. The trusted state-directory descriptor is borrowed
// and must stay valid through initialize(); the handoff socket (when one exists) is owned and
// closed by the injected handoff receiver.
class HelperLifecycleRuntime final {
  public:
    using MonotonicClock = LeasedHelperHost::MonotonicClock;
    using BootstrapOperationsFactory = LeasedHelperHost::BootstrapOperationsFactory;
    // Step 1 seam: perform and authenticate the trusted rendezvous, then hand over the validated
    // snapshot and peer. Production wiring is receiveTrustedBootstrapHandoff over the connected
    // Unix rendezvous; tests inject a fake.
    using HandoffReceiver = std::function<std::optional<HelperLifecycleHandoff>(QString *)>;
    // Step 3b seam: recover the durable PF journals against the leased directory. Returning
    // false means unresolved obligations are pending and blocks readiness fail-closed.
    using JournalRecoveryStep = std::function<bool(QString *)>;
    // Step 4 seam: fresh listener-readiness proof. The helper never trusts the snapshot's
    // historical readiness; tests inject a fake, production injects the live probe.
    using ListenerReadinessStep = std::function<bool(QString *)>;

    struct Seams {
        HandoffReceiver handoffReceiver;
        JournalRecoveryStep journalRecovery;
        ListenerReadinessStep listenerReadiness;
        BootstrapOperationsFactory operationsFactory;
        MonotonicClock monotonicClock;
    };

    static std::unique_ptr<HelperLifecycleRuntime> create(int trustedDirectoryFd, Seams seams,
                                                          QString *error = nullptr);

    HelperLifecycleRuntime(const HelperLifecycleRuntime &) = delete;
    HelperLifecycleRuntime &operator=(const HelperLifecycleRuntime &) = delete;
    HelperLifecycleRuntime(HelperLifecycleRuntime &&) = delete;
    HelperLifecycleRuntime &operator=(HelperLifecycleRuntime &&) = delete;
    ~HelperLifecycleRuntime();

    bool initialize(QString *error = nullptr);

    HelperLifecyclePhase phase() const;
    // Bounded (<= 256 characters), non-sensitive detail of the last failed/reported step.
    const QString &phaseDetail() const;
    // Fail-closed like LeasedHelperHost::state(): CleanupPending when no host is owned.
    NetworkSession::State sessionState() const;
    // The session id is not secret; it is authorization only together with the capability.
    const QString &sessionId() const;
    // The frozen immutable snapshot, or nullptr before a host is owned.
    const SessionSnapshot *snapshot() const;
    bool watchdogRunning() const;

    // Maps one gate-parsed, authenticated control request to a bounded reply. Capability bytes
    // in the reply are owned by the caller and must be wiped after use. Probe and status are
    // answered by the read-only adapter, never here.
    XpcSessionControlReply handleControlRequest(const VerifiedPeer &transportPeer,
                                                const XpcControlRequest &request);

  private:
    explicit HelperLifecycleRuntime(int trustedDirectoryFd, Seams &&seams);

    XpcSessionControlReply startSession(const VerifiedPeer &transportPeer);
    XpcSessionControlReply dispatchSessionCommand(const VerifiedPeer &transportPeer,
                                                  const XpcControlRequest &request);
    std::optional<qint64> trustedNowMs() const;

    int directoryFd_ = -1;
    Seams seams_;
    std::unique_ptr<LeasedHelperHost> host_;
    HelperLifecyclePhase phase_ = HelperLifecyclePhase::NotInitialized;
    VerifiedPeer controlPeer_;
    QString phaseDetail_;
    QString sessionId_;
    Qt::HANDLE ownerThreadId_ = nullptr;
};

} // namespace interceptor
