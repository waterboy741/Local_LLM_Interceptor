#pragma once

#include "HelperPreMutationGate.hpp"
#include "network/ArpNeighborAdapter.hpp"
#include "network/ArpRedirectRefresher.hpp"
#include "network/LeasedHelperHost.hpp"
#include "network/NetworkSession.hpp"
#include "network/PfAnchorCleanupVerifier.hpp"
#include "network/PfAnchorOperations.hpp"
#include "network/PfAnchorRecoveryCoordinator.hpp"
#include "network/PfAnchorRecoverySystemOperations.hpp"
#include "network/PfDiagnostics.hpp"
#include "network/PfEnableReferenceJournal.hpp"
#include "network/PfEnableReferenceOwner.hpp"
#include "network/PfEnableReferenceQProcessRunner.hpp"
#include "network/PfEnableReferenceRecoveryCoordinator.hpp"
#include "network/PfRecoveryJournal.hpp"
#include "network/PosixSpawnTypedCommandProcess.hpp"

#include <functional>
#include <memory>
#include <optional>

namespace interceptor {

// Sysctl-backed read/compare-and-write seam for the two session-owned kernel settings. The
// production implementation uses sysctlbyname on the fixed names below; injected fakes keep the
// scoped session offline and deterministic.
class NetworkSettingIo {
  public:
    virtual ~NetworkSettingIo() = default;
    virtual std::optional<int> read(const QString &name) = 0;
    virtual bool write(const QString &name, int value) = 0;

    static QString name(NetworkSetting setting);
};

class SysctlNetworkSettingIo final : public NetworkSettingIo {
  public:
    std::optional<int> read(const QString &name) override;
    bool write(const QString &name, int value) override;
};

// Dependencies for one scoped session execution. Every reference is borrowed and must outlive
// the operations object; only the ARP refresh timer is created per session through the injected
// factory. No production entrypoint wires these adapters; tests drive them with fakes.
struct ScopedSessionDependencies {
    HelperPreMutationDependencies preMutation;
    PfCommandRunner &pfQuery;
    NetworkSettingIo &settings;
    ArpPacketIo &arpPacketIo;
    std::function<std::unique_ptr<ArpRefreshTimer>()> arpRefreshTimerFactory;
    std::function<int()> effectiveUid;
    int arpRefreshIntervalMs = ArpRedirectRefresher::defaultIntervalMs;
    int pfQueryTimeoutMs = PfDiagnostics::defaultTimeoutMs;
};

// Real anchor-install authorization over read-only typed PF queries: effective root, PF
// enabled, both main-ruleset attachment references active, lease token match, and (for
// installs) the exact session anchor not already loaded. The injected PfCommandRunner keeps it
// fake-drivable.
class ScopedPfAnchorAuthorization final : public PfAnchorAuthorization {
  public:
    ScopedPfAnchorAuthorization(PfCommandRunner &queryRunner, const QString &sessionLeaseToken,
                                std::function<int()> effectiveUid, int queryTimeoutMs);

    bool effectiveUserIsRoot() override;
    bool pfEnabled() override;
    bool verifySessionLease(const SessionSnapshot &snapshot, const QString &leaseToken) override;
    bool verifyActiveAttachment(const SessionSnapshot &snapshot) override;
    bool verifyAnchorOwnership(const SessionSnapshot &snapshot, const QString &leaseToken,
                               PfAnchorOperation operation) override;

  private:
    PfCommandRunner &queryRunner_;
    const int queryTimeoutMs_;
    const QString &sessionLeaseToken_;
    std::function<int()> effectiveUid_;
};

// Delegate-level implementation used by the journaled decorator below: it runs nothing on its
// own before the outer fresh pre-mutation gate passes, and its exclusive session lease token is
// issued only after that gate. beginArp verifies active evaluation (anchor loaded, both owned
// rule types present, both attachments referenced) before the redirect refresh loop may send
// any frame. The one-time probe secret copy is wiped at destruction.
class ScopedSessionDelegate final : public SystemOperations {
  public:
    ScopedSessionDelegate(HelperPreMutationDependencies preMutation, PfCommandRunner &pfQuery,
                          NetworkSettingIo &settings, ArpRedirectRefresher &arpRefresher,
                          ArpNeighborAdapter &neighborAdapter, PfRecoveryJournal &anchorJournal,
                          int pfQueryTimeoutMs, QByteArray probeSecret);
    ~ScopedSessionDelegate() override;

    ScopedSessionDelegate(const ScopedSessionDelegate &) = delete;
    ScopedSessionDelegate &operator=(const ScopedSessionDelegate &) = delete;

    std::optional<QString> acquireSessionLease(const SessionSnapshot &snapshot) override;
    bool releaseSessionLease(const QString &token) override;
    std::optional<int> readSetting(NetworkSetting setting) override;
    SettingChange compareAndSetSetting(NetworkSetting setting, int expected, int desired) override;
    // The four journaled PF-mutation entry points are implemented by the decorating
    // PfAnchorRecoverySystemOperations through the anchor and enable-reference coordinators;
    // this delegate never runs them, so it fails them closed instead of guessing.
    std::optional<QString> acquirePfReference() override;
    bool releasePfReference(const QString &token) override;
    bool installAnchor(const SessionSnapshot &snapshot) override;
    bool removeAnchor(const SessionSnapshot &snapshot) override;
    bool clearOwnedState(const SessionSnapshot &snapshot) override;
    bool beginArp(const SessionSnapshot &snapshot) override;
    bool endArp(const SessionSnapshot &snapshot) override;
    bool restoreNeighbors(const SessionSnapshot &snapshot) override;
    bool interfaceAvailable(const SessionSnapshot &snapshot) override;
    bool retainRecovery(const SessionSnapshot &snapshot, const OwnershipJournal &journal) override;

    const QString &leaseToken() const { return leaseToken_; }
    // Runs the fresh, uncached pre-mutation gate using this delegate's one probe secret copy.
    bool freshPreMutationGateReady(const SessionSnapshot &snapshot);
    static bool validProbeSecretSize(const QByteArray &secret) {
        return secret.size() == helperProbeSecretBytes;
    }

  private:
    static constexpr int helperProbeSecretBytes = 32;
    HelperPreMutationDependencies preMutation_;
    PfCommandRunner &pfQuery_;
    NetworkSettingIo &settings_;
    ArpRedirectRefresher &arpRefresher_;
    ArpNeighborAdapter &neighborAdapter_;
    PfRecoveryJournal &anchorJournal_;
    const int pfQueryTimeoutMs_;
    QByteArray probeSecret_;
    QString leaseToken_;
};

// One real scoped session execution: it owns the spawn-backed typed command runners, both
// durable journals, the two PF enable-reference owners (active and startup recovery, one shared
// journal), the anchor recovery coordinator, the ARP redirect refresher, and the delegate
// above. The base class remains the single journaled command path; this class only adds the
// fresh gate before it and owns every collaborator so nothing dangles. Teardown stays exactly
// the NetworkSession reverse order; uncertain steps retain journal obligations.
class ScopedSessionSystemOperations final : public PfAnchorRecoverySystemOperations {
  public:
    static std::unique_ptr<ScopedSessionSystemOperations>
    create(const HostSessionLease &lease, const QByteArray &probeSecret, int trustedDirectoryFd,
           const ScopedSessionDependencies &dependencies, QString *error = nullptr);

    ~ScopedSessionSystemOperations() override;

    ScopedSessionSystemOperations(const ScopedSessionSystemOperations &) = delete;
    ScopedSessionSystemOperations &operator=(const ScopedSessionSystemOperations &) = delete;

    // Gate first: the fresh pre-mutation gate runs before the base class's journaled
    // recovery/lease/capture/install path, so no session mutation (including pending-reference
    // reconciliation) can run before the gate passes.
    std::optional<QString> acquireSessionLease(const SessionSnapshot &snapshot) override;

  private:
    ScopedSessionSystemOperations(const HostSessionLease &lease, const QByteArray &probeSecret,
                                  const ScopedSessionDependencies &dependencies,
                                  PfRecoveryJournal anchorJournal,
                                  PfEnableReferenceJournal enableReferenceJournal,
                                  std::unique_ptr<ArpRefreshTimer> arpRefreshTimer);

    ScopedSessionDependencies dependencies_;
    PfRecoveryJournal anchorJournal_;
    PfEnableReferenceJournal enableReferenceJournal_;
    PfAnchorPosixSpawnChildFactory anchorChildFactory_;
    QProcessPfAnchorCommandRunner anchorCommandRunner_;
    PfEnableReferencePosixSpawnChildFactory enableChildFactory_;
    QProcessPfEnableReferenceCommandRunner enableCommandRunner_;
    PfEnableReferenceOwner enableOwner_;
    PfEnableReferenceOwner startupOwner_;
    PfctlPosixSpawnEnableTokenVerifier enableTokenVerifier_;
    ArpNeighborAdapter neighborAdapter_;
    ArpRedirectRefresher arpRefresher_;
    ScopedSessionDelegate delegate_;
    ScopedPfAnchorAuthorization anchorAuthorization_;
    PfAnchorOperations anchorOperations_;
    PfCommandAnchorCleanupVerifier anchorCleanupVerifier_;
    PfAnchorRecoveryCoordinator anchorRecoveryCoordinator_;
    PfEnableReferenceRecoveryCoordinator enableRecoveryCoordinator_;
    PfEnableReferenceRecoveryCoordinator startupRecoveryCoordinator_;
};

// Builds the operations-factory seam accepted by LeasedHelperHost::createFromBootstrap /
// HelperLifecycleRuntime. The returned factory opens the durable journals from the trusted
// directory for each session, constructs the scoped execution, and returns it as the
// PfAnchorRecoverySystemOperations the host dispatches on. A failed construction yields a null
// operations object and the host fails closed. Returns a null factory when the dependencies are
// incomplete. No production entrypoint constructs this factory yet.
LeasedHelperHost::BootstrapOperationsFactory
scopedSessionOperationsFactory(int trustedDirectoryFd, ScopedSessionDependencies dependencies,
                               QString *warning = nullptr);

} // namespace interceptor
