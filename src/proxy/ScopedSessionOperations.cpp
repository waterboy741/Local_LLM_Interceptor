#define __STDC_WANT_LIB_EXT1__ 1
#include "ScopedSessionOperations.hpp"

#include <QDebug>

#include <sys/sysctl.h>
#include <unistd.h>

#include <string.h>

namespace interceptor {
namespace {

void wipe(QByteArray &bytes) noexcept {
    if (!bytes.isEmpty())
        (void)memset_s(bytes.data(), static_cast<rsize_t>(bytes.size()), 0,
                       static_cast<rsize_t>(bytes.size()));
    bytes.clear();
}

int defaultEffectiveUid() { return static_cast<int>(::geteuid()); }

} // namespace

QString NetworkSettingIo::name(NetworkSetting setting) {
    // Read-only sysctl observation verified against the target system (May 2026): the two
    // session-owned kernel settings are ip forwarding and ICMP redirect emission.
    return setting == NetworkSetting::Forwarding ? QStringLiteral("net.inet.ip.forwarding")
                                                 : QStringLiteral("net.inet.ip.redirect");
}

std::optional<int> SysctlNetworkSettingIo::read(const QString &name) {
    int value = 0;
    size_t size = sizeof(value);
    if (::sysctlbyname(name.toUtf8().constData(), &value, &size, nullptr, 0) != 0 ||
        size != sizeof(value))
        return std::nullopt;
    return value;
}

bool SysctlNetworkSettingIo::write(const QString &name, int value) {
    int desired = value;
    return ::sysctlbyname(name.toUtf8().constData(), nullptr, nullptr, &desired, sizeof(desired)) ==
           0;
}

ScopedPfAnchorAuthorization::ScopedPfAnchorAuthorization(PfCommandRunner &queryRunner,
                                                         const QString &sessionLeaseToken,
                                                         std::function<int()> effectiveUid,
                                                         int queryTimeoutMs)
    : queryRunner_(queryRunner), queryTimeoutMs_(queryTimeoutMs),
      sessionLeaseToken_(sessionLeaseToken),
      effectiveUid_(effectiveUid ? std::move(effectiveUid) : defaultEffectiveUid) {}

bool ScopedPfAnchorAuthorization::effectiveUserIsRoot() {
    return effectiveUid_ ? effectiveUid_() == 0 : false;
}

bool ScopedPfAnchorAuthorization::pfEnabled() {
    const auto readiness = PfDiagnostics::collectPreInstallReadiness(queryRunner_, queryTimeoutMs_);
    return readiness.pfEnabledKnown && readiness.pfEnabled;
}

bool ScopedPfAnchorAuthorization::verifySessionLease(const SessionSnapshot &snapshot,
                                                     const QString &leaseToken) {
    (void)snapshot;
    return !sessionLeaseToken_.isEmpty() && leaseToken == sessionLeaseToken_;
}

bool ScopedPfAnchorAuthorization::verifyActiveAttachment(const SessionSnapshot &snapshot) {
    (void)snapshot;
    const auto readiness = PfDiagnostics::collectPreInstallReadiness(queryRunner_, queryTimeoutMs_);
    return readiness.filterAttachmentKnown && readiness.filterAttachmentReferenced &&
           readiness.translationAttachmentKnown && readiness.translationAttachmentReferenced;
}

bool ScopedPfAnchorAuthorization::verifyAnchorOwnership(const SessionSnapshot &snapshot,
                                                        const QString &leaseToken,
                                                        PfAnchorOperation operation) {
    if (!verifySessionLease(snapshot, leaseToken))
        return false;
    if (snapshot.anchor() != QStringLiteral("llm_interceptor/") + snapshot.sessionId())
        return false;
    if (operation != PfAnchorOperation::Install)
        return true; // removal of exactly this session's anchor stays idempotent and journaled
    // Install refuses to clobber an already-loaded anchor; a leftover anchor from a prior
    // session must be reconciled through the journals before a new one is written.
    const auto diagnostics = PfDiagnostics::collect(snapshot.config(), snapshot.sessionId(),
                                                    queryRunner_, queryTimeoutMs_);
    return diagnostics.complete && diagnostics.sessionAnchorKnown &&
           !diagnostics.sessionAnchorLoaded;
}

ScopedSessionDelegate::ScopedSessionDelegate(HelperPreMutationDependencies preMutation,
                                             PfCommandRunner &pfQuery, NetworkSettingIo &settings,
                                             ArpRedirectRefresher &arpRefresher,
                                             ArpNeighborAdapter &neighborAdapter,
                                             PfRecoveryJournal &anchorJournal, int pfQueryTimeoutMs,
                                             QByteArray probeSecret)
    : preMutation_(preMutation), pfQuery_(pfQuery), settings_(settings),
      arpRefresher_(arpRefresher), neighborAdapter_(neighborAdapter), anchorJournal_(anchorJournal),
      pfQueryTimeoutMs_(pfQueryTimeoutMs), probeSecret_(std::move(probeSecret)) {}

ScopedSessionDelegate::~ScopedSessionDelegate() { wipe(probeSecret_); }

bool ScopedSessionDelegate::freshPreMutationGateReady(const SessionSnapshot &snapshot) {
    const auto gate = HelperPreMutationGate::verify(snapshot, probeSecret_, preMutation_);
    return gate.ready;
}

std::optional<QString> ScopedSessionDelegate::acquireSessionLease(const SessionSnapshot &snapshot) {
    // The fresh pre-mutation gate is run by the outer ScopedSessionSystemOperations before this
    // class's journaled path, so the token here is issued only after the gate passed.
    if (!leaseToken_.isEmpty())
        return std::nullopt;
    if (!snapshot.sessionId().isEmpty())
        leaseToken_ = QStringLiteral("host-lease:") + snapshot.sessionId();
    return leaseToken_.isEmpty() ? std::nullopt : std::optional<QString>(leaseToken_);
}

bool ScopedSessionDelegate::releaseSessionLease(const QString &token) {
    if (leaseToken_.isEmpty() || token != leaseToken_)
        return false;
    leaseToken_.clear();
    return true;
}

std::optional<int> ScopedSessionDelegate::readSetting(NetworkSetting setting) {
    return settings_.read(NetworkSettingIo::name(setting));
}

SettingChange ScopedSessionDelegate::compareAndSetSetting(NetworkSetting setting, int expected,
                                                          int desired) {
    const auto name = NetworkSettingIo::name(setting);
    const auto current = settings_.read(name);
    if (!current)
        return SettingChange::Failed;
    if (*current == desired)
        return SettingChange::Unchanged;
    if (*current != expected)
        return SettingChange::Conflict;
    return settings_.write(name, desired) ? SettingChange::Applied : SettingChange::Failed;
}

std::optional<QString> ScopedSessionDelegate::acquirePfReference() {
    // Journaled PF enable-reference capture belongs to the decorating base class.
    return std::nullopt;
}

bool ScopedSessionDelegate::releasePfReference(const QString &token) {
    (void)token;
    return false;
}

bool ScopedSessionDelegate::installAnchor(const SessionSnapshot &snapshot) {
    (void)snapshot;
    return false;
}

bool ScopedSessionDelegate::removeAnchor(const SessionSnapshot &snapshot) {
    (void)snapshot;
    return false;
}

bool ScopedSessionDelegate::clearOwnedState(const SessionSnapshot &snapshot) {
    // Owned state beyond the anchor, PF reference, and kernel settings is nothing in this
    // implementation; the anchor/PF journaled paths already ran at this point of cleanup.
    (void)snapshot;
    return true;
}

bool ScopedSessionDelegate::interfaceAvailable(const SessionSnapshot &snapshot) {
    (void)snapshot;
    return arpRefresher_.redirectHealthy();
}

bool ScopedSessionDelegate::beginArp(const SessionSnapshot &snapshot) {
    // Active-evaluation verification: only a loaded anchor with both owned rule types and both
    // main-ruleset attachment references may precede any redirected frame.
    const auto diagnostics = PfDiagnostics::collect(snapshot.config(), snapshot.sessionId(),
                                                    pfQuery_, pfQueryTimeoutMs_);
    if (!diagnostics.complete || !diagnostics.sessionAnchorKnown ||
        !diagnostics.sessionAnchorLoaded || diagnostics.sessionFilterRuleCount < 1 ||
        diagnostics.sessionTranslationRuleCount < 1 || !diagnostics.filterAttachmentKnown ||
        !diagnostics.filterAttachmentReferenced || !diagnostics.translationAttachmentKnown ||
        !diagnostics.translationAttachmentReferenced)
        return false;
    return arpRefresher_.start(snapshot);
}

bool ScopedSessionDelegate::endArp(const SessionSnapshot &snapshot) {
    (void)snapshot;
    return arpRefresher_.stop();
}

bool ScopedSessionDelegate::restoreNeighbors(const SessionSnapshot &snapshot) {
    return neighborAdapter_.sendRestoration(snapshot).success();
}

bool ScopedSessionDelegate::retainRecovery(const SessionSnapshot &snapshot,
                                           const OwnershipJournal &journal) {
    (void)journal;
    // Preserve the cleanup obligation durably for an explicit recovery path: never claim that a
    // crashed session's owned state was cleaned.
    return anchorJournal_.persistCleanupNeeded(snapshot.sessionId()) ==
           PfRecoveryJournalStatus::Persisted;
}

ScopedSessionSystemOperations::ScopedSessionSystemOperations(
    const HostSessionLease &lease, const QByteArray &probeSecret,
    const ScopedSessionDependencies &dependencies, PfRecoveryJournal anchorJournal,
    PfEnableReferenceJournal enableReferenceJournal,
    std::unique_ptr<ArpRefreshTimer> arpRefreshTimer)
    // The base class binds these references only; every object it names is owned below.
    : PfAnchorRecoverySystemOperations(delegate_, lease, anchorRecoveryCoordinator_,
                                       &enableRecoveryCoordinator_, &startupRecoveryCoordinator_),
      dependencies_(dependencies), anchorJournal_(std::move(anchorJournal)),
      enableReferenceJournal_(std::move(enableReferenceJournal)), anchorChildFactory_(),
      anchorCommandRunner_(anchorChildFactory_), enableChildFactory_(),
      enableCommandRunner_(enableChildFactory_), enableOwner_(enableCommandRunner_),
      startupOwner_(enableCommandRunner_), enableTokenVerifier_(),
      neighborAdapter_(dependencies_.arpPacketIo),
      arpRefresher_(dependencies_.arpPacketIo, std::move(arpRefreshTimer),
                    dependencies_.arpRefreshIntervalMs),
      delegate_(dependencies_.preMutation, dependencies_.pfQuery, dependencies_.settings,
                arpRefresher_, neighborAdapter_, anchorJournal_, dependencies_.pfQueryTimeoutMs,
                probeSecret),
      anchorAuthorization_(dependencies_.pfQuery, delegate_.leaseToken(),
                           dependencies_.effectiveUid, dependencies_.pfQueryTimeoutMs),
      anchorOperations_(anchorAuthorization_, anchorCommandRunner_),
      anchorCleanupVerifier_(dependencies_.pfQuery, dependencies_.pfQueryTimeoutMs),
      anchorRecoveryCoordinator_(anchorOperations_, anchorJournal_, anchorCleanupVerifier_),
      enableRecoveryCoordinator_(enableOwner_, enableReferenceJournal_, enableTokenVerifier_),
      startupRecoveryCoordinator_(startupOwner_, enableReferenceJournal_, enableTokenVerifier_) {}

ScopedSessionSystemOperations::~ScopedSessionSystemOperations() = default;

std::optional<QString>
ScopedSessionSystemOperations::acquireSessionLease(const SessionSnapshot &snapshot) {
    // Fresh pre-mutation gate first: it revalidates the frozen snapshot against current
    // observations and must pass before the journaled mutation path (recovery reconciliation,
    // lease, PF reference capture, anchor install) may run at all. The gate is uncached and
    // runs once per session-start attempt.
    if (!delegate_.leaseToken().isEmpty())
        return std::nullopt;
    if (!delegate_.freshPreMutationGateReady(snapshot))
        return std::nullopt;
    return PfAnchorRecoverySystemOperations::acquireSessionLease(snapshot);
}

std::unique_ptr<ScopedSessionSystemOperations> ScopedSessionSystemOperations::create(
    const HostSessionLease &lease, const QByteArray &probeSecret, int trustedDirectoryFd,
    const ScopedSessionDependencies &dependencies, QString *error) {
    const auto fail = [error](const QString &reason) {
        if (error)
            *error = reason;
        return std::unique_ptr<ScopedSessionSystemOperations>();
    };
    if (error)
        error->clear();
    if (trustedDirectoryFd < 0)
        return fail(QStringLiteral("trusted_directory_descriptor_required"));
    if (!ScopedSessionDelegate::validProbeSecretSize(probeSecret))
        return fail(QStringLiteral("probe_secret_invalid"));
    if (!dependencies.arpRefreshTimerFactory)
        return fail(QStringLiteral("arp_refresh_timer_factory_required"));
    if (dependencies.arpRefreshIntervalMs < ArpRedirectRefresher::minimumIntervalMs ||
        dependencies.arpRefreshIntervalMs > ArpRedirectRefresher::maximumIntervalMs)
        return fail(QStringLiteral("arp_refresh_interval_out_of_bounds"));
    if (dependencies.pfQueryTimeoutMs <= 0 ||
        dependencies.pfQueryTimeoutMs > PfDiagnostics::maximumTimeoutMs)
        return fail(QStringLiteral("pf_query_timeout_out_of_bounds"));

    auto anchorJournal = PfRecoveryJournal::open(trustedDirectoryFd);
    if (!anchorJournal.valid())
        return fail(QStringLiteral("anchor_recovery_journal_unavailable"));
    auto enableReferenceJournal = PfEnableReferenceJournal::open(trustedDirectoryFd);
    if (!enableReferenceJournal.valid())
        return fail(QStringLiteral("enable_reference_journal_unavailable"));

    auto arpRefreshTimer = dependencies.arpRefreshTimerFactory();
    if (!arpRefreshTimer)
        return fail(QStringLiteral("arp_refresh_timer_unavailable"));

    try {
        return std::unique_ptr<ScopedSessionSystemOperations>(new ScopedSessionSystemOperations(
            lease, probeSecret, dependencies, std::move(anchorJournal),
            std::move(enableReferenceJournal), std::move(arpRefreshTimer)));
    } catch (...) {
        return fail(QStringLiteral("scoped_session_operations_construction_failed"));
    }
}

LeasedHelperHost::BootstrapOperationsFactory
scopedSessionOperationsFactory(int trustedDirectoryFd, ScopedSessionDependencies dependencies,
                               QString *warning) {
    if (warning)
        warning->clear();
    if (!dependencies.arpRefreshTimerFactory) {
        if (warning)
            *warning = QStringLiteral("arp_refresh_timer_factory_required");
        return {};
    }
    return [trustedDirectoryFd, dependencies](
               const HostSessionLease &lease, const SessionSnapshot &,
               const QByteArray &probeSecret) -> std::unique_ptr<PfAnchorRecoverySystemOperations> {
        QString error;
        auto operations = ScopedSessionSystemOperations::create(
            lease, probeSecret, trustedDirectoryFd, dependencies, &error);
        if (!operations)
            qWarning("scoped session operations unavailable: %s", qPrintable(error));
        return operations;
    };
}

} // namespace interceptor
