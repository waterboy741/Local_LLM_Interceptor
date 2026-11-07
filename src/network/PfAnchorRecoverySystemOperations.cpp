#include "PfAnchorRecoverySystemOperations.hpp"

#include <QThread>

namespace interceptor {

PfAnchorRecoverySystemOperations::PfAnchorRecoverySystemOperations(
    SystemOperations &delegate, const HostSessionLease &hostLease,
    PfAnchorRecoveryCoordinator &coordinator,
    PfEnableReferenceRecoveryCoordinator *pfReferenceCoordinator,
    PfEnableReferenceRecoveryCoordinator *startupRecoveryCoordinator)
    : delegate_(delegate), hostLease_(hostLease), coordinator_(coordinator),
      pfReferenceCoordinator_(pfReferenceCoordinator),
      startupRecoveryCoordinator_(startupRecoveryCoordinator),
      ownerThreadId_(QThread::currentThreadId()) {}

bool PfAnchorRecoverySystemOperations::ownerThread() const noexcept {
    return QThread::currentThreadId() == ownerThreadId_;
}

bool PfAnchorRecoverySystemOperations::activeSession() const noexcept {
    return ownerThread() && hostLease_.acquired() && leaseToken_ && !leaseToken_->isEmpty();
}

bool PfAnchorRecoverySystemOperations::activeSession(
    const SessionSnapshot &snapshot) const noexcept {
    if (!activeSession() || !sessionSnapshot_)
        return false;
    const auto &expectedConfig = sessionSnapshot_->config();
    const auto &actualConfig = snapshot.config();
    const auto &expectedFacts = sessionSnapshot_->facts();
    const auto &actualFacts = snapshot.facts();
    return sessionSnapshot_->sessionId() == snapshot.sessionId() &&
           sessionSnapshot_->proxyPort() == snapshot.proxyPort() &&
           expectedConfig.interfaceName == actualConfig.interfaceName &&
           expectedConfig.clientIp == actualConfig.clientIp &&
           expectedConfig.serverIp == actualConfig.serverIp &&
           expectedConfig.serverPort == actualConfig.serverPort &&
           expectedConfig.apiPaths == actualConfig.apiPaths &&
           expectedConfig.explicitProxy == actualConfig.explicitProxy &&
           expectedFacts.interfaceName == actualFacts.interfaceName &&
           expectedFacts.researchIp == actualFacts.researchIp &&
           expectedFacts.researchMac == actualFacts.researchMac &&
           expectedFacts.clientMac == actualFacts.clientMac &&
           expectedFacts.serverMac == actualFacts.serverMac &&
           expectedFacts.proxyServerIp == actualFacts.proxyServerIp &&
           expectedFacts.proxyServerPort == actualFacts.proxyServerPort &&
           expectedFacts.proxyListenPort == actualFacts.proxyListenPort &&
           expectedFacts.prefixLength == actualFacts.prefixLength &&
           expectedFacts.interfaceUp == actualFacts.interfaceUp &&
           expectedFacts.sameLink == actualFacts.sameLink &&
           expectedFacts.anchorAttached == actualFacts.anchorAttached &&
           expectedFacts.proxyReady == actualFacts.proxyReady &&
           expectedFacts.authorized == actualFacts.authorized;
}

std::optional<int> PfAnchorRecoverySystemOperations::readSetting(NetworkSetting setting) {
    return activeSession() ? delegate_.readSetting(setting) : std::nullopt;
}

SettingChange PfAnchorRecoverySystemOperations::compareAndSetSetting(NetworkSetting setting,
                                                                     int expected, int desired) {
    return activeSession() ? delegate_.compareAndSetSetting(setting, expected, desired)
                           : SettingChange::Failed;
}

std::optional<QString>
PfAnchorRecoverySystemOperations::acquireSessionLease(const SessionSnapshot &snapshot) {
    if (!ownerThread() || !hostLease_.acquired() || leaseToken_)
        return std::nullopt;
    if (startupRecoveryCoordinator_) {
        if (!pfReferenceCoordinator_ || startupRecoveryCoordinator_ == pfReferenceCoordinator_ ||
            startupRecoveryCoordinator_->sharesOwnerWith(*pfReferenceCoordinator_))
            return std::nullopt;
        if (!startupRecoveryCoordinator_->sharesJournalWith(*pfReferenceCoordinator_))
            return std::nullopt;
        const auto recovery = startupRecoveryCoordinator_->recoverPendingRelease();
        if (!recovery.success && recovery.statusCode != QStringLiteral("recovery_journal_missing"))
            return std::nullopt;
    }
    auto token = delegate_.acquireSessionLease(snapshot);
    if (!token || token->isEmpty())
        return std::nullopt;
    leaseToken_ = *token;
    sessionSnapshot_ = snapshot;
    anchorCleanupVerified_ = false;
    return token;
}

bool PfAnchorRecoverySystemOperations::releaseSessionLease(const QString &token) {
    if (!activeSession() || !leaseToken_ || token != *leaseToken_ || pfReferencePending_ ||
        pfReferenceToken_)
        return false;
    if (!delegate_.releaseSessionLease(token))
        return false;
    leaseToken_.reset();
    sessionSnapshot_.reset();
    return true;
}

std::optional<QString> PfAnchorRecoverySystemOperations::acquirePfReference() {
    if (!activeSession())
        return std::nullopt;
    if (!pfReferenceCoordinator_)
        return delegate_.acquirePfReference();
    if (pfReferencePending_ || pfReferenceToken_)
        return std::nullopt;

    pfReferencePending_ = true;
    PfEnableReferenceRecoveryResult result;
    try {
        result = pfReferenceCoordinator_->acquire(sessionSnapshot_->sessionId());
    } catch (...) {
        return std::nullopt;
    }
    if (!result.success || !result.token) {
        pfReferencePending_ = result.cleanupPending;
        return std::nullopt;
    }
    pfReferenceToken_ = QString::number(*result.token);
    return pfReferenceToken_;
}

bool PfAnchorRecoverySystemOperations::releasePfReference(const QString &token) {
    if (!activeSession())
        return false;
    if (!pfReferenceCoordinator_)
        return delegate_.releasePfReference(token);
    if (!anchorCleanupVerified_ || !pfReferencePending_ || !pfReferenceToken_ ||
        token != *pfReferenceToken_)
        return false;

    PfEnableReferenceRecoveryResult result;
    try {
        result = pfReferenceCoordinator_->release(sessionSnapshot_->sessionId());
    } catch (...) {
        return false;
    }
    if (!result.success)
        return false;
    pfReferenceToken_.reset();
    pfReferencePending_ = false;
    return true;
}

bool PfAnchorRecoverySystemOperations::installAnchor(const SessionSnapshot &snapshot) {
    if (!activeSession(snapshot) || !leaseToken_)
        return false;
    if (pfReferenceCoordinator_)
        anchorCleanupVerified_ = false;
    if (pfReferenceCoordinator_ && (!pfReferencePending_ || !pfReferenceToken_))
        return false;
    return coordinator_.install(snapshot, *leaseToken_).success;
}

bool PfAnchorRecoverySystemOperations::removeAnchor(const SessionSnapshot &snapshot) {
    if (!activeSession(snapshot) || !leaseToken_)
        return false;
    const bool cleaned = coordinator_.cleanup(snapshot, *leaseToken_).success;
    if (cleaned)
        anchorCleanupVerified_ = true;
    return cleaned;
}

bool PfAnchorRecoverySystemOperations::clearOwnedState(const SessionSnapshot &snapshot) {
    return activeSession(snapshot) && delegate_.clearOwnedState(snapshot);
}

bool PfAnchorRecoverySystemOperations::beginArp(const SessionSnapshot &snapshot) {
    return activeSession(snapshot) && delegate_.beginArp(snapshot);
}

bool PfAnchorRecoverySystemOperations::endArp(const SessionSnapshot &snapshot) {
    return activeSession(snapshot) && delegate_.endArp(snapshot);
}

bool PfAnchorRecoverySystemOperations::restoreNeighbors(const SessionSnapshot &snapshot) {
    return activeSession(snapshot) && delegate_.restoreNeighbors(snapshot);
}

bool PfAnchorRecoverySystemOperations::interfaceAvailable(const SessionSnapshot &snapshot) {
    return activeSession(snapshot) && delegate_.interfaceAvailable(snapshot);
}

bool PfAnchorRecoverySystemOperations::retainRecovery(const SessionSnapshot &snapshot,
                                                      const OwnershipJournal &journal) {
    return activeSession(snapshot) && delegate_.retainRecovery(snapshot, journal);
}

} // namespace interceptor
