#pragma once

#include "PfEnableReferenceJournal.hpp"

namespace interceptor {

struct PfEnableReferenceRecoveryResult {
    bool success = false;
    bool cleanupPending = false;
    QString statusCode;
    QString operationStatus;
    PfEnableReferenceJournalStatus journalStatus = PfEnableReferenceJournalStatus::Ready;
    std::optional<quint64> token;
};

// Orders one active PF reference lifecycle and can reconcile one durable pending release from a
// prior process. After restart reconciliation the owner is consumed; create a fresh owner and
// coordinator for a new active lifecycle.
class PfEnableReferenceRecoveryCoordinator final {
  public:
    PfEnableReferenceRecoveryCoordinator(PfEnableReferenceOwner &owner,
                                         PfEnableReferenceJournal &journal,
                                         PfEnableReferenceTokenVerifier &verifier)
        : owner_(owner), journal_(journal), verifier_(verifier) {}

    PfEnableReferenceRecoveryResult acquire(const QString &sessionId);
    PfEnableReferenceRecoveryResult release(const QString &sessionId);
    PfEnableReferenceRecoveryResult recoverRelease(const QString &sessionId);
    // Reconcile the session named by the durable recovery record, which may belong to a previous
    // helper process with a different freshly generated session identity.
    PfEnableReferenceRecoveryResult recoverPendingRelease();
    bool sharesJournalWith(const PfEnableReferenceRecoveryCoordinator &other) const noexcept {
        return &journal_ == &other.journal_;
    }
    bool sharesOwnerWith(const PfEnableReferenceRecoveryCoordinator &other) const noexcept {
        return &owner_ == &other.owner_;
    }

  private:
    PfEnableReferenceRecoveryResult verifyAndClear(const QString &sessionId, quint64 token);

    PfEnableReferenceOwner &owner_;
    PfEnableReferenceJournal &journal_;
    PfEnableReferenceTokenVerifier &verifier_;
    bool acquireCalled_ = false;
    bool tokenJournalDurable_ = false;
    bool releasePendingDurable_ = false;
    bool releaseBlocked_ = false;
    bool releaseCompleted_ = false;
    bool recoveryAttempted_ = false;
    std::optional<PfEnableReferenceReleaseReceipt> releaseReceipt_;
};

} // namespace interceptor
