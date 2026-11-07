#pragma once

#include "PfEnableReferenceJournal.hpp"

namespace interceptor {

struct PfEnableReferenceRecoveryResult {
    bool success = false;
    bool cleanupPending = false;
    QString statusCode;
    QString operationStatus;
    PfEnableReferenceJournalStatus journalStatus = PfEnableReferenceJournalStatus::Ready;
};

// One-process ordering coordinator. It does not recover/adopt state after process restart.
class PfEnableReferenceRecoveryCoordinator final {
  public:
    PfEnableReferenceRecoveryCoordinator(PfEnableReferenceOwner &owner,
                                         PfEnableReferenceJournal &journal,
                                         PfEnableReferenceTokenVerifier &verifier)
        : owner_(owner), journal_(journal), verifier_(verifier) {}

    PfEnableReferenceRecoveryResult acquire(const QString &sessionId);
    PfEnableReferenceRecoveryResult release(const QString &sessionId);
    PfEnableReferenceRecoveryResult recoverRelease(const QString &sessionId);

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
