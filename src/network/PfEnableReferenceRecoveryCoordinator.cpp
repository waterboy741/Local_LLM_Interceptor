#include "PfEnableReferenceRecoveryCoordinator.hpp"

namespace interceptor {

PfEnableReferenceRecoveryResult
PfEnableReferenceRecoveryCoordinator::acquire(const QString &sessionId) {
    PfEnableReferenceRecoveryResult result;
    if (acquireCalled_) {
        result.statusCode = "acquire_already_called";
        result.cleanupPending = true;
        result.journalStatus = journal_.read().status;
        return result;
    }
    acquireCalled_ = true;

    result.journalStatus = journal_.persistAcquirePending(sessionId);
    if (result.journalStatus != PfEnableReferenceJournalStatus::Persisted) {
        result.statusCode = "acquire_journal_not_durable";
        result.cleanupPending = result.journalStatus != PfEnableReferenceJournalStatus::Missing;
        return result;
    }

    PfEnableReferenceResult operation;
    try {
        operation = owner_.acquire();
    } catch (...) {
        result.operationStatus = "operation_exception";
        result.journalStatus = journal_.markAcquisitionUncertain(sessionId);
        result.statusCode = "acquire_uncertain";
        result.cleanupPending = true;
        return result;
    }
    result.operationStatus = operation.statusCode;
    if (!operation.success || !operation.token) {
        if (operation.acquireNotStartedReceipt) {
            result.journalStatus =
                journal_.clearNeverStartedAcquire(sessionId, *operation.acquireNotStartedReceipt);
            result.statusCode = result.journalStatus == PfEnableReferenceJournalStatus::Cleared
                                    ? QStringLiteral("acquire_not_started")
                                    : QStringLiteral("acquire_not_started_journal_uncertain");
            result.cleanupPending = result.journalStatus != PfEnableReferenceJournalStatus::Cleared;
            return result;
        }
        if (operation.cleanupPending || operation.token)
            result.journalStatus = journal_.markAcquisitionUncertain(sessionId, operation.token);
        result.statusCode =
            operation.cleanupPending ? "acquire_uncertain" : "acquire_failed_pending";
        result.cleanupPending = true;
        return result;
    }

    result.journalStatus = journal_.persistCapturedToken(sessionId, *operation.token);
    if (result.journalStatus != PfEnableReferenceJournalStatus::Persisted) {
        result.statusCode = "acquired_token_journal_uncertain";
        result.cleanupPending = true;
        return result;
    }
    tokenJournalDurable_ = true;
    result.success = true;
    result.token = operation.token;
    result.statusCode = "acquired_token_durable";
    return result;
}

PfEnableReferenceRecoveryResult
PfEnableReferenceRecoveryCoordinator::verifyAndClear(const QString &sessionId, quint64 token) {
    PfEnableReferenceRecoveryResult result;
    if (!releaseReceipt_ || releaseReceipt_->token() != token) {
        result.statusCode = "owned_release_receipt_missing";
        result.cleanupPending = true;
        result.journalStatus = journal_.read().status;
        return result;
    }
    result.journalStatus =
        journal_.clearAfterVerifiedRelease(sessionId, *releaseReceipt_, verifier_);
    if (result.journalStatus != PfEnableReferenceJournalStatus::Cleared) {
        result.statusCode = PfEnableReferenceJournal::statusName(result.journalStatus);
        result.cleanupPending = true;
        return result;
    }
    result.success = true;
    result.statusCode = "reference_released_and_verified";
    releaseCompleted_ = true;
    return result;
}

PfEnableReferenceRecoveryResult
PfEnableReferenceRecoveryCoordinator::release(const QString &sessionId) {
    PfEnableReferenceRecoveryResult result;
    if (releaseCompleted_) {
        result.statusCode = "already_released";
        result.journalStatus = journal_.read().status;
        return result;
    }
    if (releaseBlocked_) {
        result.statusCode = "release_recovery_required";
        result.cleanupPending = true;
        result.journalStatus = journal_.read().status;
        return result;
    }
    if (!tokenJournalDurable_ && !releaseReceipt_) {
        result.statusCode = "release_not_owned_by_coordinator";
        result.cleanupPending = true;
        result.journalStatus = journal_.read().status;
        return result;
    }
    const auto read = journal_.read();
    result.journalStatus = read.status;
    if (read.status != PfEnableReferenceJournalStatus::Present || !read.record) {
        result.statusCode = "release_journal_unavailable";
        result.cleanupPending = true;
        return result;
    }
    if (read.record->sessionId != sessionId) {
        result.statusCode = "release_owner_mismatch";
        result.journalStatus = PfEnableReferenceJournalStatus::OwnerConflict;
        result.cleanupPending = true;
        return result;
    }
    if (!read.record->token) {
        result.statusCode = "release_token_unknown";
        result.cleanupPending = true;
        return result;
    }
    const auto token = *read.record->token;

    if (releaseReceipt_)
        return verifyAndClear(sessionId, token);

    if (read.record->phase == PfEnableReferenceJournalPhase::ReleaseNeeded) {
        result.journalStatus = journal_.markReleasePending(sessionId, token);
        if (result.journalStatus != PfEnableReferenceJournalStatus::Persisted) {
            releaseBlocked_ = true;
            result.statusCode = "release_pending_not_durable";
            result.cleanupPending = true;
            return result;
        }
        releasePendingDurable_ = true;
    } else if (read.record->phase != PfEnableReferenceJournalPhase::ReleasePending) {
        result.statusCode = "release_recovery_required";
        result.cleanupPending = true;
        return result;
    } else if (!releasePendingDurable_) {
        // A visible ReleasePending file after restart or an uncertain directory sync is not
        // evidence that this process durably recorded permission to issue -X.
        releaseBlocked_ = true;
        result.statusCode = "release_pending_not_owned_by_coordinator";
        result.cleanupPending = true;
        return result;
    }

    PfEnableReferenceResult operation;
    try {
        operation = owner_.release();
    } catch (...) {
        result.operationStatus = "operation_exception";
        releaseBlocked_ = true;
        result.statusCode = "release_uncertain";
        result.cleanupPending = true;
        return result;
    }
    result.operationStatus = operation.statusCode;
    if (!operation.success || !operation.releaseReceipt) {
        releaseBlocked_ = true;
        result.statusCode =
            operation.statusCode.isEmpty() ? "release_uncertain" : operation.statusCode;
        result.cleanupPending = true;
        return result;
    }
    releaseReceipt_ = operation.releaseReceipt;
    return verifyAndClear(sessionId, token);
}

PfEnableReferenceRecoveryResult
PfEnableReferenceRecoveryCoordinator::recoverRelease(const QString &sessionId) {
    PfEnableReferenceRecoveryResult result;
    if (recoveryAttempted_) {
        result.statusCode = "recovery_already_attempted";
        result.cleanupPending = true;
        result.journalStatus = journal_.read().status;
        return result;
    }
    recoveryAttempted_ = true;

    const auto read = journal_.read();
    result.journalStatus = read.status;
    if (read.status != PfEnableReferenceJournalStatus::Present || !read.record) {
        result.statusCode = read.status == PfEnableReferenceJournalStatus::Missing
                                ? QStringLiteral("recovery_journal_missing")
                                : QStringLiteral("recovery_journal_unavailable");
        result.cleanupPending = read.status != PfEnableReferenceJournalStatus::Missing;
        return result;
    }
    const auto &record = *read.record;
    if (record.sessionId != sessionId) {
        result.journalStatus = PfEnableReferenceJournalStatus::OwnerConflict;
        result.statusCode = "recovery_owner_mismatch";
        result.cleanupPending = true;
        return result;
    }
    if (!record.token) {
        result.statusCode = "recovery_token_unknown";
        result.cleanupPending = true;
        return result;
    }
    if (record.phase != PfEnableReferenceJournalPhase::ReleaseNeeded &&
        record.phase != PfEnableReferenceJournalPhase::ReleasePending) {
        result.statusCode = "recovery_phase_not_releasable";
        result.cleanupPending = true;
        return result;
    }

    PfEnableReferenceTokenState tokenState = PfEnableReferenceTokenState::Unknown;
    try {
        tokenState = verifier_.verifyToken(*record.token);
    } catch (...) {
        tokenState = PfEnableReferenceTokenState::Unknown;
    }
    if (tokenState == PfEnableReferenceTokenState::Absent) {
        result.journalStatus =
            journal_.clearAfterVerifiedAbsence(sessionId, *record.token, verifier_);
        result.success = result.journalStatus == PfEnableReferenceJournalStatus::Cleared;
        result.cleanupPending = !result.success;
        result.statusCode = result.success
                                ? QStringLiteral("recovered_token_already_absent")
                                : PfEnableReferenceJournal::statusName(result.journalStatus);
        return result;
    }
    if (record.phase == PfEnableReferenceJournalPhase::ReleasePending) {
        result.statusCode = tokenState == PfEnableReferenceTokenState::Active
                                ? QStringLiteral("release_pending_token_active_manual_recovery")
                                : QStringLiteral("release_pending_token_state_unknown");
        result.journalStatus = tokenState == PfEnableReferenceTokenState::Active
                                   ? PfEnableReferenceJournalStatus::TokenStillActive
                                   : PfEnableReferenceJournalStatus::VerificationUnknown;
        result.cleanupPending = true;
        return result;
    }
    if (tokenState != PfEnableReferenceTokenState::Active) {
        result.journalStatus = PfEnableReferenceJournalStatus::VerificationUnknown;
        result.statusCode = "release_needed_token_state_unknown";
        result.cleanupPending = true;
        return result;
    }

    result.journalStatus = journal_.markReleasePending(sessionId, *record.token);
    if (result.journalStatus != PfEnableReferenceJournalStatus::Persisted) {
        result.statusCode = "recovery_release_pending_not_durable";
        result.cleanupPending = true;
        return result;
    }
    // Only this fresh ReleaseNeeded -> durable ReleasePending transition may mint the
    // one-use recovery capability. Existing ReleasePending records never reach this point.
    PfEnableReferenceTokenState postPersistState = PfEnableReferenceTokenState::Unknown;
    try {
        postPersistState = verifier_.verifyToken(*record.token);
    } catch (...) {
        postPersistState = PfEnableReferenceTokenState::Unknown;
    }
    if (postPersistState == PfEnableReferenceTokenState::Absent) {
        result.journalStatus =
            journal_.clearAfterVerifiedAbsence(sessionId, *record.token, verifier_);
        result.success = result.journalStatus == PfEnableReferenceJournalStatus::Cleared;
        result.cleanupPending = !result.success;
        result.statusCode = result.success
                                ? QStringLiteral("recovered_token_already_absent")
                                : PfEnableReferenceJournal::statusName(result.journalStatus);
        return result;
    }
    if (postPersistState != PfEnableReferenceTokenState::Active) {
        result.journalStatus = PfEnableReferenceJournalStatus::VerificationUnknown;
        result.statusCode = "recovery_token_state_changed_before_release";
        result.cleanupPending = true;
        return result;
    }
    const PfEnableReferenceRecoveryToken recoveryToken(sessionId, *record.token);
    if (!owner_.adoptRecoveredToken(recoveryToken)) {
        result.statusCode = "recovery_owner_not_available";
        result.cleanupPending = true;
        return result;
    }

    PfEnableReferenceResult operation;
    try {
        operation = owner_.release();
    } catch (...) {
        result.operationStatus = "operation_exception";
        result.statusCode = "recovery_release_uncertain";
        result.cleanupPending = true;
        return result;
    }
    result.operationStatus = operation.statusCode;
    if (!operation.success || !operation.releaseReceipt) {
        result.statusCode = operation.statusCode.isEmpty()
                                ? QStringLiteral("recovery_release_uncertain")
                                : operation.statusCode;
        result.cleanupPending = true;
        return result;
    }
    result.journalStatus =
        journal_.clearAfterVerifiedRelease(sessionId, *operation.releaseReceipt, verifier_);
    result.success = result.journalStatus == PfEnableReferenceJournalStatus::Cleared;
    result.cleanupPending = !result.success;
    result.statusCode = result.success ? QStringLiteral("recovered_reference_released")
                                       : PfEnableReferenceJournal::statusName(result.journalStatus);
    return result;
}

PfEnableReferenceRecoveryResult PfEnableReferenceRecoveryCoordinator::recoverPendingRelease() {
    const auto read = journal_.read();
    if (read.status != PfEnableReferenceJournalStatus::Present || !read.record) {
        PfEnableReferenceRecoveryResult result;
        result.journalStatus = read.status;
        result.statusCode = read.status == PfEnableReferenceJournalStatus::Missing
                                ? QStringLiteral("recovery_journal_missing")
                                : QStringLiteral("recovery_journal_unavailable");
        result.cleanupPending = read.status != PfEnableReferenceJournalStatus::Missing;
        return result;
    }
    if (read.record->phase == PfEnableReferenceJournalPhase::ReleaseNeeded) {
        PfEnableReferenceRecoveryResult result;
        result.journalStatus = PfEnableReferenceJournalStatus::Present;
        result.statusCode = "release_needed_requires_anchor_cleanup";
        result.cleanupPending = true;
        return result;
    }
    return recoverRelease(read.record->sessionId);
}

} // namespace interceptor
