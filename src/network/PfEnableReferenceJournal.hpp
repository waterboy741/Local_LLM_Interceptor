#pragma once

#include "PfEnableReferenceOwner.hpp"

#include <QString>
#include <optional>

namespace interceptor {

enum class PfEnableReferenceJournalStatus {
    Ready,
    InvalidDirectory,
    LockFailed,
    Missing,
    Present,
    UnsafeFile,
    InvalidRecord,
    InvalidOwner,
    OwnerConflict,
    InvalidToken,
    InvalidTransition,
    VerificationUnknown,
    TokenStillActive,
    IoFailed,
    DurabilityUncertain,
    Persisted,
    Cleared
};

enum class PfEnableReferenceJournalPhase {
    AcquirePending,
    AcquireUncertain,
    AcquireUncertainWithToken,
    ReleaseNeeded,
    ReleasePending
};

struct PfEnableReferenceRecord {
    QString sessionId;
    PfEnableReferenceJournalPhase phase = PfEnableReferenceJournalPhase::AcquirePending;
    std::optional<quint64> token;
};

struct PfEnableReferenceJournalReadResult {
    PfEnableReferenceJournalStatus status = PfEnableReferenceJournalStatus::IoFailed;
    std::optional<PfEnableReferenceRecord> record;
};

enum class PfEnableReferenceTokenState { Active, Absent, Unknown };

class PfEnableReferenceTokenVerifier {
  public:
    virtual ~PfEnableReferenceTokenVerifier() = default;
    virtual PfEnableReferenceTokenState verifyToken(quint64 token) = 0;
};

class PfEnableReferenceJournalFileOps {
  public:
    virtual ~PfEnableReferenceJournalFileOps() = default;
    virtual int syncFile(int fd) = 0;
    virtual int syncDirectory(int fd) = 0;
    virtual int renameAt(int oldDirFd, const char *oldName, int newDirFd, const char *newName) = 0;
    virtual int unlinkAt(int dirFd, const char *name) = 0;
};

class PfEnableReferenceJournal final {
  public:
    // The optional file-ops seam is borrowed and must outlive the journal.
    static PfEnableReferenceJournal open(int trustedDirectoryFd,
                                         PfEnableReferenceJournalFileOps *fileOps = nullptr);
    PfEnableReferenceJournal(const PfEnableReferenceJournal &) = delete;
    PfEnableReferenceJournal &operator=(const PfEnableReferenceJournal &) = delete;
    PfEnableReferenceJournal(PfEnableReferenceJournal &&other) noexcept;
    PfEnableReferenceJournal &operator=(PfEnableReferenceJournal &&other) = delete;
    ~PfEnableReferenceJournal();

    bool valid() const noexcept;
    PfEnableReferenceJournalStatus status() const noexcept;
    PfEnableReferenceJournalReadResult read() const;
    PfEnableReferenceJournalStatus persistAcquirePending(const QString &sessionId) const;
    PfEnableReferenceJournalStatus
    markAcquisitionUncertain(const QString &sessionId,
                             std::optional<quint64> token = std::nullopt) const;
    PfEnableReferenceJournalStatus persistCapturedToken(const QString &sessionId,
                                                        quint64 token) const;
    PfEnableReferenceJournalStatus markReleasePending(const QString &sessionId,
                                                      quint64 token) const;
    PfEnableReferenceJournalStatus
    clearAfterVerifiedRelease(const QString &sessionId,
                              const PfEnableReferenceReleaseReceipt &receipt,
                              PfEnableReferenceTokenVerifier &verifier) const;

    static QString statusName(PfEnableReferenceJournalStatus status);
    static QString phaseName(PfEnableReferenceJournalPhase phase);

  private:
    explicit PfEnableReferenceJournal(PfEnableReferenceJournalStatus status, int directoryFd = -1,
                                      PfEnableReferenceJournalFileOps *fileOps = nullptr) noexcept;

    PfEnableReferenceJournalStatus status_;
    int directoryFd_;
    PfEnableReferenceJournalFileOps *fileOps_;
};

} // namespace interceptor
