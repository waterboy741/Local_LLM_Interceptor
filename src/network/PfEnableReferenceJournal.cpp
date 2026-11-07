#include "PfEnableReferenceJournal.hpp"

#include <QByteArray>
#include <QVector>

#include <atomic>
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace interceptor {
namespace {
constexpr char journalName[] = "llm_interceptor.pf-enable.journal";
constexpr char guardName[] = "llm_interceptor.pf-enable.lock";
constexpr char schema[] = "llm-interceptor.pf-enable-reference.v1";
constexpr qsizetype maximumRecordBytes = 256;
constexpr mode_t privateMode = 0700;
constexpr mode_t fileMode = 0600;
std::atomic<unsigned long long> tempSequence{0};

class SystemJournalFileOps final : public PfEnableReferenceJournalFileOps {
  public:
    int syncFile(int fd) override { return ::fsync(fd); }
    int syncDirectory(int fd) override { return ::fsync(fd); }
    int renameAt(int oldDirFd, const char *oldName, int newDirFd, const char *newName) override {
        return ::renameat(oldDirFd, oldName, newDirFd, newName);
    }
    int unlinkAt(int dirFd, const char *name) override { return ::unlinkat(dirFd, name, 0); }
};

SystemJournalFileOps systemFileOps;

bool privateDirectory(int fd) {
    struct stat info{};
    return ::fstat(fd, &info) == 0 && S_ISDIR(info.st_mode) && info.st_uid == ::geteuid() &&
           (info.st_mode & 07777) == privateMode;
}

bool safeFile(int fd) {
    struct stat info{};
    return ::fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && info.st_uid == ::geteuid() &&
           (info.st_mode & 07777) == fileMode && info.st_nlink == 1;
}

bool validOwner(const QString &owner, QByteArray *encoded) {
    *encoded = owner.toUtf8();
    if (encoded->isEmpty() || encoded->size() > 48 || QString::fromLatin1(*encoded) != owner)
        return false;
    for (const auto ch : *encoded)
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
              ch == '_' || ch == '-'))
            return false;
    return true;
}

QByteArray phaseBytes(PfEnableReferenceJournalPhase phase) {
    switch (phase) {
    case PfEnableReferenceJournalPhase::AcquirePending:
        return "acquire_pending";
    case PfEnableReferenceJournalPhase::AcquireUncertain:
        return "acquire_uncertain";
    case PfEnableReferenceJournalPhase::AcquireUncertainWithToken:
        return "acquire_uncertain_token";
    case PfEnableReferenceJournalPhase::ReleaseNeeded:
        return "release_needed";
    case PfEnableReferenceJournalPhase::ReleasePending:
        return "release_pending";
    }
    return {};
}

std::optional<PfEnableReferenceJournalPhase> parsePhase(const QByteArray &value) {
    for (const auto phase : {PfEnableReferenceJournalPhase::AcquirePending,
                             PfEnableReferenceJournalPhase::AcquireUncertain,
                             PfEnableReferenceJournalPhase::AcquireUncertainWithToken,
                             PfEnableReferenceJournalPhase::ReleaseNeeded,
                             PfEnableReferenceJournalPhase::ReleasePending})
        if (phaseBytes(phase) == value)
            return phase;
    return std::nullopt;
}

QByteArray serialize(const QByteArray &owner, PfEnableReferenceJournalPhase phase,
                     std::optional<quint64> token) {
    return QByteArray("schema=") + schema + "\nsession_id=" + owner +
           "\nphase=" + phaseBytes(phase) +
           "\ntoken=" + (token ? QByteArray::number(*token) : QByteArray("unknown")) + "\n";
}

bool writeAll(int fd, const QByteArray &bytes) {
    qsizetype offset = 0;
    while (offset < bytes.size()) {
        const auto count =
            ::write(fd, bytes.constData() + offset, static_cast<size_t>(bytes.size() - offset));
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return false;
        offset += static_cast<qsizetype>(count);
    }
    return true;
}

class JournalLock final {
  public:
    explicit JournalLock(int fd = -1) : fd_(fd) {}
    JournalLock(const JournalLock &) = delete;
    JournalLock &operator=(const JournalLock &) = delete;
    ~JournalLock() {
        if (fd_ >= 0) {
            ::flock(fd_, LOCK_UN);
            ::close(fd_);
        }
    }
    int fd() const { return fd_; }

  private:
    int fd_;
};

JournalLock lockDirectory(int directoryFd) {
    int fd = ::openat(directoryFd, guardName,
                      O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, fileMode);
    if (fd < 0 || !safeFile(fd)) {
        if (fd >= 0)
            ::close(fd);
        return JournalLock();
    }
    int result;
    do {
        result = ::flock(fd, LOCK_EX | LOCK_NB);
    } while (result < 0 && errno == EINTR);
    if (result < 0) {
        ::close(fd);
        return JournalLock();
    }
    return JournalLock(fd);
}

PfEnableReferenceJournalReadResult readUnlocked(int directoryFd) {
    const int fd =
        ::openat(directoryFd, journalName, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0)
        return {errno == ENOENT ? PfEnableReferenceJournalStatus::Missing
                                : PfEnableReferenceJournalStatus::UnsafeFile,
                std::nullopt};
    if (!safeFile(fd)) {
        ::close(fd);
        return {PfEnableReferenceJournalStatus::UnsafeFile, std::nullopt};
    }
    struct stat before{};
    if (::fstat(fd, &before) < 0 || before.st_size <= 0 || before.st_size > maximumRecordBytes) {
        ::close(fd);
        return {PfEnableReferenceJournalStatus::InvalidRecord, std::nullopt};
    }
    QByteArray bytes(static_cast<qsizetype>(before.st_size) + 1, Qt::Uninitialized);
    ssize_t count;
    do {
        count = ::read(fd, bytes.data(), static_cast<size_t>(bytes.size()));
    } while (count < 0 && errno == EINTR);
    struct stat after{};
    const bool statOk = ::fstat(fd, &after) == 0;
    const int closeResult = ::close(fd);
    if (count != before.st_size || !statOk || closeResult < 0 || after.st_dev != before.st_dev ||
        after.st_ino != before.st_ino || after.st_size != before.st_size)
        return {PfEnableReferenceJournalStatus::IoFailed, std::nullopt};
    bytes.resize(static_cast<qsizetype>(count));
    if (bytes.contains('\r') || QString::fromUtf8(bytes).toUtf8() != bytes)
        return {PfEnableReferenceJournalStatus::InvalidRecord, std::nullopt};
    const auto lines = bytes.split('\n');
    if (lines.size() != 5 || !lines[4].isEmpty() || lines[0] != QByteArray("schema=") + schema ||
        !lines[1].startsWith("session_id=") || !lines[2].startsWith("phase=") ||
        !lines[3].startsWith("token="))
        return {PfEnableReferenceJournalStatus::InvalidRecord, std::nullopt};

    const auto ownerBytes = lines[1].mid(sizeof("session_id=") - 1);
    const auto owner = QString::fromLatin1(ownerBytes);
    QByteArray validatedOwner;
    const auto phase = parsePhase(lines[2].mid(sizeof("phase=") - 1));
    const auto tokenBytes = lines[3].mid(sizeof("token=") - 1);
    std::optional<quint64> token;
    if (tokenBytes != "unknown") {
        bool ok = false;
        const auto parsed = tokenBytes.toULongLong(&ok, 10);
        if (!ok || parsed == 0 || QByteArray::number(parsed) != tokenBytes)
            return {PfEnableReferenceJournalStatus::InvalidRecord, std::nullopt};
        token = parsed;
    }
    if (!validOwner(owner, &validatedOwner) || validatedOwner != ownerBytes || !phase)
        return {PfEnableReferenceJournalStatus::InvalidRecord, std::nullopt};
    const bool requiresToken = *phase == PfEnableReferenceJournalPhase::AcquireUncertainWithToken ||
                               *phase == PfEnableReferenceJournalPhase::ReleaseNeeded ||
                               *phase == PfEnableReferenceJournalPhase::ReleasePending;
    if (requiresToken != token.has_value())
        return {PfEnableReferenceJournalStatus::InvalidRecord, std::nullopt};
    return {PfEnableReferenceJournalStatus::Present, PfEnableReferenceRecord{owner, *phase, token}};
}

PfEnableReferenceJournalStatus writeUnlocked(int directoryFd, PfEnableReferenceJournalFileOps &ops,
                                             const QByteArray &bytes) {
    QByteArray temp;
    int fd = -1;
    for (int attempt = 0; attempt < 64; ++attempt) {
        const auto sequence = tempSequence.fetch_add(1, std::memory_order_relaxed);
        temp = QByteArray(".llm_interceptor.pf-enable.tmp.") +
               QByteArray::number(static_cast<qlonglong>(::getpid())) + "." +
               QByteArray::number(static_cast<qulonglong>(sequence));
        fd = ::openat(directoryFd, temp.constData(),
                      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, fileMode);
        if (fd >= 0)
            break;
        if (errno != EEXIST)
            return PfEnableReferenceJournalStatus::IoFailed;
    }
    if (fd < 0)
        return PfEnableReferenceJournalStatus::IoFailed;
    if (!safeFile(fd) || !writeAll(fd, bytes) || ops.syncFile(fd) < 0) {
        ::close(fd);
        ::unlinkat(directoryFd, temp.constData(), 0);
        return PfEnableReferenceJournalStatus::IoFailed;
    }
    if (::close(fd) < 0) {
        ::unlinkat(directoryFd, temp.constData(), 0);
        return PfEnableReferenceJournalStatus::IoFailed;
    }
    if (ops.renameAt(directoryFd, temp.constData(), directoryFd, journalName) < 0) {
        ::unlinkat(directoryFd, temp.constData(), 0);
        return PfEnableReferenceJournalStatus::IoFailed;
    }
    if (ops.syncDirectory(directoryFd) < 0)
        return PfEnableReferenceJournalStatus::DurabilityUncertain;
    return PfEnableReferenceJournalStatus::Persisted;
}

} // namespace

PfEnableReferenceJournal::PfEnableReferenceJournal(
    PfEnableReferenceJournalStatus status, int directoryFd,
    PfEnableReferenceJournalFileOps *fileOps) noexcept
    : status_(status), directoryFd_(directoryFd), fileOps_(fileOps ? fileOps : &systemFileOps) {}

PfEnableReferenceJournal PfEnableReferenceJournal::open(int trustedDirectoryFd,
                                                        PfEnableReferenceJournalFileOps *fileOps) {
    if (!privateDirectory(trustedDirectoryFd))
        return PfEnableReferenceJournal(PfEnableReferenceJournalStatus::InvalidDirectory);
    const int fd = ::fcntl(trustedDirectoryFd, F_DUPFD_CLOEXEC, 0);
    if (fd < 0 || !privateDirectory(fd)) {
        if (fd >= 0)
            ::close(fd);
        return PfEnableReferenceJournal(PfEnableReferenceJournalStatus::InvalidDirectory);
    }
    return PfEnableReferenceJournal(PfEnableReferenceJournalStatus::Ready, fd, fileOps);
}

PfEnableReferenceJournal::PfEnableReferenceJournal(PfEnableReferenceJournal &&other) noexcept
    : status_(other.status_), directoryFd_(other.directoryFd_), fileOps_(other.fileOps_) {
    other.status_ = PfEnableReferenceJournalStatus::InvalidDirectory;
    other.directoryFd_ = -1;
}

PfEnableReferenceJournal::~PfEnableReferenceJournal() {
    if (directoryFd_ >= 0)
        ::close(directoryFd_);
}

bool PfEnableReferenceJournal::valid() const noexcept {
    return directoryFd_ >= 0 && status_ == PfEnableReferenceJournalStatus::Ready &&
           privateDirectory(directoryFd_);
}
PfEnableReferenceJournalStatus PfEnableReferenceJournal::status() const noexcept { return status_; }

PfEnableReferenceJournalReadResult PfEnableReferenceJournal::read() const {
    if (!valid())
        return {status_ == PfEnableReferenceJournalStatus::Ready
                    ? PfEnableReferenceJournalStatus::InvalidDirectory
                    : status_,
                std::nullopt};
    const auto guard = lockDirectory(directoryFd_);
    if (guard.fd() < 0)
        return {PfEnableReferenceJournalStatus::LockFailed, std::nullopt};
    return readUnlocked(directoryFd_);
}

PfEnableReferenceJournalStatus
PfEnableReferenceJournal::persistAcquirePending(const QString &sessionId) const {
    if (!valid())
        return PfEnableReferenceJournalStatus::InvalidDirectory;
    QByteArray owner;
    if (!validOwner(sessionId, &owner))
        return PfEnableReferenceJournalStatus::InvalidOwner;
    const auto guard = lockDirectory(directoryFd_);
    if (guard.fd() < 0)
        return PfEnableReferenceJournalStatus::LockFailed;
    const auto existing = readUnlocked(directoryFd_);
    if (existing.status != PfEnableReferenceJournalStatus::Missing)
        return existing.status == PfEnableReferenceJournalStatus::Present
                   ? PfEnableReferenceJournalStatus::OwnerConflict
                   : existing.status;
    return writeUnlocked(
        directoryFd_, *fileOps_,
        serialize(owner, PfEnableReferenceJournalPhase::AcquirePending, std::nullopt));
}

PfEnableReferenceJournalStatus PfEnableReferenceJournal::clearNeverStartedAcquire(
    const QString &sessionId, const PfEnableReferenceAcquireNotStartedReceipt &) const {
    if (!valid())
        return PfEnableReferenceJournalStatus::InvalidDirectory;
    QByteArray owner;
    if (!validOwner(sessionId, &owner))
        return PfEnableReferenceJournalStatus::InvalidOwner;
    const auto guard = lockDirectory(directoryFd_);
    if (guard.fd() < 0)
        return PfEnableReferenceJournalStatus::LockFailed;
    const auto existing = readUnlocked(directoryFd_);
    if (existing.status != PfEnableReferenceJournalStatus::Present || !existing.record)
        return existing.status;
    if (existing.record->sessionId != sessionId)
        return PfEnableReferenceJournalStatus::OwnerConflict;
    if (existing.record->phase != PfEnableReferenceJournalPhase::AcquirePending ||
        existing.record->token)
        return PfEnableReferenceJournalStatus::InvalidTransition;
    if (fileOps_->unlinkAt(directoryFd_, journalName) < 0)
        return PfEnableReferenceJournalStatus::IoFailed;
    if (fileOps_->syncDirectory(directoryFd_) < 0)
        return PfEnableReferenceJournalStatus::DurabilityUncertain;
    return PfEnableReferenceJournalStatus::Cleared;
}

PfEnableReferenceJournalStatus
PfEnableReferenceJournal::markAcquisitionUncertain(const QString &sessionId,
                                                   std::optional<quint64> token) const {
    if (!valid())
        return PfEnableReferenceJournalStatus::InvalidDirectory;
    QByteArray owner;
    if (!validOwner(sessionId, &owner))
        return PfEnableReferenceJournalStatus::InvalidOwner;
    if (token && *token == 0)
        return PfEnableReferenceJournalStatus::InvalidToken;
    const auto guard = lockDirectory(directoryFd_);
    if (guard.fd() < 0)
        return PfEnableReferenceJournalStatus::LockFailed;
    const auto existing = readUnlocked(directoryFd_);
    if (existing.status != PfEnableReferenceJournalStatus::Present || !existing.record)
        return existing.status;
    if (existing.record->sessionId != sessionId)
        return PfEnableReferenceJournalStatus::OwnerConflict;
    if (existing.record->phase != PfEnableReferenceJournalPhase::AcquirePending &&
        existing.record->phase != PfEnableReferenceJournalPhase::AcquireUncertain)
        return PfEnableReferenceJournalStatus::InvalidTransition;
    if (existing.record->token && token && existing.record->token != token)
        return PfEnableReferenceJournalStatus::OwnerConflict;
    const auto nextToken = token ? token : existing.record->token;
    const auto phase = nextToken ? PfEnableReferenceJournalPhase::AcquireUncertainWithToken
                                 : PfEnableReferenceJournalPhase::AcquireUncertain;
    return writeUnlocked(directoryFd_, *fileOps_, serialize(owner, phase, nextToken));
}

PfEnableReferenceJournalStatus
PfEnableReferenceJournal::persistCapturedToken(const QString &sessionId, quint64 token) const {
    if (!valid())
        return PfEnableReferenceJournalStatus::InvalidDirectory;
    QByteArray owner;
    if (!validOwner(sessionId, &owner))
        return PfEnableReferenceJournalStatus::InvalidOwner;
    if (token == 0)
        return PfEnableReferenceJournalStatus::InvalidToken;
    const auto guard = lockDirectory(directoryFd_);
    if (guard.fd() < 0)
        return PfEnableReferenceJournalStatus::LockFailed;
    const auto existing = readUnlocked(directoryFd_);
    if (existing.status != PfEnableReferenceJournalStatus::Present || !existing.record)
        return existing.status;
    if (existing.record->sessionId != sessionId)
        return PfEnableReferenceJournalStatus::OwnerConflict;
    if (existing.record->phase != PfEnableReferenceJournalPhase::AcquirePending)
        return PfEnableReferenceJournalStatus::InvalidTransition;
    return writeUnlocked(directoryFd_, *fileOps_,
                         serialize(owner, PfEnableReferenceJournalPhase::ReleaseNeeded, token));
}

PfEnableReferenceJournalStatus
PfEnableReferenceJournal::markReleasePending(const QString &sessionId, quint64 token) const {
    if (!valid())
        return PfEnableReferenceJournalStatus::InvalidDirectory;
    QByteArray owner;
    if (!validOwner(sessionId, &owner))
        return PfEnableReferenceJournalStatus::InvalidOwner;
    if (token == 0)
        return PfEnableReferenceJournalStatus::InvalidToken;
    const auto guard = lockDirectory(directoryFd_);
    if (guard.fd() < 0)
        return PfEnableReferenceJournalStatus::LockFailed;
    const auto existing = readUnlocked(directoryFd_);
    if (existing.status != PfEnableReferenceJournalStatus::Present || !existing.record)
        return existing.status;
    if (existing.record->sessionId != sessionId || existing.record->token != token)
        return PfEnableReferenceJournalStatus::OwnerConflict;
    if (existing.record->phase != PfEnableReferenceJournalPhase::ReleaseNeeded)
        return PfEnableReferenceJournalStatus::InvalidTransition;
    return writeUnlocked(directoryFd_, *fileOps_,
                         serialize(owner, PfEnableReferenceJournalPhase::ReleasePending, token));
}

PfEnableReferenceJournalStatus PfEnableReferenceJournal::clearAfterVerifiedRelease(
    const QString &sessionId, const PfEnableReferenceReleaseReceipt &receipt,
    PfEnableReferenceTokenVerifier &verifier) const {
    const auto token = receipt.token();
    if (!valid())
        return PfEnableReferenceJournalStatus::InvalidDirectory;
    QByteArray owner;
    if (!validOwner(sessionId, &owner))
        return PfEnableReferenceJournalStatus::InvalidOwner;
    if (token == 0)
        return PfEnableReferenceJournalStatus::InvalidToken;
    const auto guard = lockDirectory(directoryFd_);
    if (guard.fd() < 0)
        return PfEnableReferenceJournalStatus::LockFailed;
    const auto existing = readUnlocked(directoryFd_);
    if (existing.status != PfEnableReferenceJournalStatus::Present || !existing.record)
        return existing.status;
    if (existing.record->sessionId != sessionId || existing.record->token != token)
        return PfEnableReferenceJournalStatus::OwnerConflict;
    if (existing.record->phase != PfEnableReferenceJournalPhase::ReleasePending)
        return PfEnableReferenceJournalStatus::InvalidTransition;
    PfEnableReferenceTokenState verification;
    try {
        verification = verifier.verifyToken(token);
    } catch (...) {
        verification = PfEnableReferenceTokenState::Unknown;
    }
    if (verification == PfEnableReferenceTokenState::Active)
        return PfEnableReferenceJournalStatus::TokenStillActive;
    if (verification != PfEnableReferenceTokenState::Absent)
        return PfEnableReferenceJournalStatus::VerificationUnknown;
    if (fileOps_->unlinkAt(directoryFd_, journalName) < 0)
        return PfEnableReferenceJournalStatus::IoFailed;
    if (fileOps_->syncDirectory(directoryFd_) < 0)
        return PfEnableReferenceJournalStatus::DurabilityUncertain;
    return PfEnableReferenceJournalStatus::Cleared;
}

QString PfEnableReferenceJournal::statusName(PfEnableReferenceJournalStatus status) {
    switch (status) {
    case PfEnableReferenceJournalStatus::Ready:
        return "ready";
    case PfEnableReferenceJournalStatus::InvalidDirectory:
        return "invalid_directory";
    case PfEnableReferenceJournalStatus::LockFailed:
        return "lock_failed";
    case PfEnableReferenceJournalStatus::Missing:
        return "missing";
    case PfEnableReferenceJournalStatus::Present:
        return "present";
    case PfEnableReferenceJournalStatus::UnsafeFile:
        return "unsafe_file";
    case PfEnableReferenceJournalStatus::InvalidRecord:
        return "invalid_record";
    case PfEnableReferenceJournalStatus::InvalidOwner:
        return "invalid_owner";
    case PfEnableReferenceJournalStatus::OwnerConflict:
        return "owner_conflict";
    case PfEnableReferenceJournalStatus::InvalidToken:
        return "invalid_token";
    case PfEnableReferenceJournalStatus::InvalidTransition:
        return "invalid_transition";
    case PfEnableReferenceJournalStatus::VerificationUnknown:
        return "verification_unknown";
    case PfEnableReferenceJournalStatus::TokenStillActive:
        return "token_still_active";
    case PfEnableReferenceJournalStatus::IoFailed:
        return "io_failed";
    case PfEnableReferenceJournalStatus::DurabilityUncertain:
        return "durability_uncertain";
    case PfEnableReferenceJournalStatus::Persisted:
        return "persisted";
    case PfEnableReferenceJournalStatus::Cleared:
        return "cleared";
    }
    return "unknown";
}

QString PfEnableReferenceJournal::phaseName(PfEnableReferenceJournalPhase phase) {
    return QString::fromLatin1(phaseBytes(phase));
}

} // namespace interceptor
