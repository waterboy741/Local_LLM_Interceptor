#pragma once

#include <QByteArray>
#include <QString>
#include <QStringList>
#include <optional>
#include <utility>

namespace interceptor {

enum class PfEnableReferenceOperation { Acquire, Release };
enum class PfEnableReferenceCommandStatus {
    Completed,
    PermissionDenied,
    TimedOut,
    OutputLimitExceeded,
    Failed
};

class PfEnableReferenceCommand {
  public:
    PfEnableReferenceOperation operation() const { return operation_; }
    QString program() const;
    QStringList arguments() const;

  private:
    explicit PfEnableReferenceCommand(PfEnableReferenceOperation operation, quint64 token = 0)
        : operation_(operation), token_(token) {}
    PfEnableReferenceOperation operation_;
    quint64 token_;
    friend class PfEnableReferenceOwner;
};

struct PfEnableReferenceCommandResult {
    PfEnableReferenceCommandStatus status = PfEnableReferenceCommandStatus::Failed;
    int exitCode = -1;
    bool started = false;
    bool processReaped = false;
    QByteArray standardOutput;
};

class PfEnableReferenceAcquireNotStartedReceipt {
  private:
    PfEnableReferenceAcquireNotStartedReceipt() = default;
    friend class PfEnableReferenceOwner;
};

class PfEnableReferenceReleaseReceipt {
  public:
    quint64 token() const { return token_; }

  private:
    explicit PfEnableReferenceReleaseReceipt(quint64 token) : token_(token) {}
    quint64 token_;
    friend class PfEnableReferenceOwner;
};

class PfEnableReferenceRecoveryToken {
  public:
    quint64 token() const { return token_; }
    QString sessionId() const { return sessionId_; }

  private:
    PfEnableReferenceRecoveryToken(QString sessionId, quint64 token)
        : sessionId_(std::move(sessionId)), token_(token) {}
    QString sessionId_;
    quint64 token_;
    friend class PfEnableReferenceRecoveryCoordinator;
};

class PfEnableReferenceCommandRunner {
  public:
    virtual ~PfEnableReferenceCommandRunner() = default;
    virtual PfEnableReferenceCommandResult execute(const PfEnableReferenceCommand &command,
                                                   int timeoutMs, qsizetype outputLimitBytes) = 0;
};

enum class PfEnableReferenceState {
    Unacquired,
    Acquiring,
    AcquireUncertain,
    Owned,
    ReleaseUncertain,
    Released
};

struct PfEnableReferenceResult {
    bool success = false;
    bool cleanupPending = false;
    QString statusCode;
    std::optional<quint64> token;
    std::optional<PfEnableReferenceAcquireNotStartedReceipt> acquireNotStartedReceipt;
    std::optional<PfEnableReferenceReleaseReceipt> releaseReceipt;

    PfEnableReferenceResult(
        bool succeeded = false, bool pending = false, QString status = {},
        std::optional<quint64> ownedToken = std::nullopt,
        std::optional<PfEnableReferenceAcquireNotStartedReceipt> notStarted = std::nullopt,
        std::optional<PfEnableReferenceReleaseReceipt> released = std::nullopt)
        : success(succeeded), cleanupPending(pending), statusCode(std::move(status)),
          token(ownedToken), acquireNotStartedReceipt(std::move(notStarted)),
          releaseReceipt(std::move(released)) {}
};

class PfEnableReferenceOwner {
  public:
    static constexpr int commandTimeoutMs = 3000;
    static constexpr qsizetype maximumOutputBytes = 4096;

    // This state holder is confined to one serialized owner thread. State is marked before runner
    // calls so synchronous reentry cannot issue duplicate enable/release commands.
    explicit PfEnableReferenceOwner(PfEnableReferenceCommandRunner &runner) : runner_(runner) {}
    PfEnableReferenceResult acquire();
    PfEnableReferenceResult release();
    bool adoptRecoveredToken(const PfEnableReferenceRecoveryToken &recoveryToken);
    PfEnableReferenceState state() const { return state_; }
    std::optional<quint64> recoveryToken() const { return token_; }

    static std::optional<quint64> parseTokenOutput(const QByteArray &output);

  private:
    PfEnableReferenceCommandRunner &runner_;
    PfEnableReferenceState state_ = PfEnableReferenceState::Unacquired;
    std::optional<quint64> token_;
};

} // namespace interceptor
