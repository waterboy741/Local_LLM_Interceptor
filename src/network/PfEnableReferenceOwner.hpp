#pragma once

#include <QByteArray>
#include <QString>
#include <QStringList>
#include <optional>

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

class PfEnableReferenceReleaseReceipt {
  public:
    quint64 token() const { return token_; }

  private:
    explicit PfEnableReferenceReleaseReceipt(quint64 token) : token_(token) {}
    quint64 token_;
    friend class PfEnableReferenceOwner;
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
    std::optional<PfEnableReferenceReleaseReceipt> releaseReceipt;
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
    PfEnableReferenceState state() const { return state_; }
    std::optional<quint64> recoveryToken() const { return token_; }

    static std::optional<quint64> parseTokenOutput(const QByteArray &output);

  private:
    PfEnableReferenceCommandRunner &runner_;
    PfEnableReferenceState state_ = PfEnableReferenceState::Unacquired;
    std::optional<quint64> token_;
};

} // namespace interceptor
