#pragma once

#include "PfEnableReferenceOwner.hpp"

#include <memory>

namespace interceptor {

class PfEnableReferenceChildProcess {
  public:
    virtual ~PfEnableReferenceChildProcess() = default;
    virtual bool start(int timeoutMs) = 0;
    virtual bool started() const = 0;
    virtual void closeWriteChannel() = 0;
    virtual bool waitForReadyRead(int timeoutMs) = 0;
    virtual QByteArray readStandardOutput(qint64 maximumBytes) = 0;
    virtual QByteArray readStandardError(qint64 maximumBytes) = 0;
    virtual bool isRunning() const = 0;
    virtual bool normalExit() const = 0;
    virtual int exitCode() const = 0;
    virtual bool failed() const = 0;
    virtual void kill() = 0;
    virtual bool waitForFinished(int timeoutMs) = 0;
};

class PfEnableReferenceChildProcessFactory {
  public:
    virtual ~PfEnableReferenceChildProcessFactory() = default;
    virtual std::unique_ptr<PfEnableReferenceChildProcess>
    create(const PfEnableReferenceCommand &command) = 0;
};

class QProcessPfEnableReferenceCommandRunner final : public PfEnableReferenceCommandRunner {
  public:
    static constexpr int commandTimeoutMs = 3000;
    static constexpr int reapTimeoutMs = 1000;
    static constexpr qsizetype maximumOutputBytes = 4096;

    QProcessPfEnableReferenceCommandRunner();
    explicit QProcessPfEnableReferenceCommandRunner(PfEnableReferenceChildProcessFactory &factory);
    PfEnableReferenceCommandResult execute(const PfEnableReferenceCommand &command, int timeoutMs,
                                           qsizetype outputLimitBytes) override;

  private:
    std::unique_ptr<PfEnableReferenceChildProcessFactory> ownedFactory_;
    PfEnableReferenceChildProcessFactory *factory_ = nullptr;
};

} // namespace interceptor
