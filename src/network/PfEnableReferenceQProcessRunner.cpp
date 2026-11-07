#include "PfEnableReferenceQProcessRunner.hpp"

#include <QElapsedTimer>
#include <QProcess>

namespace interceptor {
namespace {
const QString pfctlPath = QStringLiteral("/sbin/pfctl");

bool permissionDiagnostic(const QByteArray &diagnostic) {
    const auto lower = diagnostic.toLower();
    return lower.contains("permission denied") || lower.contains("operation not permitted") ||
           lower.contains("must be root") || lower.contains("requires root");
}

bool validTypedCommand(const PfEnableReferenceCommand &command, int timeoutMs,
                       qsizetype outputLimitBytes) {
    if (command.program() != pfctlPath ||
        timeoutMs != QProcessPfEnableReferenceCommandRunner::commandTimeoutMs ||
        outputLimitBytes != QProcessPfEnableReferenceCommandRunner::maximumOutputBytes)
        return false;
    const auto args = command.arguments();
    if (command.operation() == PfEnableReferenceOperation::Acquire)
        return args == QStringList{"-E"};
    if (args.size() != 2 || args[0] != QStringLiteral("-X"))
        return false;
    bool valid = false;
    const auto token = args[1].toULongLong(&valid, 10);
    return valid && token != 0 && QString::number(token) == args[1];
}

class QProcessPfEnableReferenceChild final : public PfEnableReferenceChildProcess {
  public:
    explicit QProcessPfEnableReferenceChild(const PfEnableReferenceCommand &command)
        : program_(command.program()), arguments_(command.arguments()) {
        process_.setProcessChannelMode(QProcess::SeparateChannels);
        QObject::connect(&process_, &QProcess::started, &process_, [this] { startedEver_ = true; });
    }
    bool start(int timeoutMs) override {
        process_.start(program_, arguments_, QIODevice::ReadOnly);
        return process_.waitForStarted(timeoutMs);
    }
    bool started() const override {
        return startedEver_ || process_.state() != QProcess::NotRunning;
    }
    void closeWriteChannel() override { process_.closeWriteChannel(); }
    bool waitForReadyRead(int timeoutMs) override { return process_.waitForReadyRead(timeoutMs); }
    QByteArray readStandardOutput(qint64 maximumBytes) override {
        return process_.read(maximumBytes);
    }
    QByteArray readStandardError(qint64 maximumBytes) override {
        process_.setReadChannel(QProcess::StandardError);
        const auto bytes = process_.read(maximumBytes);
        process_.setReadChannel(QProcess::StandardOutput);
        return bytes;
    }
    bool isRunning() const override { return process_.state() != QProcess::NotRunning; }
    bool normalExit() const override { return process_.exitStatus() == QProcess::NormalExit; }
    int exitCode() const override { return process_.exitCode(); }
    bool failed() const override {
        return process_.error() != QProcess::UnknownError && process_.error() != QProcess::Timedout;
    }
    void kill() override { process_.kill(); }
    bool waitForFinished(int timeoutMs) override { return process_.waitForFinished(timeoutMs); }

  private:
    QString program_;
    QStringList arguments_;
    QProcess process_;
    bool startedEver_ = false;
};

class QProcessPfEnableReferenceChildFactory final : public PfEnableReferenceChildProcessFactory {
  public:
    std::unique_ptr<PfEnableReferenceChildProcess>
    create(const PfEnableReferenceCommand &command) override {
#if defined(Q_OS_MACOS)
        return std::make_unique<QProcessPfEnableReferenceChild>(command);
#else
        Q_UNUSED(command);
        return {};
#endif
    }
};

int remainingMs(const QElapsedTimer &timer) {
    return qMax(0, QProcessPfEnableReferenceCommandRunner::commandTimeoutMs -
                       static_cast<int>(timer.elapsed()));
}
} // namespace

QProcessPfEnableReferenceCommandRunner::QProcessPfEnableReferenceCommandRunner()
    : ownedFactory_(std::make_unique<QProcessPfEnableReferenceChildFactory>()),
      factory_(ownedFactory_.get()) {}

QProcessPfEnableReferenceCommandRunner::QProcessPfEnableReferenceCommandRunner(
    PfEnableReferenceChildProcessFactory &factory)
    : factory_(&factory) {}

PfEnableReferenceCommandResult
QProcessPfEnableReferenceCommandRunner::execute(const PfEnableReferenceCommand &command,
                                                int timeoutMs, qsizetype outputLimitBytes) {
    if (!validTypedCommand(command, timeoutMs, outputLimitBytes))
        return {};
    std::unique_ptr<PfEnableReferenceChildProcess> child;
    try {
        child = factory_->create(command);
    } catch (...) {
        return {};
    }
    if (!child)
        return {};

    QElapsedTimer elapsed;
    elapsed.start();
    PfEnableReferenceCommandResult result;
    qsizetype observedBytes = 0;
    bool permissionDenied = false;
    const auto collect = [&]() {
        const auto remaining = outputLimitBytes - observedBytes;
        const auto stdoutChunk = child->readStandardOutput(remaining + 1);
        if (stdoutChunk.size() > remaining)
            return PfEnableReferenceCommandStatus::OutputLimitExceeded;
        const auto stderrChunk = child->readStandardError(remaining - stdoutChunk.size() + 1);
        const auto added = stdoutChunk.size() + stderrChunk.size();
        if (added > remaining)
            return PfEnableReferenceCommandStatus::OutputLimitExceeded;
        observedBytes += added;
        result.standardOutput += stdoutChunk;
        permissionDenied = permissionDenied || permissionDiagnostic(stderrChunk);
        return PfEnableReferenceCommandStatus::Completed;
    };
    const auto terminate = [&](PfEnableReferenceCommandStatus status) {
        child->kill();
        result.processReaped = child->waitForFinished(reapTimeoutMs) || !child->isRunning();
        result.started = result.started || child->started();
        result.exitCode = child->exitCode();
        result.status = result.processReaped ? status : PfEnableReferenceCommandStatus::Failed;
        return result;
    };

    const bool started = child->start(remainingMs(elapsed));
    result.started = child->started();
    if (!started) {
        if (result.started)
            return terminate(remainingMs(elapsed) <= 0 ? PfEnableReferenceCommandStatus::TimedOut
                                                       : PfEnableReferenceCommandStatus::Failed);
        result.status = remainingMs(elapsed) <= 0 ? PfEnableReferenceCommandStatus::TimedOut
                                                  : PfEnableReferenceCommandStatus::Failed;
        return result;
    }
    result.started = true;
    child->closeWriteChannel();

    while (child->isRunning()) {
        const auto remaining = remainingMs(elapsed);
        if (remaining <= 0)
            return terminate(PfEnableReferenceCommandStatus::TimedOut);
        child->waitForReadyRead(qMin(remaining, 50));
        const auto status = collect();
        if (status != PfEnableReferenceCommandStatus::Completed)
            return terminate(status);
        if (child->failed() && child->isRunning())
            return terminate(PfEnableReferenceCommandStatus::Failed);
    }
    const auto collectStatus = collect();
    if (collectStatus != PfEnableReferenceCommandStatus::Completed)
        return terminate(collectStatus);
    result.processReaped = child->waitForFinished(reapTimeoutMs) || !child->isRunning();
    result.exitCode = child->exitCode();
    if (!result.processReaped) {
        result.status = PfEnableReferenceCommandStatus::Failed;
        return result;
    }
    result.status = child->normalExit() && result.exitCode != 0 && permissionDenied
                        ? PfEnableReferenceCommandStatus::PermissionDenied
                        : (child->normalExit() ? PfEnableReferenceCommandStatus::Completed
                                               : PfEnableReferenceCommandStatus::Failed);
    return result;
}

} // namespace interceptor
