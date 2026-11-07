#include "network/PfEnableReferenceQProcessRunner.hpp"

#include <QThread>
#include <QtTest>

#include <memory>
#include <utility>

using namespace interceptor;

namespace {
struct FakeChildState {
    bool startSucceeds = true;
    bool startedDespiteFailure = false;
    bool processStarted = false;
    bool running = false;
    bool killed = false;
    bool reaped = false;
    bool writeClosed = false;
    bool holdOpen = false;
    bool abnormalExit = false;
    bool failedWhileRunning = false;
    bool reapSucceeds = true;
    int exitCode = 0;
    int startTimeoutMs = 0;
    int reapTimeoutMs = 0;
    int waitForReadCalls = 0;
    QByteArray stdoutBytes;
    QByteArray stderrBytes;
    qsizetype stdoutBytesRead = 0;
    qsizetype stderrBytesRead = 0;
};

class FakeChildProcess final : public PfEnableReferenceChildProcess {
  public:
    explicit FakeChildProcess(std::shared_ptr<FakeChildState> state) : state_(std::move(state)) {}

    bool start(int timeoutMs) override {
        state_->startTimeoutMs = timeoutMs;
        state_->processStarted = state_->startSucceeds || state_->startedDespiteFailure;
        state_->running = state_->processStarted;
        return state_->startSucceeds;
    }
    bool started() const override { return state_->processStarted; }
    void closeWriteChannel() override { state_->writeClosed = true; }
    bool waitForReadyRead(int timeoutMs) override {
        ++state_->waitForReadCalls;
        if (state_->holdOpen) {
            QThread::msleep(static_cast<unsigned long>(timeoutMs));
            return false;
        }
        if (!state_->failedWhileRunning)
            state_->running = false;
        return true;
    }
    QByteArray readStandardOutput(qint64 maximumBytes) override {
        const auto bytes = take(&state_->stdoutBytes, maximumBytes);
        state_->stdoutBytesRead += bytes.size();
        return bytes;
    }
    QByteArray readStandardError(qint64 maximumBytes) override {
        const auto bytes = take(&state_->stderrBytes, maximumBytes);
        state_->stderrBytesRead += bytes.size();
        return bytes;
    }
    bool isRunning() const override { return state_->running; }
    bool normalExit() const override { return !state_->abnormalExit; }
    int exitCode() const override { return state_->exitCode; }
    bool failed() const override { return state_->failedWhileRunning; }
    void kill() override {
        state_->killed = true;
        if (state_->reapSucceeds)
            state_->running = false;
    }
    bool waitForFinished(int timeoutMs) override {
        state_->reapTimeoutMs = timeoutMs;
        if (state_->reapSucceeds) {
            state_->running = false;
            state_->reaped = true;
        }
        return state_->reapSucceeds;
    }

  private:
    static QByteArray take(QByteArray *bytes, qint64 maximumBytes) {
        const auto count = qMin<qsizetype>(bytes->size(), static_cast<qsizetype>(maximumBytes));
        const auto result = bytes->left(count);
        bytes->remove(0, count);
        return result;
    }

    std::shared_ptr<FakeChildState> state_;
};

class FakeChildFactory final : public PfEnableReferenceChildProcessFactory {
  public:
    QVector<std::shared_ptr<FakeChildState>> preparedStates;
    QVector<std::shared_ptr<FakeChildState>> states;
    QStringList programs;
    QVector<QStringList> arguments;

    std::unique_ptr<PfEnableReferenceChildProcess>
    create(const PfEnableReferenceCommand &command) override {
        const auto index = states.size();
        auto state = index < preparedStates.size() ? preparedStates[index]
                                                   : std::make_shared<FakeChildState>();
        states.append(state);
        programs.append(command.program());
        arguments.append(command.arguments());
        return std::make_unique<FakeChildProcess>(state);
    }
};

class CapturingPfRunner final : public PfEnableReferenceCommandRunner {
  public:
    QProcessPfEnableReferenceCommandRunner &runner;
    std::optional<PfEnableReferenceCommand> command;
    PfEnableReferenceCommandResult result;

    explicit CapturingPfRunner(QProcessPfEnableReferenceCommandRunner &value) : runner(value) {}
    PfEnableReferenceCommandResult execute(const PfEnableReferenceCommand &value, int timeoutMs,
                                           qsizetype outputLimitBytes) override {
        command = value;
        result = runner.execute(value, timeoutMs, outputLimitBytes);
        return result;
    }
};
} // namespace

class M6PfEnableReferenceQProcessRunnerTests : public QObject {
    Q_OBJECT

  private slots:
    void acquireAndReleaseUseOnlyFixedPfctlArguments() {
        FakeChildFactory factory;
        auto acquireState = std::make_shared<FakeChildState>();
        acquireState->stdoutBytes = "Token : 73\n";
        auto releaseState = std::make_shared<FakeChildState>();
        factory.preparedStates = {acquireState, releaseState};
        QProcessPfEnableReferenceCommandRunner runner(factory);
        PfEnableReferenceOwner owner(runner);

        const auto acquired = owner.acquire();

        QVERIFY(acquired.success);
        QCOMPARE(acquired.token, std::optional<quint64>(73));
        const auto released = owner.release();
        QVERIFY(released.success);
        QCOMPARE(factory.programs, (QStringList{"/sbin/pfctl", "/sbin/pfctl"}));
        QCOMPARE(factory.arguments,
                 (QVector<QStringList>{QStringList{"-E"}, QStringList{"-X", "73"}}));
        QVERIFY(factory.states.first()->writeClosed);
        QVERIFY(factory.states.first()->reaped);
        QVERIFY(!factory.states.first()->killed);
        QCOMPARE(factory.states.first()->startTimeoutMs,
                 QProcessPfEnableReferenceCommandRunner::commandTimeoutMs);
        QVERIFY(!factory.arguments.first().contains("-d"));
        QVERIFY(!factory.arguments.last().contains("-d"));
        QVERIFY(factory.states.last()->writeClosed);
        QVERIFY(factory.states.last()->reaped);
        QCOMPARE(released.releaseReceipt->token(), quint64(73));
    }

    void startFailureAndAmbiguousStartedFailureAreReportedSafely() {
        {
            FakeChildFactory factory;
            auto state = std::make_shared<FakeChildState>();
            state->startSucceeds = false;
            factory.preparedStates = {state};
            QProcessPfEnableReferenceCommandRunner processRunner(factory);
            CapturingPfRunner runner(processRunner);
            PfEnableReferenceOwner owner(runner);

            const auto result = owner.acquire();

            QVERIFY(!result.success);
            QCOMPARE(runner.result.status, PfEnableReferenceCommandStatus::Failed);
            QVERIFY(!runner.result.started);
            QVERIFY(!runner.result.processReaped);
            QVERIFY(!state->killed);
        }
        {
            FakeChildFactory factory;
            auto state = std::make_shared<FakeChildState>();
            state->startSucceeds = false;
            state->startedDespiteFailure = true;
            factory.preparedStates = {state};
            QProcessPfEnableReferenceCommandRunner processRunner(factory);
            CapturingPfRunner runner(processRunner);
            PfEnableReferenceOwner owner(runner);

            const auto result = owner.acquire();

            QVERIFY(!result.success);
            QCOMPARE(runner.result.status, PfEnableReferenceCommandStatus::Failed);
            QVERIFY(runner.result.started);
            QVERIFY(runner.result.processReaped);
            QVERIFY(state->killed);
            QVERIFY(state->reaped);
        }
    }

    void combinedOutputOverflowKillsAndReapsChild() {
        FakeChildFactory factory;
        auto state = std::make_shared<FakeChildState>();
        state->stdoutBytes =
            QByteArray(QProcessPfEnableReferenceCommandRunner::maximumOutputBytes, 'a');
        state->stderrBytes = "b";
        factory.preparedStates = {state};
        QProcessPfEnableReferenceCommandRunner processRunner(factory);
        CapturingPfRunner runner(processRunner);
        PfEnableReferenceOwner owner(runner);

        const auto result = owner.acquire();

        QVERIFY(!result.success);
        QCOMPARE(runner.result.status, PfEnableReferenceCommandStatus::OutputLimitExceeded);
        QVERIFY(runner.result.started);
        QVERIFY(runner.result.processReaped);
        QVERIFY(state->killed);
        QVERIFY(state->reaped);
    }

    void timeoutKillsAndReapsBeforeReturning() {
        FakeChildFactory factory;
        auto state = std::make_shared<FakeChildState>();
        state->holdOpen = true;
        factory.preparedStates = {state};
        QProcessPfEnableReferenceCommandRunner processRunner(factory);
        CapturingPfRunner runner(processRunner);
        PfEnableReferenceOwner owner(runner);

        const auto result = owner.acquire();

        QVERIFY(!result.success);
        QCOMPARE(runner.result.status, PfEnableReferenceCommandStatus::TimedOut);
        QVERIFY(runner.result.started);
        QVERIFY(runner.result.processReaped);
        QVERIFY(state->killed);
        QVERIFY(state->reaped);
        QCOMPARE(state->reapTimeoutMs, QProcessPfEnableReferenceCommandRunner::reapTimeoutMs);
    }

    void stderrPermissionAndNonzeroExitClassifyWithoutLeakingDiagnostics() {
        FakeChildFactory factory;
        auto state = std::make_shared<FakeChildState>();
        state->exitCode = 1;
        state->stderrBytes = "pfctl: Operation not permitted: private token 73";
        factory.preparedStates = {state};
        QProcessPfEnableReferenceCommandRunner processRunner(factory);
        CapturingPfRunner runner(processRunner);
        PfEnableReferenceOwner owner(runner);

        const auto result = owner.acquire();

        QVERIFY(!result.success);
        QCOMPARE(runner.result.status, PfEnableReferenceCommandStatus::PermissionDenied);
        QCOMPARE(runner.result.exitCode, 1);
        QVERIFY(runner.result.standardOutput.isEmpty());
        QVERIFY(!result.statusCode.contains("73"));
    }

    void normalNonzeroExitIsReturnedForOwnerToFailClosed() {
        FakeChildFactory factory;
        auto state = std::make_shared<FakeChildState>();
        state->exitCode = 2;
        factory.preparedStates = {state};
        QProcessPfEnableReferenceCommandRunner processRunner(factory);
        CapturingPfRunner runner(processRunner);
        PfEnableReferenceOwner owner(runner);

        const auto result = owner.acquire();

        QVERIFY(!result.success);
        QCOMPARE(runner.result.status, PfEnableReferenceCommandStatus::Completed);
        QCOMPARE(runner.result.exitCode, 2);
        QVERIFY(runner.result.started);
        QVERIFY(runner.result.processReaped);
        QCOMPARE(result.statusCode, QString("acquisition_uncertain_token_unknown"));
    }

    void abnormalExitAndOutputBoundsAreReturnedWithoutReleasingOrDisablingPf() {
        FakeChildFactory factory;
        auto state = std::make_shared<FakeChildState>();
        state->abnormalExit = true;
        factory.preparedStates = {state};
        QProcessPfEnableReferenceCommandRunner processRunner(factory);
        CapturingPfRunner runner(processRunner);
        PfEnableReferenceOwner owner(runner);

        const auto result = owner.acquire();

        QVERIFY(!result.success);
        QCOMPARE(runner.result.status, PfEnableReferenceCommandStatus::Failed);
        QVERIFY(runner.result.started);
        QVERIFY(runner.result.processReaped);
        QVERIFY(!factory.arguments.first().contains("-d"));
        QCOMPARE(factory.arguments.first(), QStringList{"-E"});
        QCOMPARE(state->startTimeoutMs, QProcessPfEnableReferenceCommandRunner::commandTimeoutMs);
        QVERIFY(state->writeClosed);
    }

    void runnerRejectsNoncanonicalTimeoutAndOutputBoundsWithoutStartingChild() {
        FakeChildFactory factory;
        auto state = std::make_shared<FakeChildState>();
        state->stdoutBytes = "Token : 73\n";
        factory.preparedStates = {state};
        QProcessPfEnableReferenceCommandRunner processRunner(factory);
        CapturingPfRunner runner(processRunner);
        PfEnableReferenceOwner owner(runner);
        QVERIFY(owner.acquire().success);
        QVERIFY(runner.command.has_value());

        const auto invalidTimeout = processRunner.execute(
            *runner.command, QProcessPfEnableReferenceCommandRunner::commandTimeoutMs - 1,
            QProcessPfEnableReferenceCommandRunner::maximumOutputBytes);
        QVERIFY(!invalidTimeout.started);
        const auto invalidLimit = processRunner.execute(
            *runner.command, QProcessPfEnableReferenceCommandRunner::commandTimeoutMs,
            QProcessPfEnableReferenceCommandRunner::maximumOutputBytes - 1);
        QVERIFY(!invalidLimit.started);
        QCOMPARE(factory.states.size(), 1);
    }

    void unreapedChildFailurePropagatesWithoutClaimingReap() {
        FakeChildFactory factory;
        auto state = std::make_shared<FakeChildState>();
        state->failedWhileRunning = true;
        state->reapSucceeds = false;
        factory.preparedStates = {state};
        QProcessPfEnableReferenceCommandRunner processRunner(factory);
        CapturingPfRunner runner(processRunner);
        PfEnableReferenceOwner owner(runner);

        const auto result = owner.acquire();

        QVERIFY(!result.success);
        QVERIFY(result.cleanupPending);
        QCOMPARE(runner.result.status, PfEnableReferenceCommandStatus::Failed);
        QVERIFY(runner.result.started);
        QVERIFY(!runner.result.processReaped);
        QVERIFY(state->killed);
        QVERIFY(!state->reaped);
        QVERIFY(state->running);
        QCOMPARE(state->reapTimeoutMs, QProcessPfEnableReferenceCommandRunner::reapTimeoutMs);
    }
};

QTEST_GUILESS_MAIN(M6PfEnableReferenceQProcessRunnerTests)
#include "M6PfEnableReferenceQProcessRunnerTests.moc"
