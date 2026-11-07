#include "network/PfEnableReferenceOwner.hpp"

#include <QtTest>

#include <functional>
#include <limits>

using namespace interceptor;

namespace {
class FakePfEnableReferenceCommandRunner final : public PfEnableReferenceCommandRunner {
  public:
    struct Call {
        QString program;
        QStringList arguments;
        int timeoutMs = 0;
        qsizetype outputLimitBytes = 0;
        PfEnableReferenceOperation operation = PfEnableReferenceOperation::Acquire;
    };

    QList<PfEnableReferenceCommandResult> results;
    QVector<Call> calls;
    std::function<void()> beforeReturn;

    PfEnableReferenceCommandResult execute(const PfEnableReferenceCommand &command, int timeoutMs,
                                           qsizetype outputLimitBytes) override {
        calls.append({command.program(), command.arguments(), timeoutMs, outputLimitBytes,
                      command.operation()});
        if (results.isEmpty())
            return {};
        const auto result = results.takeFirst();
        if (beforeReturn)
            beforeReturn();
        return result;
    }
};

PfEnableReferenceCommandResult acquiredToken(const QByteArray &output = "Token : 314159\n") {
    return {PfEnableReferenceCommandStatus::Completed, 0, true, true, output};
}
} // namespace

class M6PfEnableReferenceOwnerTests : public QObject {
    Q_OBJECT

  private slots:
    void parserAcceptsOneNonzeroUnsignedDecimalToken() {
        QCOMPARE(PfEnableReferenceOwner::parseTokenOutput("Token : 314159\n"),
                 std::optional<quint64>(314159));
        QCOMPARE(PfEnableReferenceOwner::parseTokenOutput(" \tToken\t: 42 \t\r\n"),
                 std::optional<quint64>(42));
        QCOMPARE(PfEnableReferenceOwner::parseTokenOutput("Token : 18446744073709551615\n"),
                 std::optional<quint64>(std::numeric_limits<quint64>::max()));
    }

    void parserRejectsMissingDuplicateMalformedZeroAndOverflowTokens() {
        const QList<QByteArray> invalid = {{},
                                           "pfctl completed without a token\n",
                                           "Token : 0\n",
                                           "Token : 314159\nToken : 271828\n",
                                           "Token : 314159 extra\n",
                                           "Token : -1\n",
                                           "Token : 18446744073709551616\n",
                                           "Token : 314159\nadditional output\n",
                                           QByteArray("Token : 314159\n") + char(0xff),
                                           QByteArray("Token : 314159\n") + QByteArray(4097, 'x')};
        for (const auto &output : invalid)
            QVERIFY(!PfEnableReferenceOwner::parseTokenOutput(output).has_value());
    }

    void acquireUsesOnlyPfctlEnableReferenceAndCapturesToken() {
        FakePfEnableReferenceCommandRunner runner;
        runner.results.append(acquiredToken());
        PfEnableReferenceOwner owner(runner);

        const auto result = owner.acquire();

        QVERIFY(result.success);
        QVERIFY(!result.cleanupPending);
        QCOMPARE(result.statusCode, QString("acquired"));
        QCOMPARE(result.token, std::optional<quint64>(314159));
        QCOMPARE(owner.state(), PfEnableReferenceState::Owned);
        QCOMPARE(owner.recoveryToken(), std::optional<quint64>(314159));
        QCOMPARE(runner.calls.size(), 1);
        QCOMPARE(runner.calls.first().program, QString("/sbin/pfctl"));
        QCOMPARE(runner.calls.first().arguments, QStringList{"-E"});
        QCOMPARE(runner.calls.first().operation, PfEnableReferenceOperation::Acquire);
        QCOMPARE(runner.calls.first().timeoutMs, PfEnableReferenceOwner::commandTimeoutMs);
        QCOMPARE(runner.calls.first().outputLimitBytes, PfEnableReferenceOwner::maximumOutputBytes);
        QVERIFY(!result.statusCode.contains("314159"));
        QVERIFY(!runner.calls.first().arguments.contains("-d"));
    }

    void notStartedAcquireCanRetryButDoesNotCreateCleanupObligation() {
        FakePfEnableReferenceCommandRunner runner;
        runner.results.append({PfEnableReferenceCommandStatus::Failed, -1, false, true, {}});
        runner.results.append(acquiredToken());
        PfEnableReferenceOwner owner(runner);

        const auto first = owner.acquire();
        QVERIFY(!first.success);
        QVERIFY(!first.cleanupPending);
        QCOMPARE(owner.state(), PfEnableReferenceState::Unacquired);
        QVERIFY(!owner.recoveryToken().has_value());
        QCOMPARE(first.statusCode, QString("command_failed"));

        const auto second = owner.acquire();
        QVERIFY(second.success);
        QCOMPARE(runner.calls.size(), 2);
        QCOMPARE(runner.calls[0].arguments, QStringList{"-E"});
        QCOMPARE(runner.calls[1].arguments, QStringList{"-E"});
    }

    void startedAcquireWithoutUnambiguousTokenIsUncertainAndBlocksRetry() {
        FakePfEnableReferenceCommandRunner runner;
        runner.results.append({PfEnableReferenceCommandStatus::TimedOut, -1, true, true,
                               "pfctl timed out; token output unavailable"});
        PfEnableReferenceOwner owner(runner);

        const auto acquired = owner.acquire();
        QVERIFY(!acquired.success);
        QVERIFY(acquired.cleanupPending);
        QVERIFY(!acquired.token.has_value());
        QCOMPARE(acquired.statusCode, QString("acquisition_uncertain_token_unknown"));
        QCOMPARE(owner.state(), PfEnableReferenceState::AcquireUncertain);
        QVERIFY(!owner.recoveryToken().has_value());

        const auto retry = owner.acquire();
        QVERIFY(!retry.success);
        QVERIFY(retry.cleanupPending);
        QCOMPARE(retry.statusCode, QString("acquisition_uncertain"));
        QCOMPARE(owner.release().statusCode, QString("acquisition_uncertain_token_unknown"));
        QCOMPARE(runner.calls.size(), 1);
        QVERIFY(!acquired.statusCode.contains("314159"));
        QVERIFY(!retry.statusCode.contains("314159"));
    }

    void capturedTokenAfterUncertainAcquireRemainsOwnedForCleanup() {
        FakePfEnableReferenceCommandRunner runner;
        runner.results.append(
            {PfEnableReferenceCommandStatus::TimedOut, -1, true, true, "Token : 314159\n"});
        runner.results.append({PfEnableReferenceCommandStatus::Completed, 0, true, true, {}});
        PfEnableReferenceOwner owner(runner);

        const auto acquired = owner.acquire();
        QVERIFY(!acquired.success);
        QVERIFY(acquired.cleanupPending);
        QCOMPARE(acquired.statusCode, QString("acquisition_uncertain_token_captured"));
        QCOMPARE(owner.state(), PfEnableReferenceState::Owned);
        QCOMPARE(owner.recoveryToken(), std::optional<quint64>(314159));

        const auto released = owner.release();
        QVERIFY(released.success);
        QCOMPARE(runner.calls.size(), 2);
        QCOMPARE(runner.calls.last().arguments, (QStringList{"-X", "314159"}));
        QCOMPARE(owner.state(), PfEnableReferenceState::Released);
        QVERIFY(!owner.recoveryToken().has_value());
    }

    void unreapedAcquireRetainsTokenButBlocksReleaseCommands() {
        FakePfEnableReferenceCommandRunner runner;
        runner.results.append(
            {PfEnableReferenceCommandStatus::TimedOut, -1, true, false, "Token : 314159\n"});
        PfEnableReferenceOwner owner(runner);

        const auto acquired = owner.acquire();

        QVERIFY(!acquired.success);
        QVERIFY(acquired.cleanupPending);
        QCOMPARE(acquired.statusCode, QString("acquisition_uncertain_token_captured"));
        QCOMPARE(owner.state(), PfEnableReferenceState::AcquireUncertain);
        QCOMPARE(owner.recoveryToken(), std::optional<quint64>(314159));
        const auto release = owner.release();
        QVERIFY(!release.success);
        QVERIFY(release.cleanupPending);
        QCOMPARE(release.statusCode, QString("acquisition_uncertain_token_captured"));
        QCOMPARE(runner.calls.size(), 1);
        QCOMPARE(runner.calls.first().arguments, QStringList{"-E"});
    }

    void reentrantAcquireDoesNotIssueSecondEnableReferenceCommand() {
        FakePfEnableReferenceCommandRunner runner;
        runner.results.append(acquiredToken());
        PfEnableReferenceOwner owner(runner);
        PfEnableReferenceResult nested;
        runner.beforeReturn = [&]() { nested = owner.acquire(); };

        const auto acquired = owner.acquire();

        QVERIFY(acquired.success);
        QVERIFY(!nested.success);
        QCOMPARE(nested.statusCode, QString("acquisition_in_progress"));
        QCOMPARE(owner.state(), PfEnableReferenceState::Owned);
        QCOMPARE(runner.calls.size(), 1);
        QCOMPARE(runner.calls.first().arguments, QStringList{"-E"});
    }

    void releaseUsesOnlyCapturedTokenAndCanBeIssuedAtMostOnce() {
        FakePfEnableReferenceCommandRunner runner;
        runner.results.append(acquiredToken());
        runner.results.append({PfEnableReferenceCommandStatus::Completed, 0, true, true, {}});
        PfEnableReferenceOwner owner(runner);
        QVERIFY(owner.acquire().success);

        const auto released = owner.release();
        QVERIFY(released.success);
        QVERIFY(!released.cleanupPending);
        QCOMPARE(released.statusCode, QString("released"));
        QCOMPARE(runner.calls.size(), 2);
        QCOMPARE(runner.calls.last().program, QString("/sbin/pfctl"));
        QCOMPARE(runner.calls.last().arguments, (QStringList{"-X", "314159"}));
        QCOMPARE(runner.calls.last().operation, PfEnableReferenceOperation::Release);
        QVERIFY(!runner.calls.last().arguments.contains("-d"));
        QCOMPARE(owner.state(), PfEnableReferenceState::Released);
        QVERIFY(!owner.recoveryToken().has_value());

        const auto repeated = owner.release();
        QVERIFY(!repeated.success);
        QCOMPARE(repeated.statusCode, QString("already_released"));
        QCOMPARE(runner.calls.size(), 2);
    }

    void attemptedReleaseFailureRetainsTokenAndBlocksDuplicateRelease() {
        FakePfEnableReferenceCommandRunner runner;
        runner.results.append(acquiredToken());
        runner.results.append({PfEnableReferenceCommandStatus::TimedOut, -1, true, false, {}});
        PfEnableReferenceOwner owner(runner);
        QVERIFY(owner.acquire().success);

        const auto released = owner.release();
        QVERIFY(!released.success);
        QVERIFY(released.cleanupPending);
        QCOMPARE(released.statusCode, QString("release_uncertain_timed_out"));
        QCOMPARE(owner.state(), PfEnableReferenceState::ReleaseUncertain);
        QCOMPARE(owner.recoveryToken(), std::optional<quint64>(314159));
        QVERIFY(!released.statusCode.contains("314159"));

        const auto retry = owner.release();
        QVERIFY(!retry.success);
        QVERIFY(retry.cleanupPending);
        QCOMPARE(retry.statusCode, QString("release_already_attempted"));
        QCOMPARE(runner.calls.size(), 2);
        QCOMPARE(runner.calls.last().arguments, (QStringList{"-X", "314159"}));
    }
};

QTEST_GUILESS_MAIN(M6PfEnableReferenceOwnerTests)
#include "M6PfEnableReferenceOwnerTests.moc"
