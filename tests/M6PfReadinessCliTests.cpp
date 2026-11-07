#include "network/PfReadinessCli.hpp"

#include <QJsonDocument>
#include <QMap>
#include <QtTest>

using namespace interceptor;

namespace {
class FakePfCommandRunner final : public PfCommandRunner {
  public:
    struct Call {
        PfQuery query;
        QString anchor;
        int timeoutMs;
        qsizetype outputLimitBytes;
    };

    QMap<int, PfQueryOutput> outputs;
    QVector<Call> calls;

    PfQueryOutput query(PfQuery query, const QString &sessionAnchor, int timeoutMs,
                        qsizetype outputLimitBytes) override {
        calls.append({query, sessionAnchor, timeoutMs, outputLimitBytes});
        return outputs.value(static_cast<int>(query));
    }
};

FakePfCommandRunner successfulRunner() {
    FakePfCommandRunner runner;
    runner.outputs.insert(static_cast<int>(PfQuery::Status),
                          {PfCommandStatus::Completed, 0, "Status: Enabled\n"});
    runner.outputs.insert(static_cast<int>(PfQuery::MainFilterRules),
                          {PfCommandStatus::Completed, 0, "@0 anchor \"llm_interceptor/*\" all\n"});
    runner.outputs.insert(
        static_cast<int>(PfQuery::MainTranslationRules),
        {PfCommandStatus::Completed, 0, "@0 rdr-anchor \"llm_interceptor/*\" all\n"});
    return runner;
}

QJsonObject resultJson(const PfReadinessCliResult &result) {
    QJsonParseError error;
    const auto document = QJsonDocument::fromJson(result.standardOutput.toUtf8(), &error);
    if (error.error != QJsonParseError::NoError || !document.isObject())
        qFatal("PF readiness CLI did not return a JSON object");
    return document.object();
}
} // namespace

class M6PfReadinessCliTests : public QObject {
    Q_OBJECT

  private slots:
    void successfulReadinessUsesOnlyBoundedReadOnlyQueries() {
        auto runner = successfulRunner();

        const auto result = PfReadinessCli::run({"pf_readiness"}, runner);

        QCOMPARE(result.exitCode, 0);
        QVERIFY(result.standardError.isEmpty());
        const auto json = resultJson(result);
        QCOMPARE(json.value("schema").toString(),
                 QString("llm-interceptor.pf-preinstall-readiness.v1"));
        QVERIFY(json.value("sanitized").toBool());
        QVERIFY(json.value("ready").toBool());
        QCOMPARE(json.value("status").toString(), QString("preinstall_ready"));
        QCOMPARE(json.value("timeout_ms").toInt(), PfDiagnostics::defaultTimeoutMs);
        QCOMPARE(runner.calls.size(), 3);
        const QList<PfQuery> expected = {PfQuery::Status, PfQuery::MainFilterRules,
                                         PfQuery::MainTranslationRules};
        for (qsizetype index = 0; index < runner.calls.size(); ++index) {
            QCOMPARE(runner.calls[index].query, expected[index]);
            QVERIFY(runner.calls[index].anchor.isEmpty());
            QCOMPARE(runner.calls[index].timeoutMs, PfDiagnostics::defaultTimeoutMs);
            QCOMPARE(runner.calls[index].outputLimitBytes, PfDiagnostics::maximumOutputBytes);
        }
        QCOMPARE(json.value("references_observed_only").toBool(), true);
        QCOMPARE(json.value("packet_evaluation_proven").toBool(), false);
        QVERIFY(!result.standardOutput.contains("llm_interceptor"));
        QVERIFY(!result.standardOutput.contains("pfctl"));
    }

    void explicitTimeoutIsPassedToEachQuery() {
        auto runner = successfulRunner();

        const auto result = PfReadinessCli::run({"pf_readiness", "--timeout-ms", "1250"}, runner);

        QCOMPARE(result.exitCode, 0);
        QCOMPARE(resultJson(result).value("timeout_ms").toInt(), 1250);
        QCOMPARE(runner.calls.size(), 3);
        for (const auto &call : runner.calls)
            QCOMPARE(call.timeoutMs, 1250);
    }

    void strictArgumentErrorsAndHelpDoNotQueryPf() {
        const QList<QStringList> invalidArguments = {
            {"pf_readiness", "extra"},
            {"pf_readiness", "--unknown"},
            {"pf_readiness", "--timeout-ms"},
            {"pf_readiness", "--timeout-ms", "abc"},
            {"pf_readiness", "--timeout-ms", "0"},
            {"pf_readiness", "--timeout-ms", "5001"},
            {"pf_readiness", "--timeout-ms", "100", "--timeout-ms", "200"},
            {"pf_readiness", "--timeout-ms=100", "--timeout-ms=200"}};
        for (const auto &arguments : invalidArguments) {
            auto runner = successfulRunner();
            const auto result = PfReadinessCli::run(arguments, runner);
            QCOMPARE(result.exitCode, 2);
            QVERIFY(result.standardOutput.isEmpty());
            QVERIFY(!result.standardError.isEmpty());
            QVERIFY(runner.calls.isEmpty());
        }

        for (const auto &arguments :
             {QStringList{"pf_readiness", "--help"}, QStringList{"pf_readiness", "--version"}}) {
            auto runner = successfulRunner();
            const auto result = PfReadinessCli::run(arguments, runner);
            QCOMPARE(result.exitCode, 0);
            QVERIFY(!result.standardOutput.isEmpty());
            QVERIFY(runner.calls.isEmpty());
        }
    }

    void notReadyAndCommandFailureReturnFailureWithoutLeakingOutput() {
        {
            auto runner = successfulRunner();
            runner.outputs[static_cast<int>(PfQuery::Status)].standardOutput =
                "Status: Disabled\nprivate 192.0.2.19";

            const auto result = PfReadinessCli::run({"pf_readiness"}, runner);

            QCOMPARE(result.exitCode, 1);
            const auto json = resultJson(result);
            QCOMPARE(json.value("status").toString(), QString("pf_disabled"));
            QVERIFY(!json.value("ready").toBool());
            QCOMPARE(runner.calls.size(), 1);
            QVERIFY(!result.standardOutput.contains("private"));
            QVERIFY(!result.standardOutput.contains("192.0.2.19"));
        }
        {
            auto runner = successfulRunner();
            runner.outputs[static_cast<int>(PfQuery::MainFilterRules)] = {
                PfCommandStatus::PermissionDenied, -1, "private command output for 192.0.2.19"};

            const auto result = PfReadinessCli::run({"pf_readiness"}, runner);

            QCOMPARE(result.exitCode, 1);
            const auto json = resultJson(result);
            QCOMPARE(json.value("status").toString(), QString("permission_denied"));
            QCOMPARE(runner.calls.size(), 2);
            QVERIFY(!result.standardOutput.contains("private"));
            QVERIFY(!result.standardOutput.contains("192.0.2.19"));
        }
    }
};

QTEST_GUILESS_MAIN(M6PfReadinessCliTests)
#include "M6PfReadinessCliTests.moc"
