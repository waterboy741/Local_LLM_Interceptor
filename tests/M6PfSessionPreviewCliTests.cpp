#include "network/PfSessionPreviewCli.hpp"

#include <QJsonDocument>
#include <QJsonObject>
#include <QtTest>

using namespace interceptor;

namespace {
const QStringList validArguments{QStringLiteral("pf_session_preview"),
                                 QStringLiteral("--interface"),
                                 QStringLiteral("en0"),
                                 QStringLiteral("--client-ip"),
                                 QStringLiteral("192.0.2.10"),
                                 QStringLiteral("--server-ip"),
                                 QStringLiteral("192.0.2.30"),
                                 QStringLiteral("--server-port"),
                                 QStringLiteral("11434"),
                                 QStringLiteral("--listen-port"),
                                 QStringLiteral("45678"),
                                 QStringLiteral("--research-ip"),
                                 QStringLiteral("192.0.2.20"),
                                 QStringLiteral("--research-mac"),
                                 QStringLiteral("02:00:00:00:00:20"),
                                 QStringLiteral("--client-mac"),
                                 QStringLiteral("02:00:00:00:00:10"),
                                 QStringLiteral("--server-mac"),
                                 QStringLiteral("02:00:00:00:00:30"),
                                 QStringLiteral("--prefix-length"),
                                 QStringLiteral("24"),
                                 QStringLiteral("--session-id"),
                                 QStringLiteral("demo_preview_1")};

class FakePfSyntaxCheckRunner final : public PfSyntaxCheckRunner {
  public:
    int calls = 0;
    QByteArray checkedRules;
    PfSyntaxCheckStatus nextStatus = PfSyntaxCheckStatus::Valid;

    PfSyntaxCheckStatus check(const QByteArray &rules) override {
        ++calls;
        checkedRules = rules;
        return nextStatus;
    }
};

QJsonObject report(const PfAttachmentPreparationResult &result) {
    QJsonParseError error;
    const auto document = QJsonDocument::fromJson(result.standardError.toUtf8(), &error);
    if (error.error != QJsonParseError::NoError || !document.isObject())
        qFatal("PF session preview CLI did not return a JSON object");
    return document.object();
}

QStringList withValue(QStringList arguments, const QString &option, const QString &value) {
    const auto index = arguments.indexOf(option);
    Q_ASSERT(index >= 0 && index + 1 < arguments.size());
    arguments[index + 1] = value;
    return arguments;
}

QStringList withExtra(QStringList arguments, const QString &value) {
    arguments.append(value);
    return arguments;
}
} // namespace

class M6PfSessionPreviewCliTests final : public QObject {
    Q_OBJECT

  private slots:
    void validPreviewEmitsExactSessionRulesAndOnlySyntaxChecksThem() {
        FakePfSyntaxCheckRunner runner;
        const auto result = PfSessionPreviewCli::run(validArguments, runner);
        const QByteArray expectedRules(
            "rdr on \"en0\" inet proto tcp from 192.0.2.10 to 192.0.2.30 port 11434 -> "
            "127.0.0.1 port 45678\n"
            "pass in quick on \"en0\" inet proto tcp from 192.0.2.10 to 127.0.0.1 port "
            "45678 flags S/SA keep state label \"llm_demo_preview_1\"\n"
            "pass out quick on \"en0\" inet proto tcp from 192.0.2.20 to 192.0.2.30 port "
            "11434 flags S/SA keep state label \"llm_demo_preview_1\"\n");

        QCOMPARE(result.exitCode, 0);
        QCOMPARE(result.standardOutput.toUtf8(), expectedRules);
        QCOMPARE(runner.calls, 1);
        QCOMPARE(runner.checkedRules, expectedRules);
        const auto json = report(result);
        QCOMPARE(json.value("schema").toString(),
                 QStringLiteral("llm-interceptor.pf-session-preview.v1"));
        QVERIFY(json.value("sanitized").toBool());
        QCOMPARE(json.value("status").toString(), QStringLiteral("syntax_validated"));
        QVERIFY(json.value("syntax_validated").toBool());
        QVERIFY(json.value("rules_emitted").toBool());
        QCOMPARE(json.value("anchor").toString(), QStringLiteral("llm_interceptor/demo_preview_1"));
        QCOMPARE(json.value("loaded").toBool(), false);
        QCOMPARE(json.value("pf_enabled_changed").toBool(), false);
        QCOMPARE(json.value("global_rules_changed").toBool(), false);
        QCOMPARE(json.value("arp_changed").toBool(), false);
        QVERIFY(!result.standardError.contains("pfctl"));
        QVERIFY(!result.standardError.contains("/etc/pf.conf"));
        QVERIFY(!runner.checkedRules.contains("inet from 192.0.2.10 to 192.0.2.30 "));
        QVERIFY(!runner.checkedRules.contains("inet from 192.0.2.30 to 192.0.2.10 "));
    }

    void invalidArgumentsAndUnsafeTuplesNeverReachSyntaxChecker() {
        auto missing = validArguments;
        missing.removeLast();
        const QList<QStringList> invalidArguments = {
            missing,
            withExtra(validArguments, QStringLiteral("extra")),
            withExtra(validArguments, QStringLiteral("--load")),
            withValue(validArguments, QStringLiteral("--interface"),
                      QStringLiteral("en0\nrdr pass")),
            withValue(validArguments, QStringLiteral("--client-ip"), QStringLiteral("not-an-ip")),
            withValue(validArguments, QStringLiteral("--client-ip"), QStringLiteral("192.0.2.30")),
            withValue(validArguments, QStringLiteral("--server-ip"),
                      QStringLiteral("198.51.100.30")),
            withValue(validArguments, QStringLiteral("--server-port"), QStringLiteral("0")),
            withValue(validArguments, QStringLiteral("--listen-port"), QStringLiteral("65536")),
            withValue(validArguments, QStringLiteral("--research-ip"),
                      QStringLiteral("192.0.2.10")),
            withValue(validArguments, QStringLiteral("--research-mac"),
                      QStringLiteral("ff:ff:ff:ff:ff:ff")),
            withValue(validArguments, QStringLiteral("--client-mac"),
                      QStringLiteral("02:00:00:00:00:30")),
            withValue(validArguments, QStringLiteral("--prefix-length"), QStringLiteral("33")),
            withValue(validArguments, QStringLiteral("--session-id"), QStringLiteral("../unsafe"))};

        for (const auto &arguments : invalidArguments) {
            FakePfSyntaxCheckRunner runner;
            const auto result = PfSessionPreviewCli::run(arguments, runner);
            QVERIFY2(result.exitCode == 2, qPrintable(arguments.join(' ')));
            QVERIFY(result.standardOutput.isEmpty());
            QCOMPARE(runner.calls, 0);
            const auto json = report(result);
            QVERIFY(json.value("status").toString() == QStringLiteral("invalid_arguments") ||
                    json.value("status").toString() == QStringLiteral("invalid_snapshot"));
            QCOMPARE(json.value("rules_emitted").toBool(), false);
            QCOMPARE(json.value("loaded").toBool(), false);
            QCOMPARE(json.value("pf_enabled_changed").toBool(), false);
            QCOMPARE(json.value("global_rules_changed").toBool(), false);
            QCOMPARE(json.value("arp_changed").toBool(), false);
        }
    }

    void syntaxFailuresDoNotEmitRulesOrMutateNetworkState() {
        const QList<QPair<PfSyntaxCheckStatus, QString>> failures = {
            {PfSyntaxCheckStatus::Rejected, QStringLiteral("syntax_rejected")},
            {PfSyntaxCheckStatus::Failed, QStringLiteral("syntax_check_failed")},
            {PfSyntaxCheckStatus::TimedOut, QStringLiteral("syntax_check_timed_out")},
            {PfSyntaxCheckStatus::OutputLimitExceeded,
             QStringLiteral("syntax_diagnostic_limit_exceeded")},
            {PfSyntaxCheckStatus::UnsupportedPlatform, QStringLiteral("unsupported_platform")}};
        for (const auto &[status, expectedStatus] : failures) {
            FakePfSyntaxCheckRunner runner;
            runner.nextStatus = status;
            const auto result = PfSessionPreviewCli::run(validArguments, runner);
            QCOMPARE(result.exitCode, 1);
            QVERIFY(result.standardOutput.isEmpty());
            QCOMPARE(runner.calls, 1);
            QVERIFY(!runner.checkedRules.isEmpty());
            const auto json = report(result);
            QCOMPARE(json.value("status").toString(), expectedStatus);
            QCOMPARE(json.value("syntax_validated").toBool(), false);
            QCOMPARE(json.value("rules_emitted").toBool(), false);
            QCOMPARE(json.value("loaded").toBool(), false);
            QCOMPARE(json.value("pf_enabled_changed").toBool(), false);
            QCOMPARE(json.value("global_rules_changed").toBool(), false);
            QCOMPARE(json.value("arp_changed").toBool(), false);
        }
    }

    void helpAndVersionDoNotInvokeSyntaxChecker() {
        for (const auto &arguments :
             {QStringList{QStringLiteral("pf_session_preview"), QStringLiteral("--help")},
              QStringList{QStringLiteral("pf_session_preview"), QStringLiteral("--version")}}) {
            FakePfSyntaxCheckRunner runner;
            const auto result = PfSessionPreviewCli::run(arguments, runner);
            QCOMPARE(result.exitCode, 0);
            QVERIFY(!result.standardOutput.isEmpty());
            QCOMPARE(runner.calls, 0);
        }
    }
};

QTEST_GUILESS_MAIN(M6PfSessionPreviewCliTests)
#include "M6PfSessionPreviewCliTests.moc"
