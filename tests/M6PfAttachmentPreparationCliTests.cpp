#include "network/PfAttachmentPreparationCli.hpp"

#include <QFile>
#include <QJsonDocument>
#include <QMap>
#include <QtTest>

using namespace interceptor;

namespace {
constexpr auto expectedFragment =
    "# llm_interceptor dedicated PF attachment points.\n"
    "# Preserve all existing main rules, including com.apple anchors.\n"
    "rdr-anchor \"llm_interceptor/*\"\n"
    "anchor \"llm_interceptor/*\"\n";

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

QJsonObject resultJson(const PfAttachmentPreparationResult &result) {
    QJsonParseError error;
    const auto document = QJsonDocument::fromJson(result.standardError.toUtf8(), &error);
    if (error.error != QJsonParseError::NoError || !document.isObject())
        qFatal("PF attachment preparation CLI did not return a JSON object");
    return document.object();
}
} // namespace

class M6PfAttachmentPreparationCliTests : public QObject {
    Q_OBJECT

  private slots:
    void emittedRulesMatchExactNarrowFixtureAndPreserveExistingAnchors() {
        const QByteArray expected(expectedFragment);
        QCOMPARE(PfAttachmentPreparationCli::attachmentRules(), expected);

        QFile fixture(QStringLiteral(INTERCEPTOR_TEST_SOURCE_DIR "/docs/m6/"
                                                                 "llm_interceptor_attachment.pf"));
        QVERIFY(fixture.open(QIODevice::ReadOnly));
        QCOMPARE(fixture.readAll(), expected);

        const auto lines = expected.split('\n');
        QCOMPARE(lines[2], QByteArrayLiteral("rdr-anchor \"llm_interceptor/*\""));
        QCOMPARE(lines[3], QByteArrayLiteral("anchor \"llm_interceptor/*\""));
        QCOMPARE(lines.size(), 5);
        QVERIFY(
            expected.contains("Preserve all existing main rules, including com.apple anchors."));
        QVERIFY(!expected.contains("pass "));
        QVERIFY(!expected.contains("block "));
        QVERIFY(!expected.contains("llm_interceptor/*/*"));
        QVERIFY(!expected.contains("/etc/pf.conf"));
    }

    void successfulCheckEmitsOnlyTheReviewedFragmentAndSanitizedNoMutationStatus() {
        FakePfSyntaxCheckRunner runner;

        const auto result = PfAttachmentPreparationCli::run({"pf_attachment_prepare"}, runner);

        QCOMPARE(result.exitCode, 0);
        QCOMPARE(result.standardOutput.toUtf8(), QByteArray(expectedFragment));
        QCOMPARE(runner.calls, 1);
        QCOMPARE(runner.checkedRules, QByteArray(expectedFragment));
        const auto json = resultJson(result);
        QCOMPARE(json.value("schema").toString(),
                 QString("llm-interceptor.pf-attachment-preparation.v1"));
        QVERIFY(json.value("sanitized").toBool());
        QCOMPARE(json.value("status").toString(), QString("syntax_validated"));
        QVERIFY(json.value("syntax_validated").toBool());
        QVERIFY(json.value("fragment_emitted").toBool());
        QCOMPARE(json.value("loaded").toBool(), false);
        QCOMPARE(json.value("pf_enabled_changed").toBool(), false);
        QCOMPARE(json.value("global_rules_changed").toBool(), false);
        QVERIFY(!result.standardError.contains("/etc/pf.conf"));
        QVERIFY(!result.standardError.contains("pfctl"));
    }

    void strictArgumentsDoNotInvokeTheSyntaxChecker() {
        const QList<QStringList> invalidArguments = {{"pf_attachment_prepare", "extra"},
                                                     {"pf_attachment_prepare", "--unknown"},
                                                     {"pf_attachment_prepare", "--write"},
                                                     {"pf_attachment_prepare", "--load"},
                                                     {"pf_attachment_prepare", "--enable"}};
        for (const auto &arguments : invalidArguments) {
            FakePfSyntaxCheckRunner runner;
            const auto result = PfAttachmentPreparationCli::run(arguments, runner);
            QCOMPARE(result.exitCode, 2);
            QVERIFY(result.standardOutput.isEmpty());
            QVERIFY(!result.standardError.isEmpty());
            QCOMPARE(runner.calls, 0);
        }

        for (const auto &arguments : {QStringList{"pf_attachment_prepare", "--help"},
                                      QStringList{"pf_attachment_prepare", "--version"}}) {
            FakePfSyntaxCheckRunner runner;
            const auto result = PfAttachmentPreparationCli::run(arguments, runner);
            QCOMPARE(result.exitCode, 0);
            QVERIFY(!result.standardOutput.isEmpty());
            QCOMPARE(runner.calls, 0);
        }
    }

    void rejectedAndFailedSyntaxChecksNeverEmitFragment() {
        const QList<QPair<PfSyntaxCheckStatus, QString>> failures = {
            {PfSyntaxCheckStatus::Rejected, "syntax_rejected"},
            {PfSyntaxCheckStatus::Failed, "syntax_check_failed"},
            {PfSyntaxCheckStatus::TimedOut, "syntax_check_timed_out"},
            {PfSyntaxCheckStatus::OutputLimitExceeded, "syntax_diagnostic_limit_exceeded"},
            {PfSyntaxCheckStatus::UnsupportedPlatform, "unsupported_platform"}};
        for (const auto &[status, expectedStatus] : failures) {
            FakePfSyntaxCheckRunner runner;
            runner.nextStatus = status;

            const auto result = PfAttachmentPreparationCli::run({"pf_attachment_prepare"}, runner);

            QCOMPARE(result.exitCode, 1);
            QVERIFY(result.standardOutput.isEmpty());
            QCOMPARE(runner.calls, 1);
            QCOMPARE(runner.checkedRules, QByteArray(expectedFragment));
            const auto json = resultJson(result);
            QCOMPARE(json.value("status").toString(), expectedStatus);
            QCOMPARE(json.value("syntax_validated").toBool(), false);
            QCOMPARE(json.value("fragment_emitted").toBool(), false);
            QCOMPARE(json.value("loaded").toBool(), false);
            QCOMPARE(json.value("pf_enabled_changed").toBool(), false);
            QCOMPARE(json.value("global_rules_changed").toBool(), false);
        }
    }
};

QTEST_GUILESS_MAIN(M6PfAttachmentPreparationCliTests)
#include "M6PfAttachmentPreparationCliTests.moc"
