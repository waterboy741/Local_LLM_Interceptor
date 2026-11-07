#include "network/PfAttachmentMergeCli.hpp"

#include <QIODevice>
#include <QJsonDocument>
#include <QtTest>

#include <cstring>
#include <utility>

using namespace interceptor;

namespace {
const QByteArray stockConfig =
    "# stock PF policy\n"
    "scrub-anchor \"com.apple/*\"\n"
    "rdr-anchor \"com.apple/*\"\n"
    "nat-anchor \"com.apple/*\"\n"
    "anchor \"com.apple/*\"\n"
    "load anchor \"com.apple\" from \"/etc/pf.anchors/com.apple#stock\" # keep hash\n"
    "anchor \"vendor/example\"\n";

const QByteArray mergedConfig =
    "# stock PF policy\n"
    "scrub-anchor \"com.apple/*\"\n"
    "rdr-anchor \"llm_interceptor/*\"\n"
    "rdr-anchor \"com.apple/*\"\n"
    "nat-anchor \"com.apple/*\"\n"
    "anchor \"llm_interceptor/*\"\n"
    "anchor \"com.apple/*\"\n"
    "load anchor \"com.apple\" from \"/etc/pf.anchors/com.apple#stock\" # keep hash\n"
    "anchor \"vendor/example\"\n";

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

class ShortChunkReadDevice final : public QIODevice {
  public:
    explicit ShortChunkReadDevice(QByteArray input, qsizetype chunkSize = 7)
        : input_(std::move(input)), chunkSize_(chunkSize) {}

    bool isSequential() const override { return true; }
    bool atEnd() const override { return offset_ >= input_.size(); }
    qint64 bytesAvailable() const override {
        return input_.size() - offset_ + QIODevice::bytesAvailable();
    }

  protected:
    qint64 readData(char *data, qint64 maximum) override {
        if (atEnd())
            return -1;
        const auto count = qMin<qint64>(qMin(maximum, chunkSize_), input_.size() - offset_);
        std::memcpy(data, input_.constData() + offset_, static_cast<size_t>(count));
        offset_ += count;
        return count;
    }

    qint64 writeData(const char *, qint64) override { return -1; }

  private:
    QByteArray input_;
    qsizetype chunkSize_;
    qsizetype offset_ = 0;
};

QJsonObject resultJson(const PfAttachmentPreparationResult &result) {
    QJsonParseError error;
    const auto document = QJsonDocument::fromJson(result.standardError.toUtf8(), &error);
    if (error.error != QJsonParseError::NoError || !document.isObject())
        qFatal("PF attachment merge CLI did not return a JSON object");
    return document.object();
}
} // namespace

class M6PfAttachmentMergeCliTests : public QObject {
    Q_OBJECT

  private slots:
    void mergerAddsOnlyScopedReferencesAndPreservesEveryStockByte() {
        const auto result = PfConfigAttachmentMerger::merge(stockConfig);

        QCOMPARE(result.status, PfConfigMergeStatus::Merged);
        QCOMPARE(result.candidate, mergedConfig);
        QVERIFY(result.candidate.contains("anchor \"vendor/example\"\n"));
        QVERIFY(result.candidate.contains(
            "load anchor \"com.apple\" from \"/etc/pf.anchors/com.apple#stock\" # keep hash"));
        QCOMPARE(result.candidate.count("rdr-anchor \"llm_interceptor/*\""), 1);
        QCOMPARE(result.candidate.count("\nanchor \"llm_interceptor/*\""), 1);
    }

    void mergerPreservesCrLfAndMissingFinalNewline() {
        const QByteArray input = "# CRLF stock\r\n"
                                 "rdr-anchor \"com.apple/*\"\r\n"
                                 "anchor \"com.apple/*\"";
        const QByteArray expected = "# CRLF stock\r\n"
                                    "rdr-anchor \"llm_interceptor/*\"\r\n"
                                    "rdr-anchor \"com.apple/*\"\r\n"
                                    "anchor \"llm_interceptor/*\"\r\n"
                                    "anchor \"com.apple/*\"";

        const auto result = PfConfigAttachmentMerger::merge(input);

        QCOMPARE(result.status, PfConfigMergeStatus::Merged);
        QCOMPARE(result.candidate, expected);
    }

    void malformedAndConflictingStockConfigsFailClosed() {
        struct Case {
            QByteArray input;
            PfConfigMergeStatus expectedStatus;
        };
        const QList<Case> cases = {
            {"# empty\n", PfConfigMergeStatus::MissingTranslationMarker},
            {"rdr-anchor \"com.apple/*\"\n", PfConfigMergeStatus::MissingFilterMarker},
            {"rdr-anchor \"com.apple/*\"\n"
             "rdr-anchor \"com.apple/*\"\n"
             "anchor \"com.apple/*\"\n",
             PfConfigMergeStatus::DuplicateTranslationMarker},
            {"rdr-anchor \"com.apple/*\"\n"
             "anchor \"com.apple/*\"\n"
             "anchor \"com.apple/*\"\n",
             PfConfigMergeStatus::DuplicateFilterMarker},
            {"rdr-anchor \"com.apple/*\"\n"
             "nat-anchor \"llm_interceptor/*\"\n"
             "anchor \"com.apple/*\"\n",
             PfConfigMergeStatus::ExistingApplicationReference},
            {"rdr-anchor \"com.apple/*\"\n"
             "anchor \"com.apple/*\"\n"
             "load anchor \"llm_interceptor/session\" from \"/tmp/foreign\"\n",
             PfConfigMergeStatus::ExistingApplicationReference},
            {"nat-anchor \"llm_interceptor/session\"\n"
             "rdr-anchor \"com.apple/*\"\n"
             "anchor \"com.apple/*\"\n",
             PfConfigMergeStatus::ExistingApplicationReference},
            {"binat-anchor \"llm_interceptor/session\"\n"
             "rdr-anchor \"com.apple/*\"\n"
             "anchor \"com.apple/*\"\n",
             PfConfigMergeStatus::ExistingApplicationReference},
            {"scrub-anchor \"llm_interceptor/session\"\n"
             "rdr-anchor \"com.apple/*\"\n"
             "anchor \"com.apple/*\"\n",
             PfConfigMergeStatus::ExistingApplicationReference},
            {"pass out quick from any to \"llm_interceptor\"\n"
             "rdr-anchor \"com.apple/*\"\n"
             "anchor \"com.apple/*\"\n",
             PfConfigMergeStatus::ExistingApplicationReference},
            {"rdr-anchor \"com.apple/*\" \\\n"
             "anchor \"com.apple/*\"\n",
             PfConfigMergeStatus::UnsupportedContinuation},
            {QByteArray("rdr-anchor \"com.apple/*\"\nanchor \"com.apple/*\"\n") + char(0xff),
             PfConfigMergeStatus::InvalidEncoding},
            {QByteArray("rdr-anchor \"com.apple/*\"\nanchor \"com.apple/*\"\n") + '\0',
             PfConfigMergeStatus::InvalidEncoding},
            {"rdr-anchor \"com.apple/*\"\nanchor \"com.apple/*\"\r\n",
             PfConfigMergeStatus::InvalidLineEndings},
            {"anchor \"com.apple/*\"\nrdr-anchor \"com.apple/*\"\n",
             PfConfigMergeStatus::InvalidSectionOrder}};

        for (const auto &test : cases) {
            const auto result = PfConfigAttachmentMerger::merge(test.input);
            QCOMPARE(result.status, test.expectedStatus);
            QVERIFY(result.candidate.isEmpty());
        }
    }

    void mergerIgnoresCommentedReferencesAndLeavesForeignAnchorsUntouched() {
        const QByteArray input =
            "# anchor \"llm_interceptor/commented\"\n"
            "rdr-anchor \"com.apple/*\" # stock translation # section\n"
            "anchor \"com.apple/*\" # stock filter section\n"
            "load anchor \"com.apple\" from \"/etc/pf.anchors/hash#inside\" # trailing comment\n"
            "anchor \"vendor/example\"\n";
        const QByteArray expected =
            "# anchor \"llm_interceptor/commented\"\n"
            "rdr-anchor \"llm_interceptor/*\"\n"
            "rdr-anchor \"com.apple/*\" # stock translation # section\n"
            "anchor \"llm_interceptor/*\"\n"
            "anchor \"com.apple/*\" # stock filter section\n"
            "load anchor \"com.apple\" from \"/etc/pf.anchors/hash#inside\" # trailing comment\n"
            "anchor \"vendor/example\"\n";

        const auto result = PfConfigAttachmentMerger::merge(input);

        QCOMPARE(result.status, PfConfigMergeStatus::Merged);
        QCOMPARE(result.candidate, expected);
    }

    void cliChecksAndEmitsOnlyTheCompleteCandidateAfterValidation() {
        FakePfSyntaxCheckRunner runner;

        const auto result = PfAttachmentMergeCli::run({"pf_attachment_merge"}, stockConfig, runner);

        QCOMPARE(result.exitCode, 0);
        QCOMPARE(result.standardOutput.toUtf8(), mergedConfig);
        QCOMPARE(runner.calls, 1);
        QCOMPARE(runner.checkedRules, mergedConfig);
        const auto json = resultJson(result);
        QCOMPARE(json.value("status").toString(), QString("syntax_validated"));
        QVERIFY(json.value("candidate_emitted").toBool());
        QCOMPARE(json.value("loaded").toBool(), false);
        QCOMPARE(json.value("global_rules_changed").toBool(), false);
        QCOMPARE(json.value("pf_enabled_changed").toBool(), false);
    }

    void mergeFailuresSkipSyntaxCheckAndEmitNoCandidate() {
        FakePfSyntaxCheckRunner runner;

        const auto result = PfAttachmentMergeCli::run(
            {"pf_attachment_merge"}, QByteArray("anchor \"com.apple/*\"\n"), runner);

        QCOMPARE(result.exitCode, 1);
        QVERIFY(result.standardOutput.isEmpty());
        QCOMPARE(runner.calls, 0);
        const auto json = resultJson(result);
        QCOMPARE(json.value("status").toString(), QString("translation_marker_missing"));
        QCOMPARE(json.value("candidate_emitted").toBool(), false);
        QCOMPARE(json.value("loaded").toBool(), false);
        QCOMPARE(json.value("global_rules_changed").toBool(), false);
        QVERIFY(!result.standardError.contains("com.apple"));
    }

    void syntaxFailuresEmitNoCandidateAndExposeNoStockContent() {
        const QList<QPair<PfSyntaxCheckStatus, QString>> failures = {
            {PfSyntaxCheckStatus::Rejected, "syntax_rejected"},
            {PfSyntaxCheckStatus::Failed, "syntax_check_failed"},
            {PfSyntaxCheckStatus::TimedOut, "syntax_check_timed_out"},
            {PfSyntaxCheckStatus::OutputLimitExceeded, "syntax_diagnostic_limit_exceeded"},
            {PfSyntaxCheckStatus::UnsupportedPlatform, "unsupported_platform"}};
        for (const auto &[status, expectedStatus] : failures) {
            FakePfSyntaxCheckRunner runner;
            runner.nextStatus = status;

            const auto result =
                PfAttachmentMergeCli::run({"pf_attachment_merge"}, stockConfig, runner);

            QCOMPARE(result.exitCode, 1);
            QVERIFY(result.standardOutput.isEmpty());
            QCOMPARE(runner.calls, 1);
            QCOMPARE(runner.checkedRules, mergedConfig);
            const auto json = resultJson(result);
            QCOMPARE(json.value("status").toString(), expectedStatus);
            QCOMPARE(json.value("candidate_emitted").toBool(), false);
            QCOMPARE(json.value("loaded").toBool(), false);
            QCOMPARE(json.value("global_rules_changed").toBool(), false);
            QCOMPARE(json.value("pf_enabled_changed").toBool(), false);
            QVERIFY(!result.standardError.contains("com.apple"));
            QVERIFY(!result.standardError.contains("vendor/example"));
        }
    }

    void invalidArgumentsAndOversizedInputNeverRunSyntaxCheck() {
        for (const auto &arguments : {QStringList{"pf_attachment_merge", "extra"},
                                      QStringList{"pf_attachment_merge", "--unknown"}}) {
            FakePfSyntaxCheckRunner runner;
            const auto result = PfAttachmentMergeCli::run(arguments, stockConfig, runner);
            QCOMPARE(result.exitCode, 2);
            QVERIFY(result.standardOutput.isEmpty());
            QVERIFY(!result.standardError.isEmpty());
            QCOMPARE(runner.calls, 0);
        }
        for (const auto &arguments : {QStringList{"pf_attachment_merge", "--help"},
                                      QStringList{"pf_attachment_merge", "--version"}}) {
            FakePfSyntaxCheckRunner runner;
            const auto result = PfAttachmentMergeCli::run(arguments, stockConfig, runner);
            QCOMPARE(result.exitCode, 0);
            QVERIFY(!result.standardOutput.isEmpty());
            QCOMPARE(runner.calls, 0);
        }

        FakePfSyntaxCheckRunner runner;
        const QByteArray oversized(PfAttachmentMergeCli::maximumInputBytes + 1, 'x');
        const auto oversizedResult =
            PfAttachmentMergeCli::run({"pf_attachment_merge"}, oversized, runner);
        QCOMPARE(oversizedResult.exitCode, 1);
        QVERIFY(oversizedResult.standardOutput.isEmpty());
        QCOMPARE(resultJson(oversizedResult).value("status").toString(),
                 QString("input_limit_exceeded"));
        QCOMPARE(runner.calls, 0);
    }

    void boundedReaderPreservesManyShortInputReadsExactly() {
        QByteArray input = "#" + QByteArray(12000, 'x') + "\n";
        input += "rdr-anchor \"com.apple/*\"\nanchor \"com.apple/*\"\n";
        ShortChunkReadDevice device(input);
        QVERIFY(device.open(QIODevice::ReadOnly));
        QByteArray recovered;

        QCOMPARE(PfAttachmentMergeCli::readBoundedInput(device, &recovered),
                 PfAttachmentMergeCli::InputStatus::Complete);
        QCOMPARE(recovered, input);

        FakePfSyntaxCheckRunner runner;
        const auto result = PfAttachmentMergeCli::run({"pf_attachment_merge"}, recovered, runner);
        QCOMPARE(result.exitCode, 0);
        QCOMPARE(result.standardOutput.toUtf8(), runner.checkedRules);
        QCOMPARE(runner.calls, 1);
        QVERIFY(runner.checkedRules.startsWith("#" + QByteArray(12000, 'x') + "\n"));
    }

    void boundedReaderRejectsInputOverLimitWithoutTruncatingSilently() {
        QByteArray input(PfAttachmentMergeCli::maximumInputBytes + 1, 'x');
        ShortChunkReadDevice device(input, 1024);
        QVERIFY(device.open(QIODevice::ReadOnly));
        QByteArray recovered;

        QCOMPARE(PfAttachmentMergeCli::readBoundedInput(device, &recovered),
                 PfAttachmentMergeCli::InputStatus::LimitExceeded);
        QCOMPARE(recovered.size(), PfAttachmentMergeCli::maximumInputBytes + 1);
    }
};

QTEST_GUILESS_MAIN(M6PfAttachmentMergeCliTests)
#include "M6PfAttachmentMergeCliTests.moc"
