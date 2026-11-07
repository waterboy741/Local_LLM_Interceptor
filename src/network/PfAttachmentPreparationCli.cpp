#include "PfAttachmentPreparationCli.hpp"

#include <QCommandLineParser>
#include <QElapsedTimer>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>

namespace interceptor {
namespace {
constexpr int checkTimeoutMs = 3000;
constexpr qsizetype maximumDiagnosticBytes = 4096;
const QString pfctlPath = QStringLiteral("/sbin/pfctl");

class SystemPfSyntaxCheckRunner final : public PfSyntaxCheckRunner {
  public:
    PfSyntaxCheckStatus check(const QByteArray &rules) override {
        QElapsedTimer timer;
        timer.start();
        QProcess process;
        process.setProgram(pfctlPath);
        process.setArguments({"-n", "-f", "-"});
        process.setProcessChannelMode(QProcess::SeparateChannels);
        process.start(QIODevice::ReadWrite);
        if (!process.waitForStarted(checkTimeoutMs)) {
            if (process.state() != QProcess::NotRunning) {
                process.kill();
                process.waitForFinished(1000);
            }
            return timer.elapsed() >= checkTimeoutMs ? PfSyntaxCheckStatus::TimedOut
                                                     : PfSyntaxCheckStatus::Failed;
        }

        qsizetype observedBytes = 0;
        bool outputExceeded = false;
        auto drain = [&]() {
            const auto stdoutBytes = process.readAllStandardOutput();
            const auto stderrBytes = process.readAllStandardError();
            observedBytes += stdoutBytes.size() + stderrBytes.size();
            if (observedBytes > maximumDiagnosticBytes) {
                outputExceeded = true;
                process.kill();
            }
        };

        qint64 written = 0;
        while (written < rules.size() && !outputExceeded) {
            const auto chunkSize = qMin<qint64>(rules.size() - written, 4096);
            const auto count = process.write(rules.constData() + written, chunkSize);
            if (count < 0) {
                process.kill();
                process.waitForFinished(1000);
                return PfSyntaxCheckStatus::Failed;
            }
            if (count == 0) {
                process.kill();
                process.waitForFinished(1000);
                return PfSyntaxCheckStatus::Failed;
            }
            written += count;
            if (process.bytesToWrite() > 0 && !process.waitForBytesWritten(100)) {
                drain();
                if (timer.elapsed() >= checkTimeoutMs) {
                    process.kill();
                    process.waitForFinished(1000);
                    return PfSyntaxCheckStatus::TimedOut;
                }
            }
            drain();
        }
        process.closeWriteChannel();
        while (process.state() != QProcess::NotRunning) {
            drain();
            if (outputExceeded)
                break;
            const int remaining = checkTimeoutMs - static_cast<int>(timer.elapsed());
            if (remaining <= 0) {
                process.kill();
                process.waitForFinished(1000);
                return PfSyntaxCheckStatus::TimedOut;
            }
            process.waitForReadyRead(qMin(remaining, 100));
        }
        if (process.state() != QProcess::NotRunning)
            process.waitForFinished(1000);
        drain();
        if (outputExceeded)
            return PfSyntaxCheckStatus::OutputLimitExceeded;
        if (process.state() != QProcess::NotRunning || process.exitStatus() != QProcess::NormalExit)
            return PfSyntaxCheckStatus::Failed;
        return process.exitCode() == 0 ? PfSyntaxCheckStatus::Valid : PfSyntaxCheckStatus::Rejected;
    }
};

struct ParsedArguments {
    int exitCode = 0;
    QString standardOutput;
    QString standardError;
    bool shouldCheck = false;
};

ParsedArguments parseArguments(const QStringList &arguments) {
    QCommandLineParser parser;
    parser.setApplicationDescription(
        "Print the dedicated llm_interceptor PF attachment fragment after a syntax-only check. "
        "This command does not load rules, enable PF, or edit system configuration.");
    parser.addHelpOption();
    parser.addVersionOption();
    if (!parser.parse(arguments))
        return {2, {}, QStringLiteral("Invalid command-line arguments.\n"), false};
    if (parser.isSet("help") || parser.isSet("help-all"))
        return {0, parser.helpText(), {}, false};
    if (parser.isSet("version"))
        return {0, QStringLiteral("0.1.0\n"), {}, false};
    if (!parser.positionalArguments().isEmpty())
        return {2, {}, QStringLiteral("Invalid command-line arguments.\n"), false};
    return {0, {}, {}, true};
}

QString statusName(PfSyntaxCheckStatus status) {
    switch (status) {
    case PfSyntaxCheckStatus::Valid:
        return QStringLiteral("syntax_validated");
    case PfSyntaxCheckStatus::Rejected:
        return QStringLiteral("syntax_rejected");
    case PfSyntaxCheckStatus::Failed:
        return QStringLiteral("syntax_check_failed");
    case PfSyntaxCheckStatus::TimedOut:
        return QStringLiteral("syntax_check_timed_out");
    case PfSyntaxCheckStatus::OutputLimitExceeded:
        return QStringLiteral("syntax_diagnostic_limit_exceeded");
    case PfSyntaxCheckStatus::UnsupportedPlatform:
        return QStringLiteral("unsupported_platform");
    }
    return QStringLiteral("syntax_check_failed");
}

PfAttachmentPreparationResult report(PfSyntaxCheckStatus status) {
    const bool valid = status == PfSyntaxCheckStatus::Valid;
    const QJsonObject json{{"schema", "llm-interceptor.pf-attachment-preparation.v1"},
                           {"sanitized", true},
                           {"status", statusName(status)},
                           {"syntax_validated", valid},
                           {"fragment_emitted", valid},
                           {"loaded", false},
                           {"pf_enabled_changed", false},
                           {"global_rules_changed", false}};
    return {valid ? 0 : 1,
            valid ? QString::fromUtf8(PfAttachmentPreparationCli::attachmentRules()) : QString{},
            QString::fromUtf8(QJsonDocument(json).toJson(QJsonDocument::Indented))};
}
} // namespace

QByteArray PfAttachmentPreparationCli::attachmentRules() {
    return "# llm_interceptor dedicated PF attachment points.\n"
           "# Preserve all existing main rules, including com.apple anchors.\n"
           "rdr-anchor \"llm_interceptor/*\"\n"
           "anchor \"llm_interceptor/*\"\n";
}

PfAttachmentPreparationResult PfAttachmentPreparationCli::run(const QStringList &arguments) {
    const auto parsed = parseArguments(arguments);
    if (!parsed.shouldCheck)
        return {parsed.exitCode, parsed.standardOutput, parsed.standardError};
#if defined(Q_OS_MACOS)
    SystemPfSyntaxCheckRunner runner;
    return run(arguments, runner);
#else
    return report(PfSyntaxCheckStatus::UnsupportedPlatform);
#endif
}

PfAttachmentPreparationResult PfAttachmentPreparationCli::run(const QStringList &arguments,
                                                              PfSyntaxCheckRunner &runner) {
    const auto parsed = parseArguments(arguments);
    if (!parsed.shouldCheck)
        return {parsed.exitCode, parsed.standardOutput, parsed.standardError};
    return report(runner.check(attachmentRules()));
}

} // namespace interceptor
