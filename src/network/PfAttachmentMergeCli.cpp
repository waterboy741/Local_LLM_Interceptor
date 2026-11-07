#include "PfAttachmentMergeCli.hpp"

#include <QCommandLineParser>
#include <QElapsedTimer>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <algorithm>
#include <cstdio>
#include <utility>

namespace interceptor {
namespace {
QString mergeStatusName(PfConfigMergeStatus status) {
    switch (status) {
    case PfConfigMergeStatus::Merged:
        return QStringLiteral("merged");
    case PfConfigMergeStatus::InvalidEncoding:
        return QStringLiteral("invalid_encoding");
    case PfConfigMergeStatus::InvalidLineEndings:
        return QStringLiteral("invalid_line_endings");
    case PfConfigMergeStatus::MissingTranslationMarker:
        return QStringLiteral("translation_marker_missing");
    case PfConfigMergeStatus::DuplicateTranslationMarker:
        return QStringLiteral("translation_marker_ambiguous");
    case PfConfigMergeStatus::MissingFilterMarker:
        return QStringLiteral("filter_marker_missing");
    case PfConfigMergeStatus::DuplicateFilterMarker:
        return QStringLiteral("filter_marker_ambiguous");
    case PfConfigMergeStatus::InvalidSectionOrder:
        return QStringLiteral("attachment_sections_out_of_order");
    case PfConfigMergeStatus::UnsupportedContinuation:
        return QStringLiteral("line_continuation_unsupported");
    case PfConfigMergeStatus::ExistingApplicationReference:
        return QStringLiteral("application_reference_exists");
    }
    return QStringLiteral("merge_failed");
}

bool stripComment(const QByteArray &line, QByteArray *active) {
    bool quoted = false;
    bool escaped = false;
    for (qsizetype index = 0; index < line.size(); ++index) {
        const char character = line.at(index);
        if (escaped) {
            escaped = false;
            continue;
        }
        if (quoted && character == '\\') {
            escaped = true;
            continue;
        }
        if (character == '"') {
            quoted = !quoted;
            continue;
        }
        if (character == '#' && !quoted) {
            *active = line.first(index);
            return true;
        }
    }
    if (quoted || escaped)
        return false;
    *active = line;
    return true;
}

struct Marker {
    qsizetype offset = -1;
    QByteArray newline;
};

bool validUtf8(const QByteArray &bytes) {
    return !bytes.contains('\0') && QString::fromUtf8(bytes).toUtf8() == bytes;
}

PfAttachmentPreparationResult cliStatus(int exitCode, const QString &status,
                                        const QByteArray &candidate = {}) {
    const bool emitted = exitCode == 0;
    const QJsonObject json{{"schema", "llm-interceptor.pf-attachment-merge.v1"},
                           {"sanitized", true},
                           {"status", status},
                           {"candidate_emitted", emitted},
                           {"loaded", false},
                           {"global_rules_changed", false},
                           {"pf_enabled_changed", false}};
    return {exitCode, QString::fromUtf8(candidate),
            QString::fromUtf8(QJsonDocument(json).toJson(QJsonDocument::Indented))};
}

bool validArguments(const QStringList &arguments, QString *output, QString *error,
                    bool *shouldRun) {
    QCommandLineParser parser;
    parser.setApplicationDescription(
        "Merge the llm_interceptor anchor references into supplied PF configuration text, "
        "validate syntax without loading, and print a review candidate to stdout.");
    parser.addHelpOption();
    parser.addVersionOption();
    if (!parser.parse(arguments)) {
        *error = QStringLiteral("Invalid command-line arguments.\n");
        return false;
    }
    if (parser.isSet("help") || parser.isSet("help-all")) {
        *output = parser.helpText();
        *shouldRun = false;
        return true;
    }
    if (parser.isSet("version")) {
        *output = QStringLiteral("0.1.0\n");
        *shouldRun = false;
        return true;
    }
    if (!parser.positionalArguments().isEmpty()) {
        *error = QStringLiteral("Invalid command-line arguments.\n");
        return false;
    }
    *shouldRun = true;
    return true;
}
} // namespace

PfAttachmentMergeCli::InputStatus PfAttachmentMergeCli::readBoundedInput(QIODevice &input,
                                                                         QByteArray *contents) {
    if (!contents)
        return InputStatus::ReadFailed;
    contents->clear();
    QElapsedTimer idle;
    idle.start();
    while (contents->size() <= maximumInputBytes) {
        const auto remaining = maximumInputBytes + 1 - contents->size();
        const auto chunk = input.read(qMin<qsizetype>(remaining, 4096));
        if (!chunk.isEmpty()) {
            contents->append(chunk);
            idle.restart();
            continue;
        }
        if (input.atEnd())
            return contents->size() > maximumInputBytes ? InputStatus::LimitExceeded
                                                        : InputStatus::Complete;
        if (idle.elapsed() >= 5000)
            return InputStatus::ReadFailed;
        input.waitForReadyRead(100);
    }
    return InputStatus::LimitExceeded;
}

PfConfigMergeResult PfConfigAttachmentMerger::merge(const QByteArray &existingConfig) {
    if (!validUtf8(existingConfig))
        return {PfConfigMergeStatus::InvalidEncoding, {}};

    bool sawLf = false;
    bool sawCrLf = false;
    for (qsizetype index = 0; index < existingConfig.size(); ++index) {
        if (existingConfig.at(index) != '\n')
            continue;
        if (index > 0 && existingConfig.at(index - 1) == '\r')
            sawCrLf = true;
        else
            sawLf = true;
    }
    if (sawLf && sawCrLf)
        return {PfConfigMergeStatus::InvalidLineEndings, {}};
    const QByteArray defaultNewline = sawCrLf ? QByteArray("\r\n") : QByteArray("\n");

    static const QRegularExpression translationMarker(
        R"(^[\t ]*rdr-anchor[\t ]+"com\.apple/\*"[\t ]*$)");
    static const QRegularExpression filterMarker(R"(^[\t ]*anchor[\t ]+"com\.apple/\*"[\t ]*$)");

    QList<Marker> translationMarkers;
    QList<Marker> filterMarkers;
    qsizetype lineStart = 0;
    while (lineStart <= existingConfig.size()) {
        const auto newlineAt = existingConfig.indexOf('\n', lineStart);
        const qsizetype rawEnd = newlineAt < 0 ? existingConfig.size() : newlineAt;
        qsizetype contentEnd = rawEnd;
        QByteArray lineEnding;
        if (newlineAt >= 0) {
            lineEnding = sawCrLf ? QByteArray("\r\n") : QByteArray("\n");
            if (sawCrLf && contentEnd > lineStart && existingConfig.at(contentEnd - 1) == '\r')
                --contentEnd;
        }
        const auto rawLine = existingConfig.mid(lineStart, contentEnd - lineStart);
        QByteArray activeLine;
        if (!stripComment(rawLine, &activeLine))
            return {PfConfigMergeStatus::InvalidEncoding, {}};
        const auto activeTrimmed = activeLine.trimmed();
        if (activeTrimmed.endsWith('\\'))
            return {PfConfigMergeStatus::UnsupportedContinuation, {}};
        if (activeLine.contains("llm_interceptor"))
            return {PfConfigMergeStatus::ExistingApplicationReference, {}};
        const auto text = QString::fromUtf8(activeLine);
        const Marker marker{lineStart, lineEnding.isEmpty() ? defaultNewline : lineEnding};
        if (translationMarker.match(text).hasMatch())
            translationMarkers.append(marker);
        if (filterMarker.match(text).hasMatch())
            filterMarkers.append(marker);
        if (newlineAt < 0)
            break;
        lineStart = newlineAt + 1;
    }

    if (translationMarkers.isEmpty())
        return {PfConfigMergeStatus::MissingTranslationMarker, {}};
    if (translationMarkers.size() != 1)
        return {PfConfigMergeStatus::DuplicateTranslationMarker, {}};
    if (filterMarkers.isEmpty())
        return {PfConfigMergeStatus::MissingFilterMarker, {}};
    if (filterMarkers.size() != 1)
        return {PfConfigMergeStatus::DuplicateFilterMarker, {}};
    if (translationMarkers.first().offset >= filterMarkers.first().offset)
        return {PfConfigMergeStatus::InvalidSectionOrder, {}};

    const QByteArray translationLine =
        "rdr-anchor \"llm_interceptor/*\"" + translationMarkers.first().newline;
    const QByteArray filterLine = "anchor \"llm_interceptor/*\"" + filterMarkers.first().newline;
    QByteArray candidate = existingConfig;
    struct Insertion {
        qsizetype offset;
        QByteArray text;
    };
    QList<Insertion> insertions = {{translationMarkers.first().offset, translationLine},
                                   {filterMarkers.first().offset, filterLine}};
    std::sort(
        insertions.begin(), insertions.end(),
        [](const Insertion &left, const Insertion &right) { return left.offset > right.offset; });
    for (const auto &insertion : insertions)
        candidate.insert(insertion.offset, insertion.text);
    return {PfConfigMergeStatus::Merged, std::move(candidate)};
}

PfAttachmentPreparationResult PfAttachmentMergeCli::run(const QStringList &arguments) {
    QString output;
    QString error;
    bool shouldRun = false;
    if (!validArguments(arguments, &output, &error, &shouldRun))
        return {2, {}, error};
    if (!shouldRun)
        return {0, output, {}};

    QFile input;
    if (!input.open(stdin, QIODevice::ReadOnly))
        return cliStatus(1, QStringLiteral("input_unavailable"));
    QByteArray existingConfig;
    const auto inputStatus = readBoundedInput(input, &existingConfig);
    if (inputStatus == InputStatus::LimitExceeded)
        return cliStatus(1, QStringLiteral("input_limit_exceeded"));
    if (inputStatus == InputStatus::ReadFailed)
        return cliStatus(1, QStringLiteral("input_read_failed"));

#if defined(Q_OS_MACOS)
    class SystemPfSyntaxCheckRunner final : public PfSyntaxCheckRunner {
      public:
        PfSyntaxCheckStatus check(const QByteArray &rules) override {
            return PfAttachmentPreparationCli::checkWithSystemPfctl(rules);
        }
    } runner;
    return run(arguments, existingConfig, runner);
#else
    return cliStatus(1, QStringLiteral("unsupported_platform"));
#endif
}

PfAttachmentPreparationResult PfAttachmentMergeCli::run(const QStringList &arguments,
                                                        const QByteArray &existingConfig,
                                                        PfSyntaxCheckRunner &runner) {
    QString output;
    QString error;
    bool shouldRun = false;
    if (!validArguments(arguments, &output, &error, &shouldRun))
        return {2, {}, error};
    if (!shouldRun)
        return {0, output, {}};
    if (existingConfig.size() > maximumInputBytes)
        return cliStatus(1, QStringLiteral("input_limit_exceeded"));

    const auto merged = PfConfigAttachmentMerger::merge(existingConfig);
    if (merged.status != PfConfigMergeStatus::Merged)
        return cliStatus(1, mergeStatusName(merged.status));
    const auto syntaxStatus = runner.check(merged.candidate);
    if (syntaxStatus != PfSyntaxCheckStatus::Valid) {
        QString status = QStringLiteral("syntax_check_failed");
        if (syntaxStatus == PfSyntaxCheckStatus::Rejected)
            status = QStringLiteral("syntax_rejected");
        else if (syntaxStatus == PfSyntaxCheckStatus::TimedOut)
            status = QStringLiteral("syntax_check_timed_out");
        else if (syntaxStatus == PfSyntaxCheckStatus::OutputLimitExceeded)
            status = QStringLiteral("syntax_diagnostic_limit_exceeded");
        else if (syntaxStatus == PfSyntaxCheckStatus::UnsupportedPlatform)
            status = QStringLiteral("unsupported_platform");
        return cliStatus(1, status);
    }
    return cliStatus(0, QStringLiteral("syntax_validated"), merged.candidate);
}

} // namespace interceptor
