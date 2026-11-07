#include "PfReadinessCli.hpp"

#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QJsonDocument>

namespace interceptor {
namespace {
struct ParsedArguments {
    int exitCode = 0;
    int timeoutMs = PfDiagnostics::defaultTimeoutMs;
    QString standardOutput;
    QString standardError;
    bool shouldQuery = false;
};

void configureParser(QCommandLineParser &parser) {
    parser.setApplicationDescription(
        "Read-only PF readiness check. Queries current PF status and main anchor references; "
        "does not enable PF, load rules, or change network configuration.");
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addOption(QCommandLineOption("timeout-ms", "Timeout for each PF query (1–5000).",
                                        "milliseconds"));
}

ParsedArguments parseArguments(const QStringList &arguments) {
    int timeoutOptionCount = 0;
    for (const auto &argument : arguments) {
        if (argument == QStringLiteral("--timeout-ms") ||
            argument.startsWith(QStringLiteral("--timeout-ms=")))
            ++timeoutOptionCount;
    }
    if (timeoutOptionCount > 1)
        return {2, {}, {}, QStringLiteral("Invalid command-line arguments.\n"), false};

    QCommandLineParser parser;
    configureParser(parser);
    if (!parser.parse(arguments))
        return {2, {}, {}, QStringLiteral("Invalid command-line arguments.\n"), false};
    if (parser.isSet("help") || parser.isSet("help-all"))
        return {0, {}, parser.helpText(), {}, false};
    if (parser.isSet("version"))
        return {0, {}, QStringLiteral("0.1.0\n"), {}, false};
    if (!parser.positionalArguments().isEmpty())
        return {2, {}, {}, QStringLiteral("Invalid command-line arguments.\n"), false};

    int timeoutMs = PfDiagnostics::defaultTimeoutMs;
    if (parser.isSet("timeout-ms")) {
        bool valid = false;
        timeoutMs = parser.value("timeout-ms").toInt(&valid);
        if (!valid || timeoutMs < 1 || timeoutMs > PfDiagnostics::maximumTimeoutMs)
            return {2, {}, {}, QStringLiteral("Invalid command-line arguments.\n"), false};
    }
    return {0, timeoutMs, {}, {}, true};
}

PfReadinessCliResult report(const PfPreInstallReadinessResult &result) {
    return {result.ready ? 0 : 1,
            QString::fromUtf8(QJsonDocument(result.toSanitizedJson()).toJson(
                QJsonDocument::Indented)),
            {}};
}
} // namespace

PfReadinessCliResult PfReadinessCli::run(const QStringList &arguments) {
    const auto parsed = parseArguments(arguments);
    if (!parsed.shouldQuery)
        return {parsed.exitCode, parsed.standardOutput, parsed.standardError};
#ifdef Q_OS_MACOS
    return run(arguments, systemPfCommandRunner());
#else
    PfPreInstallReadinessResult unsupported;
    unsupported.timeoutMs = parsed.timeoutMs;
    unsupported.statusCode = QStringLiteral("unsupported_platform");
    return report(unsupported);
#endif
}

PfReadinessCliResult PfReadinessCli::run(const QStringList &arguments, PfCommandRunner &runner) {
    const auto parsed = parseArguments(arguments);
    if (!parsed.shouldQuery)
        return {parsed.exitCode, parsed.standardOutput, parsed.standardError};
    return report(PfDiagnostics::collectPreInstallReadiness(runner, parsed.timeoutMs));
}

} // namespace interceptor
