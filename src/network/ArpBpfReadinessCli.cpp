#include "ArpBpfReadinessCli.hpp"

#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QJsonDocument>
#include <QJsonObject>

namespace interceptor {
namespace {
QString statusCode(BpfArpWriterStatus status) {
    switch (status) {
    case BpfArpWriterStatus::Ready:
        return QStringLiteral("ready");
    case BpfArpWriterStatus::InvalidInterface:
        return QStringLiteral("invalid_interface");
    case BpfArpWriterStatus::UnsupportedPlatform:
        return QStringLiteral("unsupported_platform");
    case BpfArpWriterStatus::OpenFailed:
        return QStringLiteral("device_open_failed");
    case BpfArpWriterStatus::AttachFailed:
        return QStringLiteral("interface_bind_failed");
    case BpfArpWriterStatus::UnsupportedLinkType:
        return QStringLiteral("unsupported_link_type");
    case BpfArpWriterStatus::HeaderCompleteFailed:
        return QStringLiteral("header_mode_failed");
    case BpfArpWriterStatus::CloseFailed:
        return QStringLiteral("close_unconfirmed");
    case BpfArpWriterStatus::InvalidFrame:
    case BpfArpWriterStatus::InterfaceMismatch:
    case BpfArpWriterStatus::WriteFailed:
    case BpfArpWriterStatus::NotReady:
        return QStringLiteral("not_ready");
    }
    return QStringLiteral("not_ready");
}

ArpBpfReadinessCliResult report(const BpfReadinessResult &result) {
    const QJsonObject json{{"status", statusCode(result.status)},
                           {"device_opened", result.deviceOpened},
                           {"interface_bound", result.interfaceBound},
                           {"ethernet_link", result.ethernetLink},
                           {"header_complete", result.headerComplete},
                           {"close_confirmed", result.closeConfirmed},
                           {"traffic_sent", false}};
    return {result.ready() ? 0 : 1,
            QString::fromUtf8(QJsonDocument(json).toJson(QJsonDocument::Indented)),
            {}};
}

void configureParser(QCommandLineParser &parser) {
    parser.setApplicationDescription(
        "Opt-in, open-only macOS BPF readiness check. It opens and configures a BPF device, "
        "then closes it without writing packets or changing network configuration.");
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addOption(
        QCommandLineOption("interface", "Interface to bind for readiness check.", "name"));
}

struct ParsedArguments {
    int exitCode = 0;
    QString interfaceName;
    QString standardOutput;
    QString standardError;
    bool shouldProbe = false;
};

ParsedArguments parseArguments(const QStringList &arguments) {
    int interfaceOptionCount = 0;
    for (const auto &argument : arguments) {
        if (argument == QStringLiteral("--interface") ||
            argument.startsWith(QStringLiteral("--interface=")))
            ++interfaceOptionCount;
    }
    if (interfaceOptionCount > 1)
        return {2, {}, {}, QStringLiteral("Invalid command-line arguments.\n"), false};

    QCommandLineParser parser;
    configureParser(parser);
    if (!parser.parse(arguments))
        return {2, {}, {}, QStringLiteral("Invalid command-line arguments.\n"), false};
    if (parser.isSet("help") || parser.isSet("help-all"))
        return {0, {}, parser.helpText(), {}, false};
    if (parser.isSet("version"))
        return {0, {}, QStringLiteral("0.1.0\n"), {}, false};
    if (!parser.isSet("interface"))
        return {2, {}, {}, QStringLiteral("Missing required option: --interface\n"), false};
    return {0, parser.value("interface"), {}, {}, true};
}
} // namespace

ArpBpfReadinessCliResult ArpBpfReadinessCli::run(const QStringList &arguments) {
    const auto parsed = parseArguments(arguments);
    if (!parsed.shouldProbe)
        return {parsed.exitCode, parsed.standardOutput, parsed.standardError};
    return report(MacBpfArpPacketIo::probeReadiness(parsed.interfaceName));
}

ArpBpfReadinessCliResult ArpBpfReadinessCli::run(const QStringList &arguments,
                                                 BpfSystemCalls &systemCalls) {
    const auto parsed = parseArguments(arguments);
    if (!parsed.shouldProbe)
        return {parsed.exitCode, parsed.standardOutput, parsed.standardError};
    return report(MacBpfArpPacketIo::probeReadiness(parsed.interfaceName, systemCalls));
}

} // namespace interceptor
