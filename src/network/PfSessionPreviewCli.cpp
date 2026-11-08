#include "PfSessionPreviewCli.hpp"
#include "NetworkSession.hpp"

#include <QCommandLineParser>
#include <QJsonDocument>
#include <QJsonObject>
#include <utility>

namespace interceptor {
namespace {
PfAttachmentPreparationResult result(int exitCode, const QString &status, const QString &rules = {},
                                     const QString &anchor = {}) {
    QJsonObject report{{"schema", "llm-interceptor.pf-session-preview.v1"},
                       {"sanitized", true},
                       {"status", status},
                       {"syntax_validated", exitCode == 0 && status == "syntax_validated"},
                       {"rules_emitted", !rules.isEmpty()},
                       {"loaded", false},
                       {"pf_enabled_changed", false},
                       {"global_rules_changed", false},
                       {"arp_changed", false}};
    if (!anchor.isEmpty())
        report.insert("anchor", anchor);
    return {exitCode, rules,
            QString::fromUtf8(QJsonDocument(report).toJson(QJsonDocument::Indented))};
}

struct Parsed {
    bool valid = false;
    PfAttachmentPreparationResult early;
    SessionConfig config;
    NetworkFacts facts;
    int listenPort = 0;
    QString sessionId;
};

Parsed early(PfAttachmentPreparationResult response) {
    Parsed parsed;
    parsed.early = std::move(response);
    return parsed;
}

Parsed parse(const QStringList &arguments) {
    QCommandLineParser parser;
    parser.setApplicationDescription("Preview exact scoped PF session-anchor rules after a "
                                     "syntax-only check. No PF state is changed.");
    parser.addHelpOption();
    parser.addVersionOption();
    const QStringList names{"interface",   "client-ip",     "server-ip",    "server-port",
                            "listen-port", "research-ip",   "research-mac", "client-mac",
                            "server-mac",  "prefix-length", "session-id"};
    for (const auto &name : names)
        parser.addOption({name, name + " supplied from current lab observations", "value"});
    if (!parser.parse(arguments) || !parser.positionalArguments().isEmpty())
        return early(result(2, "invalid_arguments"));
    if (parser.isSet("help") || parser.isSet("help-all"))
        return early({0, parser.helpText(), {}});
    if (parser.isSet("version"))
        return early({0, "0.1.0\n", {}});
    for (const auto &name : names)
        if (!parser.isSet(name) || parser.value(name).isEmpty())
            return early(result(2, "invalid_arguments"));
    bool serverPortOk = false, listenPortOk = false, prefixOk = false;
    const auto serverPort = parser.value("server-port").toInt(&serverPortOk);
    const auto listenPort = parser.value("listen-port").toInt(&listenPortOk);
    const auto prefix = parser.value("prefix-length").toInt(&prefixOk);
    if (!serverPortOk || !listenPortOk || !prefixOk)
        return early(result(2, "invalid_arguments"));
    Parsed parsed;
    parsed.valid = true;
    parsed.config = {parser.value("interface"), parser.value("client-ip"),
                     parser.value("server-ip"), serverPort,
                     SessionConfig{}.apiPaths,  false};
    parsed.listenPort = listenPort;
    parsed.sessionId = parser.value("session-id");
    parsed.facts.interfaceName = parsed.config.interfaceName;
    parsed.facts.researchIp = parser.value("research-ip");
    parsed.facts.researchMac = parser.value("research-mac");
    parsed.facts.clientMac = parser.value("client-mac");
    parsed.facts.serverMac = parser.value("server-mac");
    parsed.facts.prefixLength = prefix;
    parsed.facts.proxyServerIp = parsed.config.serverIp;
    parsed.facts.proxyServerPort = serverPort;
    parsed.facts.proxyListenPort = listenPort;
    // These are caller-supplied preview assumptions, not live evidence or an activation permit.
    parsed.facts.interfaceUp = parsed.facts.sameLink = parsed.facts.anchorAttached = true;
    parsed.facts.proxyReady = parsed.facts.authorized = true;
    return parsed;
}

PfAttachmentPreparationResult runChecked(const QString &rules, const QString &anchor,
                                         PfSyntaxCheckStatus syntax) {
    switch (syntax) {
    case PfSyntaxCheckStatus::Valid:
        break;
    case PfSyntaxCheckStatus::Rejected:
        return result(1, "syntax_rejected");
    case PfSyntaxCheckStatus::TimedOut:
        return result(1, "syntax_check_timed_out");
    case PfSyntaxCheckStatus::OutputLimitExceeded:
        return result(1, "syntax_diagnostic_limit_exceeded");
    case PfSyntaxCheckStatus::UnsupportedPlatform:
        return result(1, "unsupported_platform");
    case PfSyntaxCheckStatus::Failed:
        return result(1, "syntax_check_failed");
    }
    return result(0, "syntax_validated", rules, anchor);
}
} // namespace

PfAttachmentPreparationResult PfSessionPreviewCli::run(const QStringList &arguments) {
    const auto parsed = parse(arguments);
    if (!parsed.valid)
        return parsed.early;
    QString error;
    const auto snapshot = SessionSnapshot::create(parsed.config, parsed.facts, parsed.listenPort,
                                                  parsed.sessionId, &error);
    if (!snapshot)
        return result(2, "invalid_snapshot");
    const auto rules = snapshot->pfRules();
    return runChecked(rules, snapshot->anchor(),
                      PfAttachmentPreparationCli::checkWithSystemPfctl(rules.toUtf8()));
}

PfAttachmentPreparationResult PfSessionPreviewCli::run(const QStringList &arguments,
                                                       PfSyntaxCheckRunner &runner) {
    const auto parsed = parse(arguments);
    if (!parsed.valid)
        return parsed.early;
    QString error;
    const auto snapshot = SessionSnapshot::create(parsed.config, parsed.facts, parsed.listenPort,
                                                  parsed.sessionId, &error);
    if (!snapshot)
        return result(2, "invalid_snapshot");
    const auto rules = snapshot->pfRules();
    return runChecked(rules, snapshot->anchor(), runner.check(rules.toUtf8()));
}
} // namespace interceptor
