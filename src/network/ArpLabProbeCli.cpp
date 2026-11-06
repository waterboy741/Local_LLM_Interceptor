#include "ArpLabProbeCli.hpp"

#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QHash>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAddressEntry>
#include <QNetworkInterface>

#include <cerrno>
#include <chrono>
#include <csignal>
#include <memory>
#include <thread>

namespace interceptor {
namespace {
volatile std::sig_atomic_t caughtSignal = 0;

void probeSignalHandler(int signalNumber) { caughtSignal = signalNumber; }

class SignalAwareWaiter final : public ArpProbeWaiter {
  public:
    SignalAwareWaiter() {
        caughtSignal = 0;
        struct sigaction action{};
        action.sa_handler = probeSignalHandler;
        sigemptyset(&action.sa_mask);
        action.sa_flags = 0;
        if (sigaction(SIGINT, &action, &oldInterrupt_) != 0)
            return;
        interruptInstalled_ = true;
        if (sigaction(SIGTERM, &action, &oldTerminate_) != 0) {
            sigaction(SIGINT, &oldInterrupt_, nullptr);
            interruptInstalled_ = false;
            return;
        }
        terminateInstalled_ = true;
    }

    ~SignalAwareWaiter() override {
        if (terminateInstalled_)
            sigaction(SIGTERM, &oldTerminate_, nullptr);
        if (interruptInstalled_)
            sigaction(SIGINT, &oldInterrupt_, nullptr);
    }

    bool ready() const { return interruptInstalled_ && terminateInstalled_; }
    bool interrupted() const override { return caughtSignal != 0; }

    ArpProbeWaitOutcome waitFor(int durationMs) override {
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(durationMs);
        while (!interrupted()) {
            const auto remaining = deadline - std::chrono::steady_clock::now();
            if (remaining <= std::chrono::steady_clock::duration::zero())
                return ArpProbeWaitOutcome::Elapsed;
            std::this_thread::sleep_for(std::min<std::chrono::steady_clock::duration>(
                remaining, std::chrono::milliseconds(10)));
        }
        return ArpProbeWaitOutcome::Interrupted;
    }

  private:
    struct sigaction oldInterrupt_{};
    struct sigaction oldTerminate_{};
    bool interruptInstalled_ = false;
    bool terminateInstalled_ = false;
};

class SystemInterfaceInspector final : public ArpProbeInterfaceInspector {
  public:
    ArpProbeInterfaceEvidence inspect(const QString &interfaceName) override {
        const auto interface = QNetworkInterface::interfaceFromName(interfaceName);
        ArpProbeInterfaceEvidence facts;
        facts.found = interface.isValid();
        facts.up = facts.found && interface.flags().testFlag(QNetworkInterface::IsUp);
        facts.running = facts.found && interface.flags().testFlag(QNetworkInterface::IsRunning);
        if (!facts.found)
            return facts;
        facts.interfaceName = interface.name();
        facts.macAddress = interface.hardwareAddress();
        for (const auto &entry : interface.addressEntries()) {
            if (entry.ip().protocol() == QAbstractSocket::IPv4Protocol)
                facts.ipv4Addresses.append({entry.ip().toString(), entry.prefixLength()});
        }
        return facts;
    }
};

struct ProbeArguments {
    QString interfaceName;
    ArpLabProbeInputs planInputs;
    int durationMs = 1000;
};

QString statusCode(ArpLabProbeStatus status) {
    switch (status) {
    case ArpLabProbeStatus::CorrectionWriteAcceptedAfterTimeout:
        return QStringLiteral("corrective_frame_write_accepted_after_timeout");
    case ArpLabProbeStatus::CorrectionWriteAcceptedAfterSignal:
        return QStringLiteral("corrective_frame_write_accepted_after_signal");
    case ArpLabProbeStatus::RedirectWriteUncertainCorrectionAccepted:
        return QStringLiteral("redirect_write_uncertain_corrective_write_accepted");
    case ArpLabProbeStatus::CleanupUncertain:
        return QStringLiteral("cleanup_uncertain");
    case ArpLabProbeStatus::InterruptedBeforeRedirect:
        return QStringLiteral("interrupted_before_redirect");
    case ArpLabProbeStatus::InvalidDuration:
        return QStringLiteral("invalid_duration");
    }
    return QStringLiteral("cleanup_uncertain");
}

QString bpfStatusCode(BpfArpWriterStatus status) {
    switch (status) {
    case BpfArpWriterStatus::InvalidInterface:
        return QStringLiteral("invalid_interface");
    case BpfArpWriterStatus::UnsupportedPlatform:
        return QStringLiteral("unsupported_platform");
    case BpfArpWriterStatus::OpenFailed:
        return QStringLiteral("bpf_open_failed");
    case BpfArpWriterStatus::AttachFailed:
        return QStringLiteral("interface_bind_failed");
    case BpfArpWriterStatus::UnsupportedLinkType:
        return QStringLiteral("unsupported_link_type");
    case BpfArpWriterStatus::HeaderCompleteFailed:
        return QStringLiteral("header_setup_failed");
    case BpfArpWriterStatus::CloseFailed:
        return QStringLiteral("close_unconfirmed");
    case BpfArpWriterStatus::Ready:
    case BpfArpWriterStatus::InvalidFrame:
    case BpfArpWriterStatus::InterfaceMismatch:
    case BpfArpWriterStatus::WriteFailed:
    case BpfArpWriterStatus::NotReady:
        return QStringLiteral("bpf_not_ready");
    }
    return QStringLiteral("bpf_not_ready");
}

ArpLabProbeCliResult jsonResult(int exitCode, const QString &status, bool redirectAttempted,
                                bool redirectWriteAccepted, bool restorationAttempted,
                                bool restorationWriteAccepted, bool closeConfirmed,
                                bool interrupted) {
    const QJsonObject json{{"status", status},
                           {"redirect_write_attempted", redirectAttempted},
                           {"redirect_write_accepted", redirectWriteAccepted},
                           {"corrective_write_attempted", restorationAttempted},
                           {"corrective_write_accepted", restorationWriteAccepted},
                           {"descriptor_close_confirmed", closeConfirmed},
                           {"interrupted", interrupted},
                           {"peer_cache_change_verified", false}};
    return {exitCode, QString::fromUtf8(QJsonDocument(json).toJson(QJsonDocument::Indented)), {}};
}

void configureParser(QCommandLineParser &parser) {
    parser.setApplicationDescription(
        "Opt-in one-client ARP direction/restoration probe. Sends one targeted update and one "
        "corrective frame; peer cache changes are not verified by this tool.");
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addOption(QCommandLineOption("interface", "Selected interface.", "name"));
    parser.addOption(QCommandLineOption("research-ip", "Research Mac IPv4 address.", "ipv4"));
    parser.addOption(
        QCommandLineOption("research-mac", "Research Mac unicast MAC address.", "mac"));
    parser.addOption(QCommandLineOption("client-ip", "Authorized client IPv4 address.", "ipv4"));
    parser.addOption(
        QCommandLineOption("client-mac", "Authorized client unicast MAC address.", "mac"));
    parser.addOption(QCommandLineOption("server-ip", "Configured server IPv4 address.", "ipv4"));
    parser.addOption(
        QCommandLineOption("server-mac", "Configured server unicast MAC address.", "mac"));
    parser.addOption(
        QCommandLineOption("prefix-length", "Selected IPv4 subnet prefix (1–30).", "bits"));
    parser.addOption(QCommandLineOption(
        "duration-ms", "Redirect duration in milliseconds (1–5000; default 1000).", "ms", "1000"));
    parser.addOption(
        QCommandLineOption("confirm-one-client-arp-probe",
                           "Explicitly authorize this one-client redirect and corrective update."));
}

bool parseArguments(const QStringList &arguments, ProbeArguments &parsed, QString &error) {
    const QStringList valueOptions{"interface",  "research-ip",   "research-mac",
                                   "client-ip",  "client-mac",    "server-ip",
                                   "server-mac", "prefix-length", "duration-ms"};
    QHash<QString, int> optionCounts;
    for (const auto &argument : arguments) {
        if (!argument.startsWith("--"))
            continue;
        const QString option = argument.mid(2).section('=', 0, 0);
        if (valueOptions.contains(option) || option == "confirm-one-client-arp-probe")
            ++optionCounts[option];
    }
    for (auto it = optionCounts.cbegin(); it != optionCounts.cend(); ++it) {
        if (it.value() > 1) {
            error = "Duplicate command-line option.";
            return false;
        }
    }

    QCommandLineParser parser;
    configureParser(parser);
    if (!parser.parse(arguments)) {
        error = "Invalid command-line arguments.";
        return false;
    }
    if (parser.isSet("help") || parser.isSet("help-all") || parser.isSet("version")) {
        error = parser.isSet("version") ? "version" : parser.helpText();
        return false;
    }
    if (!parser.positionalArguments().isEmpty()) {
        error = "Unexpected positional command-line argument.";
        return false;
    }

    const QStringList required{"interface",  "research-ip", "research-mac", "client-ip",
                               "client-mac", "server-ip",   "server-mac",   "prefix-length"};
    for (const auto &name : required) {
        if (!parser.isSet(name)) {
            error = QStringLiteral("Missing required option: --%1").arg(name);
            return false;
        }
    }
    if (!parser.isSet("confirm-one-client-arp-probe")) {
        error = "Explicit confirmation is required (--confirm-one-client-arp-probe).";
        return false;
    }

    bool prefixOk = false, durationOk = false;
    const int prefix = parser.value("prefix-length").toInt(&prefixOk);
    const int duration = parser.value("duration-ms").toInt(&durationOk);
    if (!prefixOk || !durationOk || prefix < 1 || prefix > 30 || duration < 1 ||
        duration > ArpLabProbeRunner::maximumDurationMs) {
        error = "Subnet prefix or probe duration is outside its allowed range.";
        return false;
    }

    parsed.interfaceName = parser.value("interface");
    parsed.planInputs.selectedInterfaceName = parsed.interfaceName;
    parsed.planInputs.observedInterfaceName = parsed.interfaceName;
    parsed.planInputs.researchIp = parser.value("research-ip");
    parsed.planInputs.researchMac = parser.value("research-mac");
    parsed.planInputs.clientIp = parser.value("client-ip");
    parsed.planInputs.clientMac = parser.value("client-mac");
    parsed.planInputs.serverIp = parser.value("server-ip");
    parsed.planInputs.serverMac = parser.value("server-mac");
    parsed.planInputs.prefixLength = prefix;
    parsed.durationMs = duration;
    return true;
}

bool matchesResearchInterface(const ProbeArguments &arguments,
                              const ArpProbeInterfaceEvidence &evidence) {
    if (!evidence.found || !evidence.up || !evidence.running ||
        evidence.interfaceName != arguments.interfaceName ||
        evidence.macAddress.compare(arguments.planInputs.researchMac, Qt::CaseInsensitive) != 0)
        return false;
    for (const auto &address : evidence.ipv4Addresses) {
        if (address.ipv4 == arguments.planInputs.researchIp &&
            address.prefixLength == arguments.planInputs.prefixLength)
            return true;
    }
    return false;
}

template <typename WriterFactory>
ArpLabProbeCliResult executeProbe(const ProbeArguments &arguments,
                                  ArpProbeInterfaceInspector &interfaceInspector,
                                  ArpProbeWaiter &waiter, WriterFactory &&writerFactory) {
    try {
        if (waiter.interrupted())
            return jsonResult(130, "interrupted_before_redirect", false, false, false, false, false,
                              true);
    } catch (...) {
        return jsonResult(1, "signal_state_unavailable", false, false, false, false, false, false);
    }

    QString planError;
    const auto plan = ArpLabProbePlan::create(arguments.planInputs, &planError);
    if (!plan)
        return jsonResult(2, "invalid_probe_plan", false, false, false, false, false,
                          waiter.interrupted());

    ArpProbeInterfaceEvidence evidence;
    try {
        evidence = interfaceInspector.inspect(arguments.interfaceName);
    } catch (...) {
        return jsonResult(2, "interface_preflight_failed", false, false, false, false, false,
                          false);
    }
    if (!matchesResearchInterface(arguments, evidence))
        return jsonResult(2, "interface_preflight_failed", false, false, false, false, false,
                          waiter.interrupted());

    try {
        if (waiter.interrupted())
            return jsonResult(130, "interrupted_before_redirect", false, false, false, false, false,
                              true);
    } catch (...) {
        return jsonResult(1, "signal_state_unavailable", false, false, false, false, false, false);
    }

    auto writer = writerFactory(*plan);
    if (!writer->isReady()) {
        const auto writerStatus = writer->status();
        const bool closed = writer->close();
        return jsonResult(
            1, !closed ? QStringLiteral("close_unconfirmed") : bpfStatusCode(writerStatus), false,
            false, false, false, closed, waiter.interrupted());
    }

    auto result = ArpLabProbeRunner::run(*plan, *writer, waiter, arguments.durationMs);
    const bool closeConfirmed = writer->close();
    if (result.status == ArpLabProbeStatus::InterruptedBeforeRedirect) {
        return jsonResult(
            closeConfirmed ? 130 : 1,
            closeConfirmed ? statusCode(result.status) : QStringLiteral("cleanup_uncertain"),
            result.redirectAttempted, result.redirectWriteAccepted, result.restorationAttempted,
            result.restorationWriteAccepted, closeConfirmed, true);
    }
    const bool cleanupAccepted =
        result.restorationAttempted && result.restorationWriteAccepted && closeConfirmed;
    const auto status =
        cleanupAccepted ? statusCode(result.status) : QStringLiteral("cleanup_uncertain");
    const int exitCode =
        !cleanupAccepted ||
                result.status == ArpLabProbeStatus::RedirectWriteUncertainCorrectionAccepted
            ? 1
            : (result.status == ArpLabProbeStatus::CorrectionWriteAcceptedAfterSignal ? 130 : 0);
    return jsonResult(exitCode, status, result.redirectAttempted, result.redirectWriteAccepted,
                      result.restorationAttempted, result.restorationWriteAccepted, closeConfirmed,
                      result.interrupted);
}

class SystemWaiter final : public ArpProbeWaiter {
  public:
    explicit SystemWaiter(SignalAwareWaiter &signalWaiter) : signalWaiter_(signalWaiter) {}
    bool interrupted() const override { return signalWaiter_.interrupted(); }
    ArpProbeWaitOutcome waitFor(int durationMs) override {
        return signalWaiter_.waitFor(durationMs);
    }

  private:
    SignalAwareWaiter &signalWaiter_;
};
} // namespace

ArpLabProbeCliResult ArpLabProbeCli::run(const QStringList &arguments) {
    ProbeArguments parsed;
    QString error;
    if (!parseArguments(arguments, parsed, error)) {
        if (error == "version")
            return {0, QStringLiteral("0.1.0\n"), {}};
        if (error.contains("Usage:") || error.startsWith("Usage:"))
            return {0, error, {}};
        return {2, {}, error + '\n'};
    }

    SignalAwareWaiter signalWaiter;
    if (!signalWaiter.ready())
        return jsonResult(1, "signal_handler_setup_failed", false, false, false, false, false,
                          false);
    SystemWaiter waiter(signalWaiter);
    SystemInterfaceInspector inspector;
    return executeProbe(parsed, inspector, waiter, [](const ArpLabProbePlan &plan) {
        return std::make_unique<MacBpfArpPacketIo>(plan);
    });
}

ArpLabProbeCliResult ArpLabProbeCli::run(const QStringList &arguments, BpfSystemCalls &systemCalls,
                                         ArpProbeWaiter &waiter,
                                         ArpProbeInterfaceInspector &interfaceInspector) {
    ProbeArguments parsed;
    QString error;
    if (!parseArguments(arguments, parsed, error)) {
        if (error == "version")
            return {0, QStringLiteral("0.1.0\n"), {}};
        if (error.startsWith("Usage:"))
            return {0, error, {}};
        return {2, {}, error + '\n'};
    }
    return executeProbe(parsed, interfaceInspector, waiter, [&](const ArpLabProbePlan &plan) {
        return std::make_unique<MacBpfArpPacketIo>(plan, systemCalls);
    });
}

} // namespace interceptor
