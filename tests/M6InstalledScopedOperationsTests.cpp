#include "network/InstalledScopedOperations.hpp"

#include <QDir>
#include <QElapsedTimer>
#include <QFile>

#include <QTemporaryDir>
#include <QThread>
#include <QtTest>
#include <QNetworkInterface>

#include <chrono>
#include <fcntl.h>
#include <optional>
#include <thread>
#include <unistd.h>
#include <sys/stat.h>

using namespace interceptor;

namespace {

struct ScopedCommandCall {
    QString program;
    QStringList arguments;
    QString standardInput;
};

class FakeScopedCommandIo final : public InstalledScopedCommandIo {
  public:
    QList<ScopedCommandCall> calls;

    // Per-step outcomes.
    bool arpLookupSucceeds = true;
    QString interfaceName = QStringLiteral("en0"); // must match the session tuple interface
    QString clientMac = QStringLiteral("02:00:00:00:00:10");
    QString upstreamMac = QStringLiteral("02:00:00:00:00:30");
    QString arpOutput; // when non-empty, overrides the synthesized per-address output
    bool enableStarted = true;
    bool enableReaped = true;
    bool enableParses = true;
    bool anchorInstallSucceeds = true;
    bool listingSucceeds = true;
    QString natListing = QStringLiteral("rdr pass in quick on en0\n");
    QString ruleListing = QStringLiteral("pass in quick on en0\n");
    bool flushSucceeds = true;
    bool anchorFlushed = false; // after -F the verified-empty listings must come back empty
    bool releaseSucceeds = true;
    QString referencesOutput = QStringLiteral("no references\n");
    bool referencesSucceeds = true;

    static constexpr unsigned long long token = 42;

    Result run(const std::string &program, const std::vector<std::string> &arguments,
               const std::string *standardInput, int, std::size_t) override {
        ScopedCommandCall call;
        call.program = QString::fromStdString(program);
        for (const std::string &argument : arguments)
            call.arguments << QString::fromStdString(argument);
        if (standardInput)
            call.standardInput = QString::fromStdString(*standardInput);
        calls << call;

        Result result;
        result.started = true;
        result.reaped = true;
        result.normalExit = true;
        result.exitCode = 0;
        if (call.program == QStringLiteral("/usr/sbin/arp")) {
            if (!arpLookupSucceeds) {
                result.exitCode = 1;
                return result;
            }
            if (!arpOutput.isEmpty()) {
                result.standardOutput = arpOutput.toStdString();
                return result;
            }
            const QString address = call.arguments.value(1);
            const QString mac = address == QStringLiteral("192.0.2.30") ? upstreamMac : clientMac;
            // The reviewed parser stops matching at the end of the line, so the synthetic
            // neighbor line ends right after the interface token.
            result.standardOutput =
                QStringLiteral("? (%1) at %2 on %3\n").arg(address, mac, interfaceName).toStdString();
            return result;
        }
        const bool isPfctl = call.program == QStringLiteral("/sbin/pfctl");
        if (isPfctl && call.arguments.value(0) == QStringLiteral("-E")) {
            if (!enableStarted) {
                result.started = false;
                result.reaped = false;
                return result;
            }
            result.reaped = enableReaped;
            result.normalExit = enableReaped;
            result.exitCode = enableReaped ? 0 : -1;
            result.standardOutput = (enableParses && enableReaped)
                                        ? std::string("Token : 42\n")
                                        : std::string("something odd\n");
            return result;
        }
        if (isPfctl && call.arguments.value(2) == QStringLiteral("-f") &&
            call.arguments.value(3) == QStringLiteral("-")) {
            if (!anchorInstallSucceeds)
                result.exitCode = 1;
            return result;
        }
        if (isPfctl && call.arguments.value(0) == QStringLiteral("-s") &&
             call.arguments.value(2) == QStringLiteral("-a")) {
            if (!listingSucceeds) {
                result.exitCode = 1;
                return result;
            }
            if (anchorFlushed) {
                result.standardOutput = "   "; // whitespace-only listing: verified empty
                return result;
            }
            const bool isNat = call.arguments.value(1) == QStringLiteral("nat");
            result.standardOutput = (isNat ? natListing : ruleListing).toStdString();
            return result;
        }
        if (isPfctl && call.arguments.value(2) == QStringLiteral("-F")) {
            if (!flushSucceeds) {
                result.exitCode = 1;
                return result;
            }
            anchorFlushed = true;
            return result;
        }
        if (isPfctl && call.arguments.value(0) == QStringLiteral("-X")) {
            if (!releaseSucceeds)
                result.exitCode = 1;
            return result;
        }
        if (isPfctl && call.arguments.value(1) == QStringLiteral("References")) {
            if (!referencesSucceeds) {
                result.exitCode = 1;
                return result;
            }
            result.standardOutput = referencesOutput.toStdString();
            return result;
        }
        result.exitCode = 1;
        return result;
    }

    QStringList programLines() const {
        QStringList lines;
        for (const ScopedCommandCall &call : calls)
            lines << (call.program + QStringLiteral(" ") + call.arguments.join(QStringLiteral(" ")));
        return lines;
    }
};

class FakeScopedArpIo final : public InstalledScopedArpIo {
  public:
    QStringList log;
    QList<QByteArray> frames;
    int openCalls = 0;
    int closeCalls = 0;
    bool openSucceeds = true;
    int failSendsAfter = -1; // after how many successful sends to start failing (-1: never)
    bool openErrorSeen = false;

    bool open(const std::string &interfaceName, std::string *error) override {
        ++openCalls;
        openedInterface = QString::fromStdString(interfaceName);
        if (error)
            error->clear();
        if (openSucceeds)
            return true;
        if (error)
            *error = "arb_device_unavailable";
        return false;
    }
    bool sendFrame(const unsigned char *frame, std::size_t length) override {
        if (failSendsAfter >= 0 && frames.size() > static_cast<std::size_t>(failSendsAfter)) {
            log << QStringLiteral("send-failed");
            return false;
        }
        frames << QByteArray(reinterpret_cast<const char *>(frame), int(length));
        log << QStringLiteral("send");
        return true;
    }
    void close() override {
        ++closeCalls;
        log << QStringLiteral("close");
    }

    QString openedInterface;
};

struct SettingObservation {
    QString name;
    int value = 0;
    bool isWrite = false;
    bool operator==(const SettingObservation &other) const {
        return name == other.name && value == other.value && isWrite == other.isWrite;
    }
};

class FakeScopedSettingIo final : public InstalledScopedSettingIo {
  public:
    QList<SettingObservation> observations;
    int forwarding = 0;
    int sendRedirects = 1;
    bool readSucceeds = true;
    bool writeSucceeds = true;

    bool read(const std::string &name, int *value) override {
        if (!readSucceeds)
            return false;
        *value = name == std::string("net.inet.ip.forwarding") ? forwarding : sendRedirects;
        observations << SettingObservation{QString::fromStdString(name), *value, false};
        return true;
    }
    bool write(const std::string &name, int value) override {
        observations << SettingObservation{QString::fromStdString(name), value, true};
        if (!writeSucceeds)
            return false;
        if (name == std::string("net.inet.ip.forwarding"))
            forwarding = value;
        else
            sendRedirects = value;
        return true;
    }
};

class ScopedDirectory final {
  public:
    ScopedDirectory() : dir_(QStringLiteral("/tmp/m6-scoped-ops-XXXXXX")) {
        if (!dir_.isValid())
            return;
        const QByteArray path = dir_.path().toLocal8Bit();
        if (::chmod(path.constData(), 0700) != 0)
            return;
        descriptor_ = ::open(path.constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    }
    ~ScopedDirectory() {
        if (descriptor_ >= 0)
            ::close(descriptor_);
    }
    bool valid() const { return dir_.isValid() && descriptor_ >= 0; }
    int fd() const { return descriptor_; }
    QString journalPath() const {
        return dir_.filePath(QStringLiteral("scoped-session-obligations.journal"));
    }
    QStringList journalRecords() const {
        QFile file(journalPath());
        if (!file.open(QIODevice::ReadOnly))
            return {};
        const QString content = QString::fromUtf8(file.readAll());
        QStringList records;
        for (const QString &line : content.split(QLatin1Char('\n')))
            if (!line.isEmpty())
                records << line;
        return records;
    }
    void seedJournal(const QStringList &records) {
        QFile file(journalPath());
        QVERIFY(file.open(QIODevice::WriteOnly));
        for (const QString &record : records)
            file.write((record + QStringLiteral("\n")).toUtf8());
        file.close();
    }

  private:
    QTemporaryDir dir_;
    int descriptor_ = -1;
};

// A tuple with a real, active, non-loopback interface is required for the fresh interface-MAC
// observation (the only non-injectable fact in the installed backend).
std::optional<QString> activeNonLoopbackInterface() {
    for (const QNetworkInterface &entry : QNetworkInterface::allInterfaces()) {
        const QNetworkInterface::InterfaceFlags flags = entry.flags();
        if (!flags.testFlag(QNetworkInterface::IsUp) ||
            !flags.testFlag(QNetworkInterface::IsRunning) ||
            flags.testFlag(QNetworkInterface::IsLoopBack))
            continue;
        for (const QNetworkAddressEntry &address : entry.addressEntries())
            if (address.ip().protocol() == QAbstractSocket::IPv4Protocol)
                return entry.name();
    }
    return std::nullopt;
}

InstalledSessionTuple tupleFor(const QString &interfaceName) {
    return {interfaceName.toStdString(), "192.0.2.10", "192.0.2.30", "192.0.2.20", 18081, 11434};
}

constexpr int refreshTickIntervalMs = InstalledScopedOperations::minimumRefreshIntervalMs;

} // namespace

class M6InstalledScopedOperationsTests final : public QObject {
    Q_OBJECT

    bool haveInterface = false;
    QString interfaceName;

  private slots:
    void initTestCase() {
        const auto active = activeNonLoopbackInterface();
        haveInterface = active.has_value();
        if (active)
            interfaceName = *active;
    }

    void constructorValidatesJournalAndDefaults() {
        ScopedDirectory directory;
        QVERIFY(directory.valid());
        FakeScopedCommandIo commands;
        commands.interfaceName = interfaceName;
        FakeScopedArpIo arp;
        FakeScopedSettingIo settings;
        InstalledScopedOperations operations(commands, arp, settings, directory.fd(),
                                             InstalledScopedOperations::defaultRefreshIntervalMs,
                                             [] { return std::string("abcd"); });
        // Rootless runs report non-root; effectiveRoot() matches the process.
        QCOMPARE(operations.effectiveRoot(), ::geteuid() == 0);
    }

    void pendingJournalObligationsRejectStartBeforeAnyObservation() {
        ScopedDirectory directory;
        QVERIFY(directory.valid());
        directory.seedJournal({QStringLiteral("anchor llm_interceptor/leftover")});
        FakeScopedCommandIo commands;
        commands.interfaceName = interfaceName;
        FakeScopedArpIo arp;
        FakeScopedSettingIo settings;
        InstalledScopedOperations operations(commands, arp, settings, directory.fd(), refreshTickIntervalMs,
                                             [] { return std::string("deadbeef"); });
        std::string error;
        const auto tuple = tupleFor(interfaceName.isEmpty() ? QStringLiteral("en0") : interfaceName);
        QVERIFY(!operations.startOwnedOperations(tuple, &error));
        QCOMPARE(QString::fromStdString(error), QStringLiteral("recovery_pending"));
        // Fail-closed before any network observation or setup mutation.
        QVERIFY(commands.calls.isEmpty());
        QVERIFY(settings.observations.isEmpty());
        QVERIFY(arp.openCalls == 0);
        QCOMPARE(directory.journalRecords(),
                  QStringList{QStringLiteral("anchor llm_interceptor/leftover")});
    }

    void orderedHappyPathInstallsVerifiesRefreshesAndJournals() {
        if (!haveInterface)
            QSKIP("An active non-loopback IPv4 interface is required for the fresh interface MAC.");
        ScopedDirectory directory;
        QVERIFY(directory.valid());
        FakeScopedCommandIo commands;
        commands.interfaceName = interfaceName;
        FakeScopedArpIo arp;
        FakeScopedSettingIo settings;
        InstalledScopedOperations operations(commands, arp, settings, directory.fd(), refreshTickIntervalMs,
                                             [] { return std::string("0000cafebabe0000"); });
        std::string error;
        const auto tuple = tupleFor(interfaceName);
        QVERIFY2(operations.startOwnedOperations(tuple, &error),
                 qPrintable(QString::fromStdString(error)));

        // Fixed order: fresh neighbor facts -> sysctl snapshot -> pfctl -E (journaled) ->
        // anchor install with the scoped rules -> active-evaluation listings -> settings.
        const QStringList expected = {
            QStringLiteral("/usr/sbin/arp -n 192.0.2.10"),
            QStringLiteral("/usr/sbin/arp -n 192.0.2.30"),
            QStringLiteral("/sbin/pfctl -E"),
            QStringLiteral("/sbin/pfctl -a llm_interceptor/0000cafebabe0000 -f -"),
            QStringLiteral("/sbin/pfctl -s nat -a llm_interceptor/0000cafebabe0000"),
            QStringLiteral("/sbin/pfctl -s rules -a llm_interceptor/0000cafebabe0000"),
        };
        QCOMPARE(commands.programLines().mid(0, expected.size()), expected);

        // The scoped anchor rules carry exactly the tuple: one rdr for the client plus the
        // paired pass rules; never a wider match.
        const ScopedCommandCall &install = commands.calls.value(3);
        const QStringList expectedInstallArguments = {
            QStringLiteral("-a"), QStringLiteral("llm_interceptor/0000cafebabe0000"),
            QStringLiteral("-f"), QStringLiteral("-")};
        QCOMPARE(install.arguments, expectedInstallArguments);
        const QStringList ruleLines = install.standardInput.split(QLatin1Char('\n'),
                                                                  Qt::SkipEmptyParts);
        QCOMPARE(ruleLines.size(), 3);
        QVERIFY(ruleLines.at(0).contains(QStringLiteral("rdr on \"") + interfaceName));
        QVERIFY(ruleLines.at(0).contains(QStringLiteral("from 192.0.2.10 to 192.0.2.30")));
        QVERIFY(ruleLines.at(0).contains(QStringLiteral("-> 192.0.2.20 port 11434")));
        QVERIFY(ruleLines.at(1).contains(QStringLiteral("pass in quick")));
        QVERIFY(ruleLines.at(2).contains(QStringLiteral("pass out quick")));
        QVERIFY(install.standardInput.contains(QStringLiteral("label \"llm_0000cafebabe0000\"")));

        // Journal records every obligation before it can be dropped.
        QVERIFY(directory.journalRecords().contains(QStringLiteral("pf-token 42")));
        QVERIFY(directory.journalRecords().contains(
            QStringLiteral("anchor llm_interceptor/0000cafebabe0000")));

        // Settings snapshot first, values written only where not already desired.
        QVERIFY(settings.observations.size() >= 2);
        QCOMPARE(settings.observations.at(0).name, QStringLiteral("net.inet.ip.forwarding"));
        QCOMPARE(settings.observations.at(0).isWrite, false);
        QVERIFY(settings.observations.contains(
            {QStringLiteral("net.inet.ip.forwarding"), 1, true}));
        QVERIFY(settings.observations.contains(
            {QStringLiteral("net.inet.ip.redirect"), 0, true}));

        // Pairwise redirect frames exactly once each: 60 bytes, ARP reply, Ethernet+ARP sender
        // both the research (this) host.
        QCOMPARE(arp.frames.size(), 2);
        for (const QByteArray &frame : arp.frames) {
            QCOMPARE(frame.size(), qsizetype(60));
            QCOMPARE((unsigned char)frame.at(12), 0x08);
            QCOMPARE((unsigned char)frame.at(13), 0x06);
            QCOMPARE((unsigned char)frame.at(20), 0x00);
            QCOMPARE((unsigned char)frame.at(21), 0x02); // reply
        }

        // The bounded refresh loop re-announces ONLY the client mapping (frame zero).
        QElapsedTimer refreshDeadline;
        refreshDeadline.start();
        while (arp.frames.size() < 3 && refreshDeadline.elapsed() < 1500)
            QThread::msleep(25);
        QVERIFY(arp.frames.size() >= 3);
        QCOMPARE(arp.frames.at(2), arp.frames.at(0));

        bool cleaned = false;
        settings.forwarding = 1;
        settings.sendRedirects = 0; // after writes they are already desired
        QVERIFY2(operations.stopOwnedOperations(&cleaned, &error), qPrintable(QString::fromStdString(error)));
        QVERIFY(cleaned);
        QVERIFY(directory.journalRecords().isEmpty());

        // Reverse order: flush nat/rules -> verified-empty listings -> settings restore ->
        // exact token release -> reference absence.
        const QStringList teardown = commands.programLines().mid(expected.size());
        QVERIFY(teardown.contains(
            QStringLiteral("/sbin/pfctl -a llm_interceptor/0000cafebabe0000 -F nat")));
        QVERIFY(teardown.contains(
            QStringLiteral("/sbin/pfctl -a llm_interceptor/0000cafebabe0000 -F rules")));
        QVERIFY(teardown.indexOf(
                    QStringLiteral("/sbin/pfctl -s nat -a llm_interceptor/0000cafebabe0000")) >
                teardown.indexOf(
                    QStringLiteral("/sbin/pfctl -a llm_interceptor/0000cafebabe0000 -F nat")));
        QVERIFY(teardown.contains(QStringLiteral("/sbin/pfctl -X 42")));
        QVERIFY(teardown.contains(QStringLiteral("/sbin/pfctl -s References")));
        QVERIFY(teardown.indexOf(QStringLiteral("/sbin/pfctl -s References")) >
                teardown.indexOf(QStringLiteral("/sbin/pfctl -X 42")));
        // Pairwise restoration frames were sent during teardown.
        QVERIFY(arp.frames.size() >= 5);
        QVERIFY(arp.closeCalls >= 1);
    }

    void uncertainOrFailedStartStepsKeepOrligationsAndStayFailClosed() {
        if (!haveInterface)
            QSKIP("An active non-loopback IPv4 interface is required for the fresh interface MAC.");

        // Settings unreadable: no PF/ARP step may run.
        {
            ScopedDirectory directory;
            QVERIFY(directory.valid());
            FakeScopedCommandIo commands;
            commands.interfaceName = interfaceName;
            FakeScopedArpIo arp;
            FakeScopedSettingIo settings;
            settings.readSucceeds = false;
            InstalledScopedOperations operations(commands, arp, settings, directory.fd(),
                                                 refreshTickIntervalMs,
                                                 [] { return std::string("0000beefcafe0000"); });
            std::string error;
            QVERIFY(!operations.startOwnedOperations(tupleFor(interfaceName), &error));
            QCOMPARE(QString::fromStdString(error), QStringLiteral("settings_unavailable"));
            // The lease/token steps never ran: the settings snapshot precedes pfctl -E.
            QVERIFY(!commands.programLines().contains(QStringLiteral("/sbin/pfctl -E")));
            QVERIFY(arp.openCalls == 0);
            // The rolled-back start left no durable obligation.
            QVERIFY(directory.journalRecords().isEmpty());
        }
        // Neighbor facts missing (arp -n failed or unresolvable): stop before any mutation.
        {
            ScopedDirectory directory;
            QVERIFY(directory.valid());
            FakeScopedCommandIo commands;
            commands.interfaceName = interfaceName;
            FakeScopedArpIo arp;
            FakeScopedSettingIo settings;
            commands.arpLookupSucceeds = false;
            InstalledScopedOperations operations(commands, arp, settings, directory.fd(),
                                                 refreshTickIntervalMs,
                                                 [] { return std::string("0000beefcafe0000"); });
            std::string error;
            QVERIFY(!operations.startOwnedOperations(tupleFor(interfaceName), &error));
            QCOMPARE(QString::fromStdString(error), QStringLiteral("neighbor_identity_unavailable"));
            QVERIFY(directory.journalRecords().isEmpty());
            QVERIFY(arp.openCalls == 0);
        }
        // Unknown/MAC-malformed arp output is never bridged to a frame.
        for (const QString &malformed :
             {QStringLiteral("? (192.0.2.10) at nonsense on en0 ifscope\n"),
              QStringLiteral("? (192.0.2.10) at 2:0:0:0:0:10 on lo0 ifscope\n"),
              QStringLiteral("? (192.0.2.10) 2:0:0:0:0:10 on en0 ifscope\n")}) {
            ScopedDirectory directory;
            QVERIFY(directory.valid());
            FakeScopedCommandIo commands;
            commands.interfaceName = interfaceName;
            commands.arpOutput = malformed;
            FakeScopedArpIo arp;
            FakeScopedSettingIo settings;
            InstalledScopedOperations operations(commands, arp, settings, directory.fd(),
                                                 refreshTickIntervalMs,
                                                 [] { return std::string("0000beefcafe0000"); });
            std::string error;
            QVERIFY(!operations.startOwnedOperations(tupleFor(interfaceName), &error));
            QCOMPARE(QString::fromStdString(error),
                     QStringLiteral("neighbor_identity_unavailable"));
        }
        // pfctl -E started but unreaped/unparsable: uncertain, obligation journaled.
        {
            ScopedDirectory directory;
            QVERIFY(directory.valid());
            FakeScopedCommandIo commands;
            commands.interfaceName = interfaceName;
            commands.enableStarted = false; // spawn failed: no obligation may be invented
            FakeScopedArpIo arp;
            FakeScopedSettingIo settings;
            InstalledScopedOperations operations(commands, arp, settings, directory.fd(),
                                                 refreshTickIntervalMs,
                                                 [] { return std::string("0000beefcafe0000"); });
            std::string error;
            QVERIFY(!operations.startOwnedOperations(tupleFor(interfaceName), &error));
            QCOMPARE(QString::fromStdString(error),
                     QStringLiteral("pf_reference_unavailable"));
            QVERIFY(directory.journalRecords().isEmpty());
        }
        {
            ScopedDirectory directory;
            QVERIFY(directory.valid());
            FakeScopedCommandIo commands;
            commands.interfaceName = interfaceName;
            commands.enableReaped = false; // ran but never reaped: uncertain by failure matrix
            FakeScopedArpIo arp;
            FakeScopedSettingIo settings;
            InstalledScopedOperations operations(commands, arp, settings, directory.fd(),
                                                 refreshTickIntervalMs,
                                                 [] { return std::string("0000beefcafe0000"); });
            std::string error;
            QVERIFY(!operations.startOwnedOperations(tupleFor(interfaceName), &error));
            QCOMPARE(QString::fromStdString(error),
                     QStringLiteral("pf_reference_uncertain"));
            QVERIFY(directory.journalRecords().contains(QStringLiteral("pf-token-uncertain")));
            // The next process reads the durable obligation as recovery_pending.
            FakeScopedCommandIo restartCommands;
            restartCommands.interfaceName = interfaceName;
            FakeScopedArpIo restartArp;
            FakeScopedSettingIo restartSettings;
            InstalledScopedOperations restart(restartCommands, restartArp, restartSettings,
                                              directory.fd(), refreshTickIntervalMs,
                                              [] { return std::string("0000beefcafe0000"); });
            std::string restartError;
            QVERIFY(!restart.startOwnedOperations(tupleFor(interfaceName), &restartError));
            QCOMPARE(QString::fromStdString(restartError), QStringLiteral("recovery_pending"));
            QVERIFY(restartCommands.calls.isEmpty());
        }
        // Anchor install uncertain: the obligation stands until verified removed. With the
        // rollback's flush failing too, the durable record must survive a restart.
        {
            ScopedDirectory directory;
            QVERIFY(directory.valid());
            FakeScopedCommandIo commands;
            commands.interfaceName = interfaceName;
            commands.anchorInstallSucceeds = false;
            commands.flushSucceeds = false; // the fail-closed rollback cannot verify removal
            FakeScopedArpIo arp;
            FakeScopedSettingIo settings;
            InstalledScopedOperations operations(commands, arp, settings, directory.fd(),
                                                 refreshTickIntervalMs,
                                                 [] { return std::string("0000beefcafe0000"); });
            std::string error;
            QVERIFY(!operations.startOwnedOperations(tupleFor(interfaceName), &error));
            QCOMPARE(QString::fromStdString(error), QStringLiteral("anchor_install_uncertain"));
            QVERIFY(directory.journalRecords().contains(
                QStringLiteral("anchor llm_interceptor/0000beefcafe0000")));
        }
        // The active-evaluation listing lacking the owned rules never reaches a frame.
        {
            ScopedDirectory directory;
            QVERIFY(directory.valid());
            FakeScopedCommandIo commands;
            commands.interfaceName = interfaceName;
            commands.natListing = QStringLiteral("\n");
            FakeScopedArpIo arp;
            FakeScopedSettingIo settings;
            InstalledScopedOperations operations(commands, arp, settings, directory.fd(),
                                                 refreshTickIntervalMs,
                                                 [] { return std::string("0000beefcafe0000"); });
            std::string error;
            QVERIFY(!operations.startOwnedOperations(tupleFor(interfaceName), &error));
            QCOMPARE(QString::fromStdString(error),
                     QStringLiteral("anchor_verification_failed"));
            QVERIFY(arp.openCalls == 0);
        }
        // ARP writer failing at open or at the first frame keeps its obligation.
        {
            ScopedDirectory directory;
            QVERIFY(directory.valid());
            FakeScopedCommandIo commands;
            commands.interfaceName = interfaceName;
            FakeScopedArpIo arp;
            arp.openSucceeds = false;
            FakeScopedSettingIo settings;
            InstalledScopedOperations operations(commands, arp, settings, directory.fd(),
                                                 refreshTickIntervalMs,
                                                 [] { return std::string("0000beefcafe0000"); });
            std::string error;
            QVERIFY(!operations.startOwnedOperations(tupleFor(interfaceName), &error));
            QCOMPARE(QString::fromStdString(error), QStringLiteral("arp_writer_unavailable"));
            // No frame was ever sent and every earlier step rolled back verified, so the
            // durable obligation is truthfully empty again.
            QVERIFY(directory.journalRecords().isEmpty());
        }
        {
            ScopedDirectory directory;
            QVERIFY(directory.valid());
            FakeScopedCommandIo commands;
            commands.interfaceName = interfaceName;
            FakeScopedArpIo arp;
            arp.failSendsAfter = 0; // the very first redirect frame fails
            FakeScopedSettingIo settings;
            InstalledScopedOperations operations(commands, arp, settings, directory.fd(),
                                                 refreshTickIntervalMs,
                                                 [] { return std::string("0000beefcafe0000"); });
            std::string error;
            QVERIFY(!operations.startOwnedOperations(tupleFor(interfaceName), &error));
            QCOMPARE(QString::fromStdString(error), QStringLiteral("arp_write_failed"));
        }
    }

    void startOwnerIsExclusiveAndDestroyedOwnerRunsCleanup() {
        if (!haveInterface)
            QSKIP("An active non-loopback IPv4 interface is required for the fresh interface MAC.");
        ScopedDirectory directory;
        QVERIFY(directory.valid());
        FakeScopedCommandIo commands;
        commands.interfaceName = interfaceName;
        FakeScopedArpIo arp;
        FakeScopedSettingIo settings;
        auto operations = std::make_unique<InstalledScopedOperations>(
            commands, arp, settings, directory.fd(), refreshTickIntervalMs,
            [] { return std::string("0000f00dcafe0000"); });
        std::string firstError, secondError;
        bool firstStart = false, secondStart = false;
        std::thread second([&] {
          secondStart = operations->startOwnedOperations(tupleFor(interfaceName), &secondError);
        });
        firstStart = operations->startOwnedOperations(tupleFor(interfaceName), &firstError);
        second.join();
        QVERIFY(firstStart != secondStart); // serialized queue: exactly one session owner
        const std::string &loserError = firstStart ? secondError : firstError;
        QCOMPARE(QString::fromStdString(loserError), QStringLiteral("session_already_owned"));

        // Destruction of an active owner drives the verified teardown on its queue.
        operations.reset();
        const QStringList teardownLog = commands.programLines();
        QVERIFY(teardownLog.join(QLatin1Char('\n')).contains(QStringLiteral(" -F nat")));
        QVERIFY(teardownLog.contains(QStringLiteral("/sbin/pfctl -s References")));
        QVERIFY(arp.closeCalls >= 1);
        QVERIFY(directory.journalRecords().isEmpty());

        // After the verified teardown the next owner can start again on the same directory.
        FakeScopedCommandIo restartCommands;
        restartCommands.interfaceName = interfaceName;
        FakeScopedArpIo restartArp;
        FakeScopedSettingIo restartSettings;
        InstalledScopedOperations restart(restartCommands, restartArp, restartSettings,
                                          directory.fd(), refreshTickIntervalMs,
                                          [] { return std::string("0000f00dcafe0000"); });
        std::string restartError;
        QVERIFY2(restart.startOwnedOperations(tupleFor(interfaceName), &restartError),
                 qPrintable(QString::fromStdString(restartError)));
        bool cleaned = false;
        QVERIFY2(restart.stopOwnedOperations(&cleaned, &restartError), qPrintable(QString::fromStdString(restartError)));
        QVERIFY(cleaned);
    }

    void stopRetryKeepsTokenObligationUntilAbsenceIsVerified() {
        if (!haveInterface)
            QSKIP("An active non-loopback IPv4 interface is required for the fresh interface MAC.");
        ScopedDirectory directory;
        QVERIFY(directory.valid());
        FakeScopedCommandIo commands;
        commands.interfaceName = interfaceName;
        commands.referencesOutput = QStringLiteral("Token : 42\n"); // still active after -X
        FakeScopedArpIo arp;
        FakeScopedSettingIo settings;
        InstalledScopedOperations operations(commands, arp, settings, directory.fd(),
                                             refreshTickIntervalMs,
                                             [] { return std::string("0000cafebeef0000"); });
        std::string error;
        QVERIFY(operations.startOwnedOperations(tupleFor(interfaceName), &error));

        bool cleaned = true;
        QVERIFY(!operations.stopOwnedOperations(&cleaned, &error));
        QVERIFY(!cleaned);
        QCOMPARE(QString::fromStdString(error), QStringLiteral("pf_token_still_active"));
        QVERIFY(!directory.journalRecords().isEmpty());

        // An unrecognized reference table shape stays Unknown: fail-closed, never a guessed
        // cleanup success.
        commands.referencesOutput = QStringLiteral("weird table\n");
        cleaned = true;
        QVERIFY(!operations.stopOwnedOperations(&cleaned, &error));
        QVERIFY(!cleaned);
        QCOMPARE(QString::fromStdString(error), QStringLiteral("pf_token_absence_unknown"));

        commands.referencesOutput = QStringLiteral("no references\n");
        cleaned = false;
        QVERIFY2(operations.stopOwnedOperations(&cleaned, &error), qPrintable(QString::fromStdString(error)));
        QVERIFY(cleaned);
        QVERIFY(directory.journalRecords().isEmpty());
    }

    void emptyAnchorKeyFailsStartAndRetriesAfterAFixedKey() {
        if (!haveInterface)
            QSKIP("An active non-loopback IPv4 interface is required for the fresh interface MAC.");
        ScopedDirectory directory;
        QVERIFY(directory.valid());
        FakeScopedCommandIo commands;
        commands.interfaceName = interfaceName;
        FakeScopedArpIo arp;
        FakeScopedSettingIo settings;
        bool broken = true;
        InstalledScopedOperations operations(commands, arp, settings, directory.fd(),
                                             refreshTickIntervalMs,
                                             [&broken] {
                                                 return broken ? std::string()
                                                               : std::string("0000aaaabbbb0000");
                                             });
        std::string error;
        QVERIFY(!operations.startOwnedOperations(tupleFor(interfaceName), &error));
        QCOMPARE(QString::fromStdString(error), QStringLiteral("session_key_unavailable"));
        // No anchor was journaled, so a retry with a working key can still own a session.
        broken = false;
        QVERIFY2(operations.startOwnedOperations(tupleFor(interfaceName), &error),
                 qPrintable(QString::fromStdString(error)));
        bool cleaned = false;
        QVERIFY2(operations.stopOwnedOperations(&cleaned, &error), qPrintable(QString::fromStdString(error)));
        QVERIFY(cleaned);
        QVERIFY(directory.journalRecords().isEmpty());
    }
};

QTEST_GUILESS_MAIN(M6InstalledScopedOperationsTests)
#include "M6InstalledScopedOperationsTests.moc"
