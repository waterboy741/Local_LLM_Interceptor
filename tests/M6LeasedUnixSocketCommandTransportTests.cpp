#include "network/HelperDispatcher.hpp"
#include "network/LeasedUnixSocketCommandTransport.hpp"
#include "network/UnixPeerCredentials.hpp"

#include <QTemporaryDir>
#include <QtTest>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

using namespace interceptor;

class LeasedTransportFakeOperations final : public SystemOperations {
  public:
    QStringList calls;
    int forwarding = 0;
    int redirects = 1;

    std::optional<int> readSetting(NetworkSetting setting) override {
        calls << (setting == NetworkSetting::Forwarding ? "read-forwarding" : "read-redirects");
        return setting == NetworkSetting::Forwarding ? forwarding : redirects;
    }
    SettingChange compareAndSetSetting(NetworkSetting setting, int expected, int desired) override {
        calls << "compare-and-set";
        auto &current = setting == NetworkSetting::Forwarding ? forwarding : redirects;
        if (current == desired)
            return SettingChange::Unchanged;
        if (current != expected)
            return SettingChange::Conflict;
        current = desired;
        return SettingChange::Applied;
    }
    std::optional<QString> acquireSessionLease(const SessionSnapshot &) override {
        calls << "acquire-lease";
        return QStringLiteral("synthetic-lease");
    }
    bool releaseSessionLease(const QString &) override {
        calls << "release-lease";
        return true;
    }
    std::optional<QString> acquirePfReference() override {
        calls << "acquire-pf-reference";
        return QStringLiteral("synthetic-pf-reference");
    }
    bool releasePfReference(const QString &) override {
        calls << "release-pf-reference";
        return true;
    }
    bool installAnchor(const SessionSnapshot &) override {
        calls << "install-anchor";
        return true;
    }
    bool removeAnchor(const SessionSnapshot &) override {
        calls << "remove-anchor";
        return true;
    }
    bool clearOwnedState(const SessionSnapshot &) override {
        calls << "clear-state";
        return true;
    }
    bool beginArp(const SessionSnapshot &) override {
        calls << "begin-arp";
        return true;
    }
    bool endArp(const SessionSnapshot &) override {
        calls << "end-arp";
        return true;
    }
    bool restoreNeighbors(const SessionSnapshot &) override {
        calls << "restore-neighbors";
        return true;
    }
    bool interfaceAvailable(const SessionSnapshot &) override {
        calls << "interface-available";
        return true;
    }
    bool retainRecovery(const SessionSnapshot &, const OwnershipJournal &) override {
        calls << "retain-recovery";
        return true;
    }
};

class PrivateLeaseDirectory {
  public:
    PrivateLeaseDirectory() {
        if (!directory_.isValid())
            return;
        const QByteArray path = directory_.path().toLocal8Bit();
        if (::chmod(path.constData(), 0700) != 0)
            return;
        descriptor_ = ::open(path.constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    }
    ~PrivateLeaseDirectory() {
        if (descriptor_ >= 0)
            ::close(descriptor_);
    }
    bool valid() const { return directory_.isValid() && descriptor_ >= 0; }
    int fd() const { return descriptor_; }

  private:
    QTemporaryDir directory_;
    int descriptor_ = -1;
};

class M6LeasedUnixSocketCommandTransportTests final : public QObject {
    Q_OBJECT

    static SessionSnapshot snapshot() {
        SessionConfig config{"synthetic0", "192.0.2.10",      "192.0.2.30",
                             18081,        {"/api/generate"}, false};
        NetworkFacts facts;
        facts.interfaceName = "synthetic0";
        facts.researchIp = "192.0.2.20";
        facts.researchMac = "02:00:00:00:00:20";
        facts.clientMac = "02:00:00:00:00:10";
        facts.serverMac = "02:00:00:00:00:30";
        facts.proxyServerIp = config.serverIp;
        facts.proxyServerPort = config.serverPort;
        facts.proxyListenPort = 11434;
        facts.interfaceUp = facts.sameLink = facts.anchorAttached = facts.proxyReady =
            facts.authorized = true;
        const auto result = SessionSnapshot::create(config, facts, 11434, "leased-transport-test");
        if (!result)
            qFatal("Cannot construct synthetic leased-transport snapshot");
        return *result;
    }

    static VerifiedPeer peerForSocket(int fd) {
        const auto peer = verifiedPeerForUnixSocket(fd);
        if (!peer)
            qFatal("Cannot read synthetic Unix peer credentials");
        return *peer;
    }

    static QByteArray capability() { return QByteArray(32, 'l'); }

    static QByteArray wireCommand(quint8 command, const SessionSnapshot &session) {
        const QByteArray anchor = session.anchor().toUtf8();
        QByteArray payload;
        payload.append(char(1));
        payload.append(static_cast<char>(command));
        payload.append(static_cast<char>(capability().size()));
        payload += capability();
        payload.append(static_cast<char>(anchor.size()));
        payload += anchor;
        QByteArray frame;
        const quint32 length = static_cast<quint32>(payload.size());
        frame.append(static_cast<char>((length >> 24) & 0xff));
        frame.append(static_cast<char>((length >> 16) & 0xff));
        frame.append(static_cast<char>((length >> 8) & 0xff));
        frame.append(static_cast<char>(length & 0xff));
        frame += payload;
        return frame;
    }

    static void prepareSocketPair(int sockets[2], const QByteArray &wire) {
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
            qFatal("Cannot create synthetic Unix socket pair");
        if (::write(sockets[1], wire.constData(), static_cast<size_t>(wire.size())) != wire.size())
            qFatal("Cannot write synthetic command frame");
        if (::shutdown(sockets[1], SHUT_WR) != 0)
            qFatal("Cannot half-close synthetic command socket");
    }

    static HelperCommand startCommand(const SessionSnapshot &session) {
        HelperCommand command;
        command.type = HelperCommand::Type::Start;
        command.capability = capability();
        command.anchor = session.anchor();
        command.snapshot = session;
        command.nowMs = 10;
        return command;
    }

  private slots:
    void unavailableAndReleasedLeasesRejectBeforeSocketRead() {
        LeasedTransportFakeOperations operations;
        const auto session = snapshot();
        int credentialSockets[2] = {-1, -1};
        QCOMPARE(::socketpair(AF_UNIX, SOCK_STREAM, 0, credentialSockets), 0);
        const auto peer = peerForSocket(credentialSockets[0]);
        ::close(credentialSockets[0]);
        ::close(credentialSockets[1]);
        int clockCalls = 0;
        HelperDispatcher dispatcher(operations, session, peer, capability(), nullptr,
                                    [&clockCalls] {
                                        ++clockCalls;
                                        return qint64(50);
                                    });
        QVERIFY(dispatcher.dispatch(peer, startCommand(session)));
        const auto initialCalls = operations.calls;

        const auto verifyRejectedBeforeRead = [&](const HostSessionLease &lease) {
            int sockets[2] = {-1, -1};
            const QByteArray wire = wireCommand(1, session); // Heartbeat
            prepareSocketPair(sockets, wire);
            QString error;
            QVERIFY(!dispatchOneLeasedUnixSocketCommand(sockets[0], lease, dispatcher, &error));
            QVERIFY(!error.isEmpty());
            QCOMPARE(error, QStringLiteral("host_session_lease_required"));

            QByteArray unread(wire.size(), Qt::Uninitialized);
            QCOMPARE(::recv(sockets[0], unread.data(), static_cast<size_t>(unread.size()),
                            MSG_PEEK | MSG_DONTWAIT),
                     static_cast<ssize_t>(wire.size()));
            QCOMPARE(unread, wire);
            char response = 0;
            QCOMPARE(::recv(sockets[1], &response, 1, MSG_DONTWAIT), ssize_t(-1));
            QCOMPARE(dispatcher.state(), NetworkSession::State::Active);
            QCOMPARE(clockCalls, 0);
            QCOMPARE(operations.calls, initialCalls);
            QVERIFY(::fcntl(sockets[0], F_GETFD) >= 0); // wrapper does not own the descriptor
            QVERIFY(::fcntl(sockets[1], F_GETFD) >= 0);
            ::close(sockets[0]);
            ::close(sockets[1]);
        };

        auto unavailableLease = HostSessionLease::acquire(-1);
        QVERIFY(!unavailableLease.acquired());
        verifyRejectedBeforeRead(unavailableLease);

        PrivateLeaseDirectory directory;
        QVERIFY(directory.valid());
        auto releasedLease = HostSessionLease::acquire(directory.fd());
        QVERIFY(releasedLease.acquired());
        QCOMPARE(releasedLease.release(), HostSessionLeaseStatus::Released);
        verifyRejectedBeforeRead(releasedLease);
    }

    void acquiredLeaseDelegatesAndLeavesSocketOpen() {
        PrivateLeaseDirectory directory;
        QVERIFY(directory.valid());
        auto lease = HostSessionLease::acquire(directory.fd());
        QVERIFY(lease.acquired());

        LeasedTransportFakeOperations operations;
        const auto session = snapshot();
        int credentialSockets[2] = {-1, -1};
        QCOMPARE(::socketpair(AF_UNIX, SOCK_STREAM, 0, credentialSockets), 0);
        const auto peer = peerForSocket(credentialSockets[0]);
        ::close(credentialSockets[0]);
        ::close(credentialSockets[1]);
        int clockCalls = 0;
        HelperDispatcher dispatcher(operations, session, peer, capability(), nullptr,
                                    [&clockCalls] {
                                        ++clockCalls;
                                        return qint64(50);
                                    });
        QVERIFY(dispatcher.dispatch(peer, startCommand(session)));
        operations.calls.clear();

        int sockets[2] = {-1, -1};
        prepareSocketPair(sockets, wireCommand(1, session)); // Heartbeat
        QString error;
        QVERIFY(dispatchOneLeasedUnixSocketCommand(sockets[0], lease, dispatcher, &error));
        QVERIFY(error.isEmpty());
        char response = 0;
        QCOMPARE(::recv(sockets[1], &response, 1, 0), ssize_t(1));
        QCOMPARE(response, char(1));
        QCOMPARE(clockCalls, 1);
        QVERIFY(operations.calls.isEmpty());
        QCOMPARE(dispatcher.state(), NetworkSession::State::Active);
        QVERIFY(::fcntl(sockets[0], F_GETFD) >= 0);
        QVERIFY(::fcntl(sockets[1], F_GETFD) >= 0);
        ::close(sockets[0]);
        ::close(sockets[1]);
        QCOMPARE(lease.release(), HostSessionLeaseStatus::Released);
    }

    void wrongThreadRejectsBeforeSocketRead() {
        PrivateLeaseDirectory directory;
        QVERIFY(directory.valid());
        auto lease = HostSessionLease::acquire(directory.fd());
        QVERIFY(lease.acquired());

        LeasedTransportFakeOperations operations;
        const auto session = snapshot();
        int credentialSockets[2] = {-1, -1};
        QCOMPARE(::socketpair(AF_UNIX, SOCK_STREAM, 0, credentialSockets), 0);
        const auto peer = peerForSocket(credentialSockets[0]);
        ::close(credentialSockets[0]);
        ::close(credentialSockets[1]);
        int clockCalls = 0;
        HelperDispatcher dispatcher(operations, session, peer, capability(), nullptr,
                                    [&clockCalls] {
                                        ++clockCalls;
                                        return qint64(50);
                                    });

        int sockets[2] = {-1, -1};
        const QByteArray wire = wireCommand(1, session);
        prepareSocketPair(sockets, wire);
        bool accepted = true;
        QString error;
        std::thread worker([&] {
            accepted = dispatchOneLeasedUnixSocketCommand(sockets[0], lease, dispatcher, &error);
        });
        worker.join();

        QVERIFY(!accepted);
        QCOMPARE(error, QStringLiteral("dispatcher_thread_required"));
        QByteArray unread(wire.size(), Qt::Uninitialized);
        QCOMPARE(::recv(sockets[0], unread.data(), static_cast<size_t>(unread.size()),
                        MSG_PEEK | MSG_DONTWAIT),
                 static_cast<ssize_t>(wire.size()));
        QCOMPARE(unread, wire);
        QCOMPARE(clockCalls, 0);
        QVERIFY(operations.calls.isEmpty());
        QCOMPARE(dispatcher.state(), NetworkSession::State::Idle);
        QVERIFY(::fcntl(sockets[0], F_GETFD) >= 0);
        QVERIFY(::fcntl(sockets[1], F_GETFD) >= 0);
        ::close(sockets[0]);
        ::close(sockets[1]);
        QCOMPARE(lease.release(), HostSessionLeaseStatus::Released);
    }
};

QTEST_GUILESS_MAIN(M6LeasedUnixSocketCommandTransportTests)
#include "M6LeasedUnixSocketCommandTransportTests.moc"
