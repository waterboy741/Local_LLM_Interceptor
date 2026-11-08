#include "network/TrustedBootstrapHandoff.hpp"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QtTest>

#include <cerrno>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace interceptor;

class HandoffFakeAuthenticator final : public BootstrapPeerAuthenticator {
  public:
    bool accept = true;
    int calls = 0;
    int observedFd = -1;
    QByteArray observedIdentity;

    bool authenticate(int fd, const QByteArray &identity) override {
        ++calls;
        observedFd = fd;
        observedIdentity = identity;
        return accept;
    }
};

class M6TrustedBootstrapHandoffTests final : public QObject {
    Q_OBJECT

    static SessionSnapshot snapshot() {
        SessionConfig config{
            "synthetic0", "192.0.2.10", "192.0.2.30", 18081, {"/api/generate", "/api/chat"}, false};
        NetworkFacts facts;
        facts.interfaceName = config.interfaceName;
        facts.researchIp = "192.0.2.20";
        facts.researchMac = "02:00:00:00:00:20";
        facts.clientMac = "02:00:00:00:00:10";
        facts.serverMac = "02:00:00:00:00:30";
        facts.proxyServerIp = config.serverIp;
        facts.proxyServerPort = config.serverPort;
        facts.proxyListenPort = 11434;
        facts.interfaceUp = facts.sameLink = facts.anchorAttached = facts.proxyReady =
            facts.authorized = true;
        const auto created = SessionSnapshot::create(config, facts, 11434,
                                                     QStringLiteral("trusted-handoff-session"));
        if (!created)
            qFatal("Could not create synthetic trusted-handoff snapshot");
        return *created;
    }

    static void socketPair(int sockets[2]) {
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
            qFatal("Could not create synthetic handoff socketpair");
    }

    static bool readExactly(int fd, char *data, size_t size) {
        size_t read = 0;
        while (read < size) {
            const ssize_t amount = ::recv(fd, data + read, size - read, 0);
            if (amount <= 0)
                return false;
            read += static_cast<size_t>(amount);
        }
        return true;
    }

    static bool sendExactly(int fd, const char *data, size_t size) {
        size_t sent = 0;
        while (sent < size) {
            const ssize_t amount = ::send(fd, data + sent, size - sent, 0);
            if (amount <= 0)
                return false;
            sent += static_cast<size_t>(amount);
        }
        return true;
    }

    static QJsonObject snapshotJson(const SessionSnapshot &value,
                                    bool mismatchUpstreamPort = false) {
        const auto &config = value.config();
        const auto &facts = value.facts();
        QJsonArray paths;
        for (const auto &path : config.apiPaths)
            paths.append(path);
        QJsonObject configObject{
            {"interfaceName", config.interfaceName},
            {"clientIp", config.clientIp},
            {"serverIp", config.serverIp},
            {"serverPort", mismatchUpstreamPort ? config.serverPort + 1 : config.serverPort},
            {"apiPaths", paths},
            {"explicitProxy", config.explicitProxy}};
        QJsonObject factsObject{{"interfaceName", facts.interfaceName},
                                {"researchIp", facts.researchIp},
                                {"researchMac", facts.researchMac},
                                {"clientMac", facts.clientMac},
                                {"serverMac", facts.serverMac},
                                {"proxyServerIp", facts.proxyServerIp},
                                {"proxyServerPort", facts.proxyServerPort},
                                {"proxyListenPort", facts.proxyListenPort},
                                {"prefixLength", facts.prefixLength},
                                {"interfaceUp", facts.interfaceUp},
                                {"sameLink", facts.sameLink},
                                {"anchorAttached", facts.anchorAttached},
                                {"proxyReady", facts.proxyReady},
                                {"authorized", facts.authorized}};
        return {{"version", 1},
                {"sessionId", value.sessionId()},
                {"proxyPort", value.proxyPort()},
                {"config", configObject},
                {"facts", factsObject}};
    }

    static bool fakePeerResponse(int fd, const SessionSnapshot &value, bool corruptChallenge,
                                 bool mismatchSnapshot) {
        char challenge[32]{};
        if (!readExactly(fd, challenge, sizeof(challenge)))
            return false;
        QByteArray payload(32, 'x');
        if (!corruptChallenge)
            payload = QByteArray(challenge, sizeof(challenge));
        payload += QByteArray(32, 's');
        const QByteArray json =
            QJsonDocument(snapshotJson(value, mismatchSnapshot)).toJson(QJsonDocument::Compact);
        payload += json;
        const auto length = static_cast<quint16>(payload.size());
        const char prefix[2] = {static_cast<char>((length >> 8) & 0xff),
                                static_cast<char>(length & 0xff)};
        return sendExactly(fd, prefix, sizeof(prefix)) &&
               sendExactly(fd, payload.constData(), static_cast<size_t>(payload.size()));
    }

  private slots:
    void authenticatedHandoffRoundTripsSnapshotAndOneTimeSecret() {
        int sockets[2] = {-1, -1};
        socketPair(sockets);
        const auto original = snapshot();
        const QByteArray secret(32, 's');
        HandoffFakeAuthenticator writerAuthenticator;
        HandoffFakeAuthenticator receiverAuthenticator;
        QString writeError;
        QString receiveError;
        bool writeResult = false;
        std::unique_ptr<TrustedBootstrapHandoff> received;

        std::thread receiver([&] {
            auto value = receiveTrustedBootstrapHandoff(
                sockets[1], receiverAuthenticator, QByteArrayLiteral("gui-team-id"), &receiveError);
            if (value)
                received = std::make_unique<TrustedBootstrapHandoff>(std::move(*value));
        });
        std::thread writer([&] {
            writeResult = writeBootstrapHandoff(sockets[0], writerAuthenticator,
                                                QByteArrayLiteral("helper-team-id"), original,
                                                secret, &writeError);
        });
        writer.join();
        receiver.join();
        ::close(sockets[0]);
        ::close(sockets[1]);

        QVERIFY2(writeResult, qPrintable(writeError));
        QVERIFY2(received != nullptr, qPrintable(receiveError));
        QVERIFY(writeError.isEmpty());
        QVERIFY(receiveError.isEmpty());
        QCOMPARE(writerAuthenticator.calls, 1);
        QCOMPARE(writerAuthenticator.observedFd, sockets[0]);
        QCOMPARE(writerAuthenticator.observedIdentity, QByteArrayLiteral("helper-team-id"));
        QCOMPARE(receiverAuthenticator.calls, 1);
        QCOMPARE(receiverAuthenticator.observedFd, sockets[1]);
        QCOMPARE(receiverAuthenticator.observedIdentity, QByteArrayLiteral("gui-team-id"));

        const auto &transferred = received->snapshot();
        QCOMPARE(transferred.sessionId(), original.sessionId());
        QCOMPARE(transferred.proxyPort(), original.proxyPort());
        QCOMPARE(transferred.config().interfaceName, original.config().interfaceName);
        QCOMPARE(transferred.config().clientIp, original.config().clientIp);
        QCOMPARE(transferred.config().serverIp, original.config().serverIp);
        QCOMPARE(transferred.config().serverPort, original.config().serverPort);
        QCOMPARE(transferred.config().apiPaths, original.config().apiPaths);
        QCOMPARE(transferred.facts().researchIp, original.facts().researchIp);
        QCOMPARE(transferred.facts().researchMac, original.facts().researchMac);
        QCOMPARE(transferred.facts().proxyListenPort, original.facts().proxyListenPort);
        QVERIFY(transferred.facts().proxyReady);

        QCOMPARE(received->takeProbeSecret(), secret);
        QVERIFY(received->takeProbeSecret().isEmpty());
    }

    void rejectsUnauthenticatedPeersBeforeSendingOrReceivingProtocolBytes() {
        int writerSockets[2] = {-1, -1};
        socketPair(writerSockets);
        HandoffFakeAuthenticator rejectWriter;
        rejectWriter.accept = false;
        QString error;
        QVERIFY(!writeBootstrapHandoff(writerSockets[0], rejectWriter,
                                       QByteArrayLiteral("expected-helper"), snapshot(),
                                       QByteArray(32, 's'), &error));
        QCOMPARE(error, QStringLiteral("bootstrap_peer_not_authenticated"));
        QCOMPARE(rejectWriter.calls, 1);
        char probe[1]{};
        QCOMPARE(::recv(writerSockets[1], probe, sizeof(probe), MSG_DONTWAIT), ssize_t(-1));
        QCOMPARE(errno, EAGAIN);
        ::close(writerSockets[0]);
        ::close(writerSockets[1]);

        int receiverSockets[2] = {-1, -1};
        socketPair(receiverSockets);
        HandoffFakeAuthenticator rejectReceiver;
        rejectReceiver.accept = false;
        error.clear();
        QVERIFY(!receiveTrustedBootstrapHandoff(receiverSockets[1], rejectReceiver,
                                                QByteArrayLiteral("expected-gui"), &error));
        QCOMPARE(error, QStringLiteral("bootstrap_peer_not_authenticated"));
        QCOMPARE(rejectReceiver.calls, 1);
        QCOMPARE(::recv(receiverSockets[0], probe, sizeof(probe), MSG_DONTWAIT), ssize_t(-1));
        QCOMPARE(errno, EAGAIN);
        ::close(receiverSockets[0]);
        ::close(receiverSockets[1]);
    }

    void rejectsInvalidIdentityAndSecretBeforeProtocolExchange() {
        int sockets[2] = {-1, -1};
        socketPair(sockets);
        HandoffFakeAuthenticator authenticator;
        QString error;
        QVERIFY(!writeBootstrapHandoff(sockets[0], authenticator, {}, snapshot(),
                                       QByteArray(32, 's'), &error));
        QCOMPARE(error, QStringLiteral("bootstrap_socket_or_identity_invalid"));
        QCOMPARE(authenticator.calls, 0);

        QVERIFY(!writeBootstrapHandoff(sockets[0], authenticator,
                                       QByteArrayLiteral("expected-helper"), snapshot(),
                                       QByteArray(31, 's'), &error));
        QCOMPARE(error, QStringLiteral("bootstrap_secret_invalid"));
        QCOMPARE(authenticator.calls, 1);

        char probe[1]{};
        QCOMPARE(::recv(sockets[1], probe, sizeof(probe), MSG_DONTWAIT), ssize_t(-1));
        QCOMPARE(errno, EAGAIN);
        ::close(sockets[0]);
        ::close(sockets[1]);
    }

    void rejectsOversizedPathCollectionsBeforeWaitingForChallenge() {
        const auto original = snapshot();
        auto config = original.config();
        const auto facts = original.facts();
        config.apiPaths = QStringList(17, QStringLiteral("/api/generate"));
        auto tooManyPaths = SessionSnapshot::create(config, facts, original.proxyPort(),
                                                    QStringLiteral("too-many-paths"));
        QVERIFY(tooManyPaths.has_value());

        int sockets[2] = {-1, -1};
        socketPair(sockets);
        HandoffFakeAuthenticator authenticator;
        QString error;
        QVERIFY(!writeBootstrapHandoff(sockets[0], authenticator,
                                       QByteArrayLiteral("expected-helper"), *tooManyPaths,
                                       QByteArray(32, 's'), &error));
        QCOMPARE(error, QStringLiteral("bootstrap_paths_invalid"));
        QCOMPARE(authenticator.calls, 1);

        config = original.config();
        config.apiPaths = {QStringLiteral("/") + QString(256, QChar('x'))};
        auto oversizedPath = SessionSnapshot::create(config, facts, original.proxyPort(),
                                                     QStringLiteral("oversized-path"));
        QVERIFY(oversizedPath.has_value());
        error.clear();
        QVERIFY(!writeBootstrapHandoff(sockets[0], authenticator,
                                       QByteArrayLiteral("expected-helper"), *oversizedPath,
                                       QByteArray(32, 's'), &error));
        QCOMPARE(error, QStringLiteral("bootstrap_paths_invalid"));
        QCOMPARE(authenticator.calls, 2);
        ::close(sockets[0]);
        ::close(sockets[1]);
    }

    void acceptsCompleteFrameWhenPeerClosesImmediatelyAfterSending() {
        int sockets[2] = {-1, -1};
        socketPair(sockets);
        HandoffFakeAuthenticator authenticator;
        const auto original = snapshot();
        QString error;
        bool responseSent = false;
        std::unique_ptr<TrustedBootstrapHandoff> received;
        std::thread fakePeer([&] {
            responseSent = fakePeerResponse(sockets[0], original, false, false);
            (void)::shutdown(sockets[0], SHUT_WR);
        });
        auto value = receiveTrustedBootstrapHandoff(sockets[1], authenticator,
                                                    QByteArrayLiteral("expected-gui"), &error);
        if (value)
            received = std::make_unique<TrustedBootstrapHandoff>(std::move(*value));
        fakePeer.join();
        ::close(sockets[0]);
        ::close(sockets[1]);

        QVERIFY(responseSent);
        QVERIFY2(received != nullptr, qPrintable(error));
        QVERIFY(error.isEmpty());
        QCOMPARE(received->snapshot().sessionId(), original.sessionId());
        QCOMPARE(received->takeProbeSecret(), QByteArray(32, 's'));
    }

    void rejectsInvalidLengthBeforeParsingPayload() {
        int sockets[2] = {-1, -1};
        socketPair(sockets);
        HandoffFakeAuthenticator authenticator;
        std::thread malformedPeer([&] {
            char challenge[32]{};
            if (!readExactly(sockets[0], challenge, sizeof(challenge)))
                return;
            const char prefix[2] = {0x10, 0x01}; // 4097 bytes exceeds the bounded frame.
            (void)::send(sockets[0], prefix, sizeof(prefix), 0);
        });
        QString error;
        const auto received = receiveTrustedBootstrapHandoff(
            sockets[1], authenticator, QByteArrayLiteral("expected-gui"), &error);
        malformedPeer.join();
        ::close(sockets[0]);
        ::close(sockets[1]);
        QVERIFY(!received.has_value());
        QCOMPARE(error, QStringLiteral("bootstrap_length_invalid"));
        QCOMPARE(authenticator.calls, 1);
    }

    void rejectsMismatchedChallengeAndInconsistentSnapshot() {
        const auto original = snapshot();
        for (const bool corruptChallenge : {true, false}) {
            int sockets[2] = {-1, -1};
            socketPair(sockets);
            HandoffFakeAuthenticator authenticator;
            bool responseSent = false;
            std::thread fakePeer([&] {
                responseSent =
                    fakePeerResponse(sockets[0], original, corruptChallenge, !corruptChallenge);
            });
            QString error;
            const auto received = receiveTrustedBootstrapHandoff(
                sockets[1], authenticator, QByteArrayLiteral("expected-gui"), &error);
            fakePeer.join();
            ::close(sockets[0]);
            ::close(sockets[1]);

            QVERIFY(responseSent);
            QVERIFY(!received.has_value());
            QCOMPARE(error, QStringLiteral("bootstrap_payload_not_trusted"));
            QCOMPARE(authenticator.calls, 1);
        }
    }
};

QTEST_GUILESS_MAIN(M6TrustedBootstrapHandoffTests)
#include "M6TrustedBootstrapHandoffTests.moc"
