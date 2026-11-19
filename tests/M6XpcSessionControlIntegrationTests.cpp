#include "network/InstalledSessionControl.hpp"
#include "network/XpcReadOnlyServiceListener.hpp"
#include "network/XpcSessionControlClient.hpp"
#include "network/XpcSessionControlServiceAdapter.hpp"

#include <QProcess>
#include <QRegularExpression>
#include <QtTest>

#include <xpc/xpc.h>

#include <vector>

namespace interceptor {

// The friend name declared by XpcSessionControlClient.hpp; defines access to the testing seam.
class M6XpcSessionControlClientTestAccess final {
  public:
    static XpcSessionControlClientResult
    start(xpc_endpoint_t endpoint, const XpcSessionControlClientTuple &tuple,
          const QByteArray &probeSecret, const QByteArray &helperRequirement, int timeoutMs) {
        return XpcSessionControlClient::startWithEndpointForTesting(endpoint, tuple, probeSecret,
                                                                    helperRequirement, timeoutMs);
    }
    static XpcSessionControlClientResult
    heartbeat(xpc_endpoint_t endpoint, const QString &sessionId, const QByteArray &capability,
              const QByteArray &helperRequirement, int timeoutMs) {
        return XpcSessionControlClient::sessionWithEndpointForTesting(
            endpoint, XpcSessionControlClient::Operation::Heartbeat, sessionId, capability,
            helperRequirement, timeoutMs);
    }
    static XpcSessionControlClientResult
    stop(xpc_endpoint_t endpoint, const QString &sessionId, const QByteArray &capability,
         const QByteArray &helperRequirement, int timeoutMs) {
        return XpcSessionControlClient::sessionWithEndpointForTesting(
            endpoint, XpcSessionControlClient::Operation::Stop, sessionId, capability,
            helperRequirement, timeoutMs);
    }
    static XpcSessionControlClientResult
    status(xpc_endpoint_t endpoint, const QByteArray &helperRequirement, int timeoutMs) {
        return XpcSessionControlClient::statusWithEndpointForTesting(endpoint, helperRequirement,
                                                                     timeoutMs);
    }
};

class M6XpcReadOnlyServiceListenerTestAccess final {
  public:
    static bool startWithAnonymousListener(XpcReadOnlyServiceListener &listener,
                                           xpc_connection_t connection, std::string *error) {
        return listener.startWithAnonymousListenerForTesting(connection, error);
    }
};

namespace {

class FakeInstalledPolicy final : public XpcPeerCodeSignaturePolicy {
  public:
    bool authenticate(xpc_object_t, std::string_view, std::string *error) override {
        ++calls;
        if (error)
            *error = policyError;
        return result;
    }
    int calls = 0;
    std::string policyError;
    bool result = true;
};

class IntegrationCoreBackend final : public InstalledSessionControlBackend {
  public:
    bool effectiveRoot() override { return isRoot; }
    bool freshListenerVerification(const InstalledSessionTuple &,
                                   const std::vector<unsigned char> &secret) override {
        lastSecretSize = secret.size();
        return verificationSucceeds;
    }
    bool startOwnedOperations(const InstalledSessionTuple &, std::string *) override {
        return starts;
    }
    void heartbeatOwnedOperations() override {}
    bool stopOwnedOperations(bool *cleaned, std::string *) override {
        if (stopAttemptsUntilClean > 0) {
            --stopAttemptsUntilClean;
            *cleaned = false;
            return false;
        }
        *cleaned = true;
        return true;
    }

    bool isRoot = true;
    bool verificationSucceeds = true;
    bool starts = true;
    int stopAttemptsUntilClean = 0;
    std::size_t lastSecretSize = 0;
};

// Serves one fixed reply shape through the anonymous-endpoint harness (bad-reply parsing cases).
class FixedReplyService final : public XpcServiceMessageHandler {
  public:
    explicit FixedReplyService(std::function<xpc_object_t()> replyFactory)
        : replyFactory_(std::move(replyFactory)) {}

    bool isConfigured() const override { return true; }
    xpc_object_t handleMessage(xpc_object_t message) const override {
        (void)message;
        xpc_object_t reply = xpc_dictionary_create_reply(message);
        if (!reply)
            return nullptr;
        xpc_object_t payload = replyFactory_();
        if (!payload) {
            xpc_release(reply);
            return nullptr;
        }
        xpc_dictionary_apply(payload, ^bool(const char *key, xpc_object_t value) {
          xpc_dictionary_set_value(reply, key, value);
          return true;
        });
        xpc_release(payload);
        return reply;
    }

  private:
    std::function<xpc_object_t()> replyFactory_;
};

class SilentAuthService final : public XpcServiceMessageHandler {
  public:
    bool isConfigured() const override { return true; }
    xpc_object_t handleMessage(xpc_object_t) const override { return nullptr; }
};

// Replies only after replyDelayMs, so a deadline below it times out deterministically.
class DelayedReplyService final : public XpcServiceMessageHandler {
  public:
    explicit DelayedReplyService(int replyDelayMs) : replyDelayMs_(replyDelayMs) {}

    bool isConfigured() const override { return true; }
    xpc_object_t handleMessage(xpc_object_t message) const override {
        xpc_object_t retainedMessage = xpc_retain(message);
        dispatch_after(
            dispatch_time(DISPATCH_TIME_NOW, static_cast<int64_t>(replyDelayMs_) * NSEC_PER_MSEC),
            dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
              xpc_object_t response = xpc_dictionary_create_reply(retainedMessage);
              if (response) {
                  xpc_dictionary_set_bool(response, "ok", true);
                  xpc_dictionary_set_uint64(response, "protocol_version", 1);
                  xpc_dictionary_set_string(response, "state", "active");
                  xpc_connection_send_message(
                      xpc_dictionary_get_remote_connection(retainedMessage), response);
                  xpc_release(response);
              }
              xpc_release(retainedMessage);
            });
        return nullptr;
    }

  private:
    int replyDelayMs_;
};

// One serialized installed-service instance on an anonymous endpoint: the operator-gated gate,
// the Qt-free core behind a controllable fake backend, and the session-control adapter.
class InstalledServiceHarness final {
  public:
    explicit InstalledServiceHarness(XpcServiceMessageHandler *customHandler = nullptr) {
        gateway_ = std::make_unique<XpcControlRequestGate>(
            "trusted requirement", policy_, XpcControlRequestGate::Mode::InstalledLifecycle);
        core_ =
            std::make_unique<InstalledSessionControlCore>(backend_, [] { return qint64(100); });
        if (customHandler) {
            handler_ = customHandler;
        } else {
            ownedHandler_ = std::make_unique<XpcSessionControlServiceAdapter>(*gateway_, *core_);
            handler_ = ownedHandler_.get();
        }
        listener_ = std::make_unique<XpcReadOnlyServiceListener>(
            "org.example.interceptor.session", *handler_);
        anonymousListener_ = xpc_connection_create(nullptr, nullptr);
        endpoint_ = xpc_endpoint_create(anonymousListener_);
        std::string error;
        started_ = M6XpcReadOnlyServiceListenerTestAccess::startWithAnonymousListener(
            *listener_, anonymousListener_, &error);
        startError_ = QString::fromStdString(error);
    }

    ~InstalledServiceHarness() {
        listener_->stop();
        // startWithAnonymousListenerForTesting consumed our +1 reference on the anonymous
        // listener connection, so only the endpoint reference remains ours to release.
        if (endpoint_)
            xpc_release(endpoint_);
        anonymousListener_ = nullptr;
    }

    bool started() const { return started_; }
    const QString &startError() const { return startError_; }
    xpc_endpoint_t endpoint() const { return endpoint_; }
    FakeInstalledPolicy &policy() { return policy_; }
    IntegrationCoreBackend &backend() { return backend_; }
    InstalledSessionControlCore &core() { return *core_; }

    static QByteArray selfCodeSigningRequirement() {
        QProcess codesign;
        codesign.setProcessChannelMode(QProcess::MergedChannels);
        codesign.start(QStringLiteral("/usr/bin/codesign"),
                       {QStringLiteral("-d"), QStringLiteral("-r-"),
                        QCoreApplication::applicationFilePath()});
        if (!codesign.waitForFinished(5000)) {
            codesign.kill();
            codesign.waitForFinished(1000);
            return {};
        }
        const QByteArray signature = codesign.readAll();
        const QRegularExpression hashLine(
            QStringLiteral("(?m)^# designated => cdhash H\"([a-fA-F0-9]{40}|[a-fA-F0-9]{64})\"$"));
        const auto match = hashLine.match(QString::fromLatin1(signature));
        if (!match.hasMatch())
            return {};
        return "cdhash H\"" + match.captured(1).toLatin1() + "\"";
    }

    static XpcSessionControlClientTuple sampleTuple() {
        XpcSessionControlClientTuple tuple;
        tuple.interfaceName = QStringLiteral("en0");
        tuple.clientIpv4 = QStringLiteral("192.0.2.10");
        tuple.upstreamIpv4 = QStringLiteral("192.0.2.30");
        tuple.listenAddress = QStringLiteral("192.0.2.20");
        tuple.upstreamPort = 18081;
        tuple.listenerPort = 11434;
        return tuple;
    }

  private:
    FakeInstalledPolicy policy_;
    IntegrationCoreBackend backend_;
    std::unique_ptr<XpcControlRequestGate> gateway_;
    std::unique_ptr<InstalledSessionControlCore> core_;
    std::shared_ptr<XpcServiceMessageHandler> ownedHandler_;
    XpcServiceMessageHandler *handler_ = nullptr;
    std::unique_ptr<XpcReadOnlyServiceListener> listener_;
    xpc_connection_t anonymousListener_ = nullptr;
    xpc_endpoint_t endpoint_ = nullptr;
    bool started_ = false;
    QString startError_;
};

} // namespace

class M6XpcSessionControlIntegrationTests final : public QObject {
    Q_OBJECT

  private:
    void verifyClientStatusOrSkip(const QByteArray &requirement) {
        if (requirement.isEmpty())
            QSKIP("The test executable signature could not be pinned for anonymous XPC.");
    }

  private slots:
    void authenticatedStartHeartbeatStopRoundTripOverAnonymousXpc() {
        const QByteArray requirement = InstalledServiceHarness::selfCodeSigningRequirement();
        verifyClientStatusOrSkip(requirement);
        InstalledServiceHarness harness;
        QVERIFY2(harness.started(), qPrintable(harness.startError()));
        const QByteArray probeSecret(32, 'q');

        // Start: the sole 9-key grammar crosses the pinned, authenticated endpoint.
        const auto start = M6XpcSessionControlClientTestAccess::start(
            harness.endpoint(), InstalledServiceHarness::sampleTuple(), probeSecret, requirement,
            3000);
        QCOMPARE(start.status, XpcSessionControlClientStatus::Success);
        QVERIFY(start.succeeded());
        QCOMPARE(start.state, QStringLiteral("active"));
        QCOMPARE(harness.backend().lastSecretSize, std::size_t(32));
        QVERIFY(start.sessionId.size() == 16);
        QVERIFY(start.sessionCapability.size() == XpcSessionControlClient::capabilityBytes);
        QVERIFY(harness.core().sessionActive());
        QVERIFY(harness.policy().calls >= 1);

        // Heartbeat holds the session; the reply echoes the id and no capability.
        const auto heartbeat = M6XpcSessionControlClientTestAccess::heartbeat(
            harness.endpoint(), start.sessionId, start.sessionCapability, requirement, 3000);
        QCOMPARE(heartbeat.status, XpcSessionControlClientStatus::Success);
        QCOMPARE(heartbeat.state, QStringLiteral("active"));
        QVERIFY(heartbeat.sessionCapability.isEmpty());
        QCOMPARE(heartbeat.sessionId, start.sessionId);

        // Stop reports the verified transition and revokes the handle.
        const auto stop = M6XpcSessionControlClientTestAccess::stop(
            harness.endpoint(), start.sessionId, start.sessionCapability, requirement, 3000);
        QCOMPARE(stop.status, XpcSessionControlClientStatus::Success);
        QVERIFY(stop.ok);
        QCOMPARE(stop.state, QStringLiteral("stopped"));
        QVERIFY(stop.sessionCapability.isEmpty());

        // A Stop replay after the verified stop fails binding over the wire.
        const auto replay = M6XpcSessionControlClientTestAccess::stop(
            harness.endpoint(), start.sessionId, start.sessionCapability, requirement, 3000);
        QCOMPARE(replay.status, XpcSessionControlClientStatus::Success);
        QCOMPARE(replay.reason, QStringLiteral("session_binding_mismatch"));
        QCOMPARE(replay.state, QStringLiteral("stopped"));
        QVERIFY(!replay.ok);
    }

    void adapterServesProbeStatusParityAndCoreLifecycleReasons() {
        const QByteArray requirement = InstalledServiceHarness::selfCodeSigningRequirement();
        verifyClientStatusOrSkip(requirement);
        InstalledServiceHarness harness;
        QVERIFY2(harness.started(), qPrintable(harness.startError()));

        // Probe/status stay byte-identical to the read-only v1 surface (fixed "inactive"
        // state); the lifecycle state reaches the GUI only through session-control replies.
        const auto status = M6XpcSessionControlClientTestAccess::status(harness.endpoint(),
                                                                        requirement, 3000);
        QVERIFY2(status.state == QStringLiteral("inactive"),
                 qPrintable(QStringLiteral("clientStatus=%1 ok=%2 state=%3 reason=%4")
                                .arg(int(status.status))
                                .arg(status.ok)
                                .arg(status.state, status.reason)));
        QCOMPARE(status.succeeded(), true);

        // A duplicate Start rejection exposes the fixed reason vocabulary over the wire.
        const QByteArray probeSecret(32, 'q');
        const auto first = M6XpcSessionControlClientTestAccess::start(
            harness.endpoint(), InstalledServiceHarness::sampleTuple(), probeSecret, requirement,
            3000);
        QVERIFY(first.succeeded() && first.ok);
        const auto duplicate = M6XpcSessionControlClientTestAccess::start(
            harness.endpoint(), InstalledServiceHarness::sampleTuple(), probeSecret, requirement,
            3000);
        QCOMPARE(duplicate.status, XpcSessionControlClientStatus::Success);
        QCOMPARE(duplicate.reason, QStringLiteral("duplicate_start"));
        QCOMPARE(duplicate.state, QStringLiteral("active"));
        QVERIFY(duplicate.sessionCapability.isEmpty());
        QVERIFY(!duplicate.ok);
    }

    void clientFailsClosedOnDeadlinesShapesAndUnavailableServices() {
        const QByteArray requirement = InstalledServiceHarness::selfCodeSigningRequirement();
        verifyClientStatusOrSkip(requirement);
        const XpcSessionControlClientTuple tuple = InstalledServiceHarness::sampleTuple();
        const QByteArray probeSecret(32, 'q');
        const QString sessionId = QStringLiteral("0123456789abcdef");
        const QByteArray capability(32, 'c');

        // Deadline bounds are enforced before any connection attempt.
        for (const int invalidTimeout : {0, -1, XpcSessionControlClient::maximumTimeoutMs + 1}) {
            const auto rejected = M6XpcSessionControlClientTestAccess::start(
                nullptr, tuple, probeSecret, requirement, invalidTimeout);
            QCOMPARE(rejected.status, XpcSessionControlClientStatus::InvalidTimeout);
        }
        // An empty or uncompilable requirement fails closed before connecting.
        {
            InstalledServiceHarness harness;
            QVERIFY2(harness.started(), qPrintable(harness.startError()));
            const auto empty = M6XpcSessionControlClientTestAccess::start(
                harness.endpoint(), tuple, probeSecret, QByteArrayLiteral(""), 1000);
            QCOMPARE(empty.status, XpcSessionControlClientStatus::InvalidPeerRequirement);
            const auto malformed = M6XpcSessionControlClientTestAccess::start(
                harness.endpoint(), tuple, probeSecret, QByteArrayLiteral("not-a-requirement"),
                1000);
            QCOMPARE(malformed.status, XpcSessionControlClientStatus::InvalidPeerRequirement);
        }
        // Invalid request shapes: heartbeat/stop need a session id and a 32-byte capability.
        {
            InstalledServiceHarness harness;
            QVERIFY2(harness.started(), qPrintable(harness.startError()));
            const auto noCapability = M6XpcSessionControlClientTestAccess::heartbeat(
                harness.endpoint(), sessionId, QByteArrayLiteral("short"), requirement, 1000);
            QCOMPARE(noCapability.status, XpcSessionControlClientStatus::InvalidRequest);
            const auto noSession = M6XpcSessionControlClientTestAccess::heartbeat(
                harness.endpoint(), QString(), capability, requirement, 1000);
            QCOMPARE(noSession.status, XpcSessionControlClientStatus::InvalidRequest);
        }
        // A pinned requirement that this anonymous peer does not satisfy.
        {
            InstalledServiceHarness harness;
            QVERIFY2(harness.started(), qPrintable(harness.startError()));
            const QByteArray mismatching = QByteArrayLiteral("cdhash H\"") +
                                          QByteArray(40, '0') + QByteArrayLiteral("\"");
            const auto mismatch = M6XpcSessionControlClientTestAccess::start(
                harness.endpoint(), tuple, probeSecret, mismatching, 3000);
            QCOMPARE(mismatch.status, XpcSessionControlClientStatus::PeerIdentityMismatch);
            QVERIFY(!mismatch.ok);
        }
        // A service that authenticates-then-never-replies still fails closed (no half-parsed
        // result): observed as the connection error surfacing before the deadline.
        {
            SilentAuthService silent;
            InstalledServiceHarness harness(&silent);
            QVERIFY2(harness.started(), qPrintable(harness.startError()));
            const auto noReply = M6XpcSessionControlClientTestAccess::start(
                harness.endpoint(), tuple, probeSecret, requirement, 300);
            QVERIFY(noReply.status == XpcSessionControlClientStatus::TimedOut ||
                    noReply.status == XpcSessionControlClientStatus::ServiceUnavailable);
            QVERIFY(!noReply.ok);
            QVERIFY(noReply.sessionCapability.isEmpty());
        }
        // A service slower than the deadline times out exactly at the deadline.
        {
            DelayedReplyService slow(400);
            InstalledServiceHarness harness2(&slow);
            QVERIFY2(harness2.started(), qPrintable(harness2.startError()));
            const auto timedOut = M6XpcSessionControlClientTestAccess::start(
                harness2.endpoint(), tuple, probeSecret, requirement, 200);
            QCOMPARE(timedOut.status, XpcSessionControlClientStatus::TimedOut);
            QVERIFY(timedOut.sessionCapability.isEmpty());
        }
        // Malformed reply shapes are rejected instead of half-parsed.
        const auto malformedReplies = std::vector<std::function<xpc_object_t()>>{
            [] {
                xpc_object_t reply = xpc_dictionary_create(nullptr, nullptr, 0);
                xpc_dictionary_set_bool(reply, "ok", true); // missing version/state
                return reply;
            },
            [] {
                xpc_object_t reply = xpc_dictionary_create(nullptr, nullptr, 0);
                xpc_dictionary_set_int64(reply, "ok", 1); // wrong ok type
                xpc_dictionary_set_uint64(reply, "protocol_version", 1);
                xpc_dictionary_set_string(reply, "state", "ready");
                return reply;
            },
            [] {
                xpc_object_t reply = xpc_dictionary_create(nullptr, nullptr, 0);
                xpc_dictionary_set_bool(reply, "ok", false);
                xpc_dictionary_set_uint64(reply, "protocol_version", 2);
                xpc_dictionary_set_string(reply, "state", "ready");
                xpc_dictionary_set_string(reply, "reason", "x");
                return reply;
            },
            [] {
                // A capability on a rejected reply violates capability exclusivity.
                xpc_object_t reply = xpc_dictionary_create(nullptr, nullptr, 0);
                xpc_dictionary_set_bool(reply, "ok", false);
                xpc_dictionary_set_uint64(reply, "protocol_version", 1);
                xpc_dictionary_set_string(reply, "state", "ready");
                xpc_dictionary_set_string(reply, "reason", "duplicate_start");
                const QByteArray capability(32, 'k');
                xpc_dictionary_set_data(reply, "session_capability", capability.constData(),
                                        capability.size());
                return reply;
            },
        };
        for (const auto &factory : malformedReplies) {
            FixedReplyService service(factory);
            InstalledServiceHarness harness(&service);
            QVERIFY2(harness.started(), qPrintable(harness.startError()));
            const auto reply = M6XpcSessionControlClientTestAccess::start(
                harness.endpoint(), tuple, probeSecret, requirement, 3000);
            QCOMPARE(reply.status, XpcSessionControlClientStatus::InvalidReply);
        }
    }

    void rejectedHeartbeatReplyMustKeepOkFalseForTheGui() {
        const QByteArray requirement = InstalledServiceHarness::selfCodeSigningRequirement();
        verifyClientStatusOrSkip(requirement);
        // A contract-shaped rejected heartbeat reply (ok=false, state active, bounded reason).
        FixedReplyService service([] {
            xpc_object_t reply = xpc_dictionary_create(nullptr, nullptr, 0);
            xpc_dictionary_set_bool(reply, "ok", false);
            xpc_dictionary_set_uint64(reply, "protocol_version", 1);
            xpc_dictionary_set_string(reply, "state", "active");
            xpc_dictionary_set_string(reply, "session_id", "0123456789abcdef");
            xpc_dictionary_set_string(reply, "reason", "heartbeat_rejected");
            return reply;
        });
        InstalledServiceHarness harness(&service);
        QVERIFY2(harness.started(), qPrintable(harness.startError()));

        const auto heartbeat = M6XpcSessionControlClientTestAccess::heartbeat(
            harness.endpoint(), QStringLiteral("0123456789abcdef"), QByteArray(32, 'c'),
            requirement, 3000);
        QVERIFY(!heartbeat.ok);
    }

  private:
};

} // namespace interceptor

QTEST_GUILESS_MAIN(interceptor::M6XpcSessionControlIntegrationTests)
#include "M6XpcSessionControlIntegrationTests.moc"
