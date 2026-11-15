#include "network/XpcReadOnlyServiceClient.hpp"

#include <QProcess>
#include <QRegularExpression>
#include <QtTest>

#include <xpc/xpc.h>

#include <future>
#include <memory>
#include <vector>

namespace interceptor {

class M6XpcReadOnlyServiceClientTestAccess final {
  public:
    static XpcReadOnlyClientResult
    request(xpc_endpoint_t endpoint, XpcReadOnlyClientOperation operation, int timeoutMs = 1500) {
        return XpcReadOnlyServiceClient::requestWithEndpointForTesting(endpoint, operation,
                                                                       timeoutMs);
    }

    static XpcReadOnlyClientResult
    trustedStatus(xpc_endpoint_t endpoint, const QByteArray &requirement, int timeoutMs = 1500) {
        return XpcReadOnlyServiceClient::trustedStatusWithEndpointForTesting(endpoint, requirement,
                                                                             timeoutMs);
    }
};

namespace {
enum class ReplyShape {
    Probe,
    Status,
    Empty,
    MissingOk,
    WrongOkType,
    WrongService,
    WrongVersion,
    MissingService,
    MissingVersion,
    MissingState,
    WrongState,
    ExtraField
};

class AnonymousService final {
  public:
    explicit AnonymousService(ReplyShape shape, bool reply = true, int replyDelayMs = 0) {
        if (!listenerQueue_)
            return;
        listener_ = xpc_connection_create(nullptr, listenerQueue_);
        if (!listener_)
            return;
        const auto connections = connections_;
        xpc_connection_set_event_handler(listener_, ^(xpc_object_t event) {
          if (xpc_get_type(event) != XPC_TYPE_CONNECTION)
              return;
          xpc_connection_t peer = reinterpret_cast<xpc_connection_t>(event);
          if (connections->closed) {
              xpc_connection_cancel(peer);
              return;
          }
          xpc_retain(peer);
          xpc_connection_set_event_handler(peer, ^(xpc_object_t message) {
            if (!reply || xpc_get_type(message) != XPC_TYPE_DICTIONARY)
                return;
            xpc_object_t retainedMessage = xpc_retain(message);
            xpc_retain(peer);
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                         static_cast<int64_t>(replyDelayMs) * NSEC_PER_MSEC),
                           dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
                             xpc_object_t response = xpc_dictionary_create_reply(retainedMessage);
                             if (response) {
                                 populate(response, shape);
                                 xpc_connection_send_message(peer, response);
                                 xpc_release(response);
                             }
                             xpc_release(retainedMessage);
                             xpc_release(peer);
                           });
          });
          xpc_connection_activate(peer);
          connections->peers.push_back(peer);
        });
        xpc_connection_activate(listener_);
        endpoint_ = xpc_endpoint_create(listener_);
    }

    ~AnonymousService() {
        makeUnavailable();
        if (endpoint_)
            xpc_release(endpoint_);
        if (listenerQueue_)
            dispatch_release(listenerQueue_);
    }

    xpc_endpoint_t endpoint() const { return endpoint_; }

    void makeUnavailable() {
        if (listener_) {
            xpc_connection_cancel(listener_);
            const auto connections = connections_;
            dispatch_sync(listenerQueue_, ^{
              connections->closed = true;
              for (xpc_connection_t peer : connections->peers) {
                  xpc_connection_cancel(peer);
                  xpc_release(peer);
              }
              connections->peers.clear();
            });
            xpc_release(listener_);
            listener_ = nullptr;
        }
    }

  private:
    struct Connections {
        bool closed = false;
        std::vector<xpc_connection_t> peers;
    };

    static void populate(xpc_object_t response, ReplyShape shape) {
        if (shape == ReplyShape::Empty)
            return;
        if (shape == ReplyShape::MissingOk) {
            xpc_dictionary_set_string(response, "service", "llm_interceptor");
            xpc_dictionary_set_uint64(response, "protocol_version", 1);
            return;
        }
        if (shape == ReplyShape::WrongOkType) {
            xpc_dictionary_set_string(response, "ok", "true");
            xpc_dictionary_set_string(response, "service", "llm_interceptor");
            xpc_dictionary_set_uint64(response, "protocol_version", 1);
            return;
        }
        if (shape == ReplyShape::MissingService) {
            xpc_dictionary_set_bool(response, "ok", true);
            xpc_dictionary_set_uint64(response, "protocol_version", 1);
            return;
        }
        if (shape == ReplyShape::MissingVersion) {
            xpc_dictionary_set_bool(response, "ok", true);
            xpc_dictionary_set_string(response, "service", "llm_interceptor");
            return;
        }
        if (shape == ReplyShape::MissingState) {
            xpc_dictionary_set_bool(response, "ok", true);
            xpc_dictionary_set_string(response, "service", "llm_interceptor");
            xpc_dictionary_set_uint64(response, "protocol_version", 1);
            return;
        }

        xpc_dictionary_set_bool(response, "ok", true);
        xpc_dictionary_set_string(response, "service",
                                  shape == ReplyShape::WrongService ? "other_service"
                                                                    : "llm_interceptor");
        xpc_dictionary_set_uint64(response, "protocol_version",
                                  shape == ReplyShape::WrongVersion ? 2 : 1);
        if (shape == ReplyShape::Probe)
            return;
        if (shape == ReplyShape::Status || shape == ReplyShape::WrongState ||
            shape == ReplyShape::ExtraField)
            xpc_dictionary_set_string(response, "state",
                                      shape == ReplyShape::WrongState ? "active" : "inactive");
        if (shape == ReplyShape::ExtraField)
            xpc_dictionary_set_string(response, "extra", "not allowed");
    }

    dispatch_queue_t listenerQueue_ =
        dispatch_queue_create("interceptor.test.xpc.listener", DISPATCH_QUEUE_SERIAL);
    xpc_connection_t listener_ = nullptr;
    xpc_endpoint_t endpoint_ = nullptr;
    std::shared_ptr<Connections> connections_ = std::make_shared<Connections>();
};
} // namespace

class M6XpcReadOnlyServiceClientTests final : public QObject {
    Q_OBJECT

  private slots:
    void trustedStatusRejectsInvalidRequirementsBeforeConnecting() {
        const QByteArray hash(40, 'a');
        const QByteArray exact = "cdhash H\"" + hash + "\"";
        const QList<QByteArray> invalidRequirements = {{},
                                                       "identifier \"com.example.helper\"",
                                                       "anchor apple generic",
                                                       "cdhash H\"abcd\"",
                                                       exact + " or anchor apple generic",
                                                       exact + QByteArray("\0suffix", 7)};
        for (const QByteArray &requirement : invalidRequirements) {
            const auto result =
                M6XpcReadOnlyServiceClientTestAccess::trustedStatus(nullptr, requirement);
            QCOMPARE(result.status, XpcReadOnlyClientStatus::InvalidPeerRequirement);
            QVERIFY(!result.ok);
            QVERIFY(result.service.isEmpty());
            QVERIFY(result.state.isEmpty());
            QCOMPARE(result.protocolVersion, 0ULL);
        }
    }

    void trustedStatusChecksSignedAnonymousPeer() {
        QProcess codesign;
        codesign.setProcessChannelMode(QProcess::MergedChannels);
        codesign.start(
            QStringLiteral("/usr/bin/codesign"),
            {QStringLiteral("-d"), QStringLiteral("-r-"), QCoreApplication::applicationFilePath()});
        if (!codesign.waitForFinished(3000)) {
            codesign.kill();
            codesign.waitForFinished(1000);
            QFAIL("Unable to inspect the test executable signature within the deadline");
        }
        const QByteArray signature = codesign.readAll();
        QVERIFY2(codesign.exitStatus() == QProcess::NormalExit && codesign.exitCode() == 0,
                 signature.constData());
        const QRegularExpression hashLine(
            QStringLiteral("(?m)^# designated => cdhash H\"([a-fA-F0-9]{40}|[a-fA-F0-9]{64})\"$"));
        const auto match = hashLine.match(QString::fromLatin1(signature));
        QVERIFY2(match.hasMatch(), signature.constData());
        QByteArray hash = match.captured(1).toLatin1();

        AnonymousService service(ReplyShape::Status);
        QVERIFY(service.endpoint() != nullptr);
        const QByteArray requirement = "cdhash H\"" + hash + "\"";
        // A raw-data view does not guarantee a trailing NUL for the XPC API.
        const QByteArray backing = requirement + " and (";
        const auto verified = M6XpcReadOnlyServiceClientTestAccess::trustedStatus(
            service.endpoint(), QByteArray::fromRawData(backing.constData(), requirement.size()));
        QCOMPARE(verified.status, XpcReadOnlyClientStatus::Success);
        QVERIFY(verified.ok);
        QCOMPARE(verified.state, QStringLiteral("inactive"));

        hash[0] = hash.at(0) == '0' ? '1' : '0';
        const auto mismatch = M6XpcReadOnlyServiceClientTestAccess::trustedStatus(
            service.endpoint(), "cdhash H\"" + hash + "\"");
        QCOMPARE(mismatch.status, XpcReadOnlyClientStatus::PeerIdentityMismatch);
        QVERIFY(!mismatch.ok);
        QVERIFY(mismatch.service.isEmpty());
        QVERIFY(mismatch.state.isEmpty());
        QCOMPARE(mismatch.protocolVersion, 0ULL);
    }

    void probeAcceptsOnlyTheFixedPayload() {
        AnonymousService service(ReplyShape::Probe);
        QVERIFY(service.endpoint() != nullptr);

        const XpcReadOnlyClientResult result = M6XpcReadOnlyServiceClientTestAccess::request(
            service.endpoint(), XpcReadOnlyClientOperation::Probe);
        QCOMPARE(result.status, XpcReadOnlyClientStatus::Success);
        QVERIFY(result.succeeded());
        QVERIFY(result.ok);
        QCOMPARE(result.service, QStringLiteral("llm_interceptor"));
        QCOMPARE(result.protocolVersion, 1ULL);
        QVERIFY(result.state.isEmpty());
    }

    void statusAcceptsOnlyTheFixedPayload() {
        AnonymousService service(ReplyShape::Status);
        QVERIFY(service.endpoint() != nullptr);

        const XpcReadOnlyClientResult result = M6XpcReadOnlyServiceClientTestAccess::request(
            service.endpoint(), XpcReadOnlyClientOperation::Status);
        QCOMPARE(result.status, XpcReadOnlyClientStatus::Success);
        QVERIFY(result.ok);
        QCOMPARE(result.service, QStringLiteral("llm_interceptor"));
        QCOMPARE(result.protocolVersion, 1ULL);
        QCOMPARE(result.state, QStringLiteral("inactive"));
    }

    void missingAndMalformedReplyFieldsAreRejected() {
        const QList<ReplyShape> shapes = {ReplyShape::Empty,          ReplyShape::MissingOk,
                                          ReplyShape::WrongOkType,    ReplyShape::WrongService,
                                          ReplyShape::WrongVersion,   ReplyShape::MissingService,
                                          ReplyShape::MissingVersion, ReplyShape::ExtraField};
        for (ReplyShape shape : shapes) {
            AnonymousService service(shape);
            QVERIFY(service.endpoint() != nullptr);
            const XpcReadOnlyClientResult result = M6XpcReadOnlyServiceClientTestAccess::request(
                service.endpoint(), XpcReadOnlyClientOperation::Probe);
            QCOMPARE(result.status, XpcReadOnlyClientStatus::InvalidReply);
            QVERIFY(!result.succeeded());
            QVERIFY(!result.ok);
        }
    }

    void wrongStatusValueAndUnexpectedFieldsAreRejected() {
        const QList<ReplyShape> shapes = {ReplyShape::WrongOkType,    ReplyShape::WrongService,
                                          ReplyShape::WrongVersion,   ReplyShape::MissingService,
                                          ReplyShape::MissingVersion, ReplyShape::MissingState,
                                          ReplyShape::WrongState,     ReplyShape::ExtraField};
        for (ReplyShape shape : shapes) {
            AnonymousService service(shape);
            QVERIFY(service.endpoint() != nullptr);
            const XpcReadOnlyClientResult result = M6XpcReadOnlyServiceClientTestAccess::request(
                service.endpoint(), XpcReadOnlyClientOperation::Status);
            QCOMPARE(result.status, XpcReadOnlyClientStatus::InvalidReply);
        }
    }

    void noReplyIsBoundedByCallerTimeout() {
        AnonymousService service(ReplyShape::Probe, true, 250);
        QVERIFY(service.endpoint() != nullptr);
        const XpcReadOnlyClientResult result = M6XpcReadOnlyServiceClientTestAccess::request(
            service.endpoint(), XpcReadOnlyClientOperation::Probe, 40);
        QCOMPARE(result.status, XpcReadOnlyClientStatus::TimedOut);
    }

    void unavailableEndpointAndInvalidTimeoutAreRejected() {
        AnonymousService service(ReplyShape::Probe);
        QVERIFY(service.endpoint() != nullptr);
        service.makeUnavailable();
        const XpcReadOnlyClientResult unavailable = M6XpcReadOnlyServiceClientTestAccess::request(
            service.endpoint(), XpcReadOnlyClientOperation::Probe, 200);
        QVERIFY(unavailable.status == XpcReadOnlyClientStatus::ServiceUnavailable ||
                unavailable.status == XpcReadOnlyClientStatus::TimedOut);

        const XpcReadOnlyClientResult invalidTimeout =
            M6XpcReadOnlyServiceClientTestAccess::request(service.endpoint(),
                                                          XpcReadOnlyClientOperation::Probe, 0);
        QCOMPARE(invalidTimeout.status, XpcReadOnlyClientStatus::InvalidTimeout);
        const XpcReadOnlyClientResult excessiveTimeout =
            M6XpcReadOnlyServiceClientTestAccess::request(
                service.endpoint(), XpcReadOnlyClientOperation::Status,
                XpcReadOnlyServiceClient::maximumTimeoutMs + 1);
        QCOMPARE(excessiveTimeout.status, XpcReadOnlyClientStatus::InvalidTimeout);
    }

    void concurrentCallsRemainIndependent() {
        AnonymousService probeService(ReplyShape::Probe);
        AnonymousService statusService(ReplyShape::Status);
        QVERIFY(probeService.endpoint() != nullptr);
        QVERIFY(statusService.endpoint() != nullptr);

        auto probe = std::async(std::launch::async, [&] {
            return M6XpcReadOnlyServiceClientTestAccess::request(probeService.endpoint(),
                                                                 XpcReadOnlyClientOperation::Probe);
        });
        auto status = std::async(std::launch::async, [&] {
            return M6XpcReadOnlyServiceClientTestAccess::request(
                statusService.endpoint(), XpcReadOnlyClientOperation::Status);
        });

        const XpcReadOnlyClientResult probeResult = probe.get();
        const XpcReadOnlyClientResult statusResult = status.get();
        QCOMPARE(probeResult.status, XpcReadOnlyClientStatus::Success);
        QCOMPARE(statusResult.status, XpcReadOnlyClientStatus::Success);
        QVERIFY(probeResult.state.isEmpty());
        QCOMPARE(statusResult.state, QStringLiteral("inactive"));
    }
};

} // namespace interceptor

QTEST_GUILESS_MAIN(interceptor::M6XpcReadOnlyServiceClientTests)
#include "M6XpcReadOnlyServiceClientTests.moc"
