#include "network/XpcReadOnlyServiceClient.hpp"

#include <QtTest>

#include <xpc/xpc.h>

#include <future>
#include <vector>

namespace interceptor {

class M6XpcReadOnlyServiceClientTestAccess final {
  public:
    static XpcReadOnlyClientResult
    request(xpc_endpoint_t endpoint, XpcReadOnlyClientOperation operation, int timeoutMs = 1500) {
        return XpcReadOnlyServiceClient::requestWithEndpointForTesting(endpoint, operation,
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
    explicit AnonymousService(ReplyShape shape, bool reply = true, int replyDelayMs = 0)
        : shape_(shape), reply_(reply), replyDelayMs_(replyDelayMs) {
        listener_ = xpc_connection_create(nullptr, nullptr);
        if (!listener_)
            return;
        endpoint_ = xpc_endpoint_create(listener_);
        if (!endpoint_)
            return;
        xpc_connection_set_event_handler(listener_, ^(xpc_object_t event) {
          if (xpc_get_type(event) != XPC_TYPE_CONNECTION)
              return;
          xpc_connection_t peer = reinterpret_cast<xpc_connection_t>(event);
          xpc_retain(peer);
          const ReplyShape shape = shape_;
          const bool shouldReply = reply_;
          const int replyDelayMs = replyDelayMs_;
          xpc_connection_set_event_handler(peer, ^(xpc_object_t message) {
            if (!shouldReply || xpc_get_type(message) != XPC_TYPE_DICTIONARY)
                return;
            xpc_object_t retainedMessage = xpc_retain(message);
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
                           });
          });
          xpc_connection_activate(peer);
          peers_.push_back(peer);
        });
        xpc_connection_activate(listener_);
    }

    ~AnonymousService() {
        for (xpc_connection_t peer : peers_) {
            xpc_connection_cancel(peer);
            xpc_release(peer);
        }
        if (listener_) {
            xpc_connection_cancel(listener_);
            xpc_release(listener_);
        }
        if (endpoint_)
            xpc_release(endpoint_);
    }

    xpc_endpoint_t endpoint() const { return endpoint_; }

    void makeUnavailable() {
        if (listener_) {
            xpc_connection_cancel(listener_);
            xpc_release(listener_);
            listener_ = nullptr;
        }
    }

  private:
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

    xpc_connection_t listener_ = nullptr;
    xpc_endpoint_t endpoint_ = nullptr;
    std::vector<xpc_connection_t> peers_;
    ReplyShape shape_;
    bool reply_;
    int replyDelayMs_;
};
} // namespace

class M6XpcReadOnlyServiceClientTests final : public QObject {
    Q_OBJECT

  private slots:
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
