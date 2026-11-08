#include "network/XpcReadOnlyServiceListener.hpp"

#include <QtTest>

#include <xpc/xpc.h>

namespace interceptor {

class FakeCodeSignaturePolicy final : public XpcPeerCodeSignaturePolicy {
  public:
    bool authenticate(xpc_object_t message, const QByteArray &expectedRequirement,
                      QString *error) override {
        ++calls;
        lastMessage = message;
        lastRequirement = expectedRequirement;
        if (error)
            *error = errorText;
        return accepted;
    }

    int calls = 0;
    xpc_object_t lastMessage = nullptr;
    QByteArray lastRequirement;
    QString errorText;
    bool accepted = true;
};

class M6XpcReadOnlyServiceListenerTests final : public QObject {
    Q_OBJECT

  private:
    static xpc_object_t message(const char *operation) {
        xpc_object_t value = xpc_dictionary_create(nullptr, nullptr, 0);
        if (value)
            xpc_dictionary_set_string(value, "operation", operation);
        return value;
    }

    static QString valueString(xpc_object_t dictionary, const char *key) {
        const char *value = xpc_dictionary_get_string(dictionary, key);
        return value ? QString::fromUtf8(value) : QString();
    }

  private slots:
    void probeReplyPayloadHasOnlyTheFixedBoundedFields() {
        xpc_object_t reply =
            XpcReadOnlyControlAdapter::createBoundedReplyPayload(XpcControlOperation::Probe);
        QVERIFY(reply != nullptr);
        QCOMPARE(xpc_get_type(reply), XPC_TYPE_DICTIONARY);
        QCOMPARE(xpc_dictionary_get_count(reply), 3ULL);
        QCOMPARE(xpc_get_type(xpc_dictionary_get_value(reply, "ok")), XPC_TYPE_BOOL);
        QVERIFY(xpc_dictionary_get_bool(reply, "ok"));
        QCOMPARE(valueString(reply, "service"), QStringLiteral("llm_interceptor"));
        QCOMPARE(xpc_get_type(xpc_dictionary_get_value(reply, "protocol_version")),
                 XPC_TYPE_UINT64);
        QCOMPARE(xpc_dictionary_get_uint64(reply, "protocol_version"), 1ULL);
        xpc_release(reply);
    }

    void statusReplyPayloadHasOnlyTheFixedBoundedFields() {
        xpc_object_t reply =
            XpcReadOnlyControlAdapter::createBoundedReplyPayload(XpcControlOperation::Status);
        QVERIFY(reply != nullptr);
        QCOMPARE(xpc_dictionary_get_count(reply), 4ULL);
        QVERIFY(xpc_dictionary_get_bool(reply, "ok"));
        QCOMPARE(valueString(reply, "service"), QStringLiteral("llm_interceptor"));
        QCOMPARE(xpc_dictionary_get_uint64(reply, "protocol_version"), 1ULL);
        QCOMPARE(valueString(reply, "state"), QStringLiteral("inactive"));
        xpc_release(reply);
    }

    void unsupportedOperationCannotProduceAReplyPayload() {
        QCOMPARE(XpcReadOnlyControlAdapter::createBoundedReplyPayload(XpcControlOperation::Invalid),
                 nullptr);
    }

    void adapterAuthenticatesAndRejectsUnauthenticatedMessagesWithoutReply() {
        FakeCodeSignaturePolicy policy;
        policy.accepted = false;
        policy.errorText = QStringLiteral("xpc_peer_code_requirement_failed");
        XpcControlRequestGate gate(QByteArrayLiteral("trusted requirement"), policy);
        XpcReadOnlyControlAdapter adapter(gate);
        xpc_object_t request = message("probe");
        QVERIFY(request != nullptr);

        QCOMPARE(adapter.handleMessage(request), nullptr);
        QCOMPARE(policy.calls, 1);
        QCOMPARE(policy.lastMessage, request);
        QCOMPARE(policy.lastRequirement, QByteArrayLiteral("trusted requirement"));
        xpc_release(request);
    }

    void adapterAuthenticatesValidRequestBeforeReplyEncoding() {
        FakeCodeSignaturePolicy policy;
        XpcControlRequestGate gate(QByteArrayLiteral("trusted requirement"), policy);
        XpcReadOnlyControlAdapter adapter(gate);
        xpc_object_t request = message("status");
        QVERIFY(request != nullptr);

        // A locally-created dictionary has no XPC reply context; the adapter
        // still authenticates and accepts the protocol before reply creation.
        QCOMPARE(adapter.handleMessage(request), nullptr);
        QCOMPARE(policy.calls, 1);
        QCOMPARE(policy.lastMessage, request);
        xpc_release(request);
    }

    void adapterRejectsUnsupportedAndMalformedMessagesWithoutReply() {
        FakeCodeSignaturePolicy policy;
        XpcControlRequestGate gate(QByteArrayLiteral("trusted requirement"), policy);
        XpcReadOnlyControlAdapter adapter(gate);

        xpc_object_t unsupported = message("Start");
        QVERIFY(unsupported != nullptr);
        QCOMPARE(adapter.handleMessage(unsupported), nullptr);
        xpc_release(unsupported);

        xpc_object_t malformed = xpc_dictionary_create(nullptr, nullptr, 0);
        QVERIFY(malformed != nullptr);
        xpc_dictionary_set_int64(malformed, "operation", 7);
        QCOMPARE(adapter.handleMessage(malformed), nullptr);
        xpc_release(malformed);

        xpc_object_t extra = message("status");
        QVERIFY(extra != nullptr);
        xpc_dictionary_set_string(extra, "capability", "should-not-be-accepted");
        QCOMPARE(adapter.handleMessage(extra), nullptr);
        xpc_release(extra);
        QCOMPARE(policy.calls, 3);
    }

    void listenerConfigurationFailuresStayStoppedAndStopIsIdempotent() {
        FakeCodeSignaturePolicy configuredPolicy;
        XpcControlRequestGate configuredGate(QByteArrayLiteral("trusted"), configuredPolicy);
        XpcReadOnlyControlAdapter configuredAdapter(configuredGate);

        const QList<QByteArray> invalidNames = {
            QByteArray(),
            QByteArrayLiteral("invalid"),
            QByteArrayLiteral(".org.example"),
            QByteArrayLiteral("org.example."),
            QByteArrayLiteral("org..example"),
            QByteArrayLiteral("org/example.service"),
            QByteArray(129, 'a'),
        };
        for (const QByteArray &name : invalidNames) {
            XpcReadOnlyServiceListener invalidName(name, configuredAdapter);
            QString error;
            QVERIFY(!invalidName.start(&error));
            QCOMPARE(error, QStringLiteral("xpc_listener_service_name_invalid"));
            QVERIFY(!invalidName.isRunning());
            invalidName.stop();
            invalidName.stop();
            QVERIFY(!invalidName.isRunning());
        }

        FakeCodeSignaturePolicy missingPolicy;
        XpcControlRequestGate missingGate(QByteArray(), missingPolicy);
        XpcReadOnlyControlAdapter missingAdapter(missingGate);
        XpcReadOnlyServiceListener missingRequirement(QByteArrayLiteral("org.example.interceptor"),
                                                      missingAdapter);
        QString error = QStringLiteral("stale");
        QVERIFY(!missingRequirement.start(&error));
        QCOMPARE(error, QStringLiteral("xpc_listener_trusted_requirement_missing"));
        QVERIFY(!missingRequirement.isRunning());
        QCOMPARE(configuredPolicy.calls, 0);
        QCOMPARE(missingPolicy.calls, 0);
    }
};

} // namespace interceptor

QTEST_GUILESS_MAIN(interceptor::M6XpcReadOnlyServiceListenerTests)
#include "M6XpcReadOnlyServiceListenerTests.moc"
