#include "network/XpcControlRequestGate.hpp"

#include <QtTest>

#include <xpc/xpc.h>

namespace interceptor {

class FakeCodeSignaturePolicy final : public XpcPeerCodeSignaturePolicy {
  public:
    bool authenticate(xpc_object_t message, const QByteArray &expectedRequirement,
                      QString *error) override {
        ++calls;
        seenMessage = message;
        seenRequirement = expectedRequirement;
        if (error)
            *error = policyError;
        return result;
    }

    int calls = 0;
    xpc_object_t seenMessage = nullptr;
    QByteArray seenRequirement;
    QString policyError;
    bool result = true;
};

class M6XpcControlRequestGateTests final : public QObject {
    Q_OBJECT

  private:
    static xpc_object_t request(const char *operation) {
        xpc_object_t message = xpc_dictionary_create(nullptr, nullptr, 0);
        if (message)
            xpc_dictionary_set_string(message, "operation", operation);
        return message;
    }

  private slots:
    void authenticatesBeforeInspectingMalformedProtocolFields() {
        xpc_object_t message = xpc_dictionary_create(nullptr, nullptr, 0);
        QVERIFY(message != nullptr);
        xpc_dictionary_set_string(message, "operation", "Start");
        xpc_dictionary_set_int64(message, "extra", 7);

        FakeCodeSignaturePolicy policy;
        XpcControlRequestGate gate(QByteArrayLiteral("trusted local requirement"), policy);
        policy.result = false;
        policy.policyError = QStringLiteral("signature_requirement_rejected");
        XpcControlRequest parsed{XpcControlOperation::Status};
        QString error;

        QVERIFY(!gate.parse(message, &parsed, &error));
        QCOMPARE(policy.calls, 1);
        QCOMPARE(policy.seenMessage, message);
        QCOMPARE(policy.seenRequirement, QByteArrayLiteral("trusted local requirement"));
        QCOMPARE(error, QStringLiteral("signature_requirement_rejected"));
        QCOMPARE(parsed.operation, XpcControlOperation::Invalid);
        xpc_release(message);
    }

    void acceptsOnlyTheTwoBoundedReadOnlyRequestNames() {
        FakeCodeSignaturePolicy policy;
        XpcControlRequestGate gate(QByteArrayLiteral("trusted"), policy);
        QString error = QStringLiteral("stale");

        xpc_object_t probe = request("probe");
        QVERIFY(probe != nullptr);
        XpcControlRequest parsed{XpcControlOperation::Status};
        QVERIFY(gate.parse(probe, &parsed, &error));
        QCOMPARE(parsed.operation, XpcControlOperation::Probe);
        QCOMPARE(error, QString());
        xpc_release(probe);

        xpc_object_t status = request("status");
        QVERIFY(status != nullptr);
        QVERIFY(gate.parse(status, &parsed, &error));
        QCOMPARE(parsed.operation, XpcControlOperation::Status);
        QCOMPARE(policy.calls, 2);
        xpc_release(status);
    }

    void retainsTheTrustedRequirementSuppliedAtConstruction() {
        FakeCodeSignaturePolicy policy;
        QByteArray requirement = QByteArrayLiteral("trusted requirement");
        XpcControlRequestGate gate(requirement, policy);
        requirement.fill('x');

        xpc_object_t message = request("status");
        QVERIFY(message != nullptr);
        XpcControlRequest parsed;
        QString error;
        QVERIFY(gate.parse(message, &parsed, &error));
        QCOMPARE(policy.seenRequirement, QByteArrayLiteral("trusted requirement"));
        QCOMPARE(parsed.operation, XpcControlOperation::Status);
        xpc_release(message);
    }

    void rejectsInvalidTrustedRequirementsBeforeCallingPolicy() {
        xpc_object_t message = request("probe");
        QVERIFY(message != nullptr);
        const QList<QByteArray> invalidRequirements = {
            QByteArray(),
            QByteArray(1025, 'x'),
        };

        for (const QByteArray &requirement : invalidRequirements) {
            FakeCodeSignaturePolicy policy;
            XpcControlRequestGate gate(requirement, policy);
            XpcControlRequest parsed{XpcControlOperation::Status};
            QString error;
            QVERIFY(!gate.parse(message, &parsed, &error));
            QCOMPARE(error, QStringLiteral("xpc_peer_requirement_invalid"));
            QCOMPARE(policy.calls, 0);
            QCOMPARE(parsed.operation, XpcControlOperation::Invalid);
        }
        xpc_release(message);
    }

    void rejectsUnsupportedAndMalformedOperations() {
        const QList<const char *> unsupported = {"Start", "Heartbeat", "Stop", "install", ""};
        FakeCodeSignaturePolicy policy;
        XpcControlRequestGate gate(QByteArrayLiteral("trusted"), policy);
        for (const char *value : unsupported) {
            xpc_object_t message = request(value);
            QVERIFY(message != nullptr);
            XpcControlRequest parsed{XpcControlOperation::Status};
            QString error;
            QVERIFY(!gate.parse(message, &parsed, &error));
            QCOMPARE(error, value[0] == '\0'
                                ? QStringLiteral("xpc_control_request_operation_invalid")
                                : QStringLiteral("xpc_control_request_operation_unsupported"));
            QCOMPARE(parsed.operation, XpcControlOperation::Invalid);
            xpc_release(message);
        }

        xpc_object_t message = xpc_dictionary_create(nullptr, nullptr, 0);
        QVERIFY(message != nullptr);
        xpc_dictionary_set_int64(message, "operation", 1);
        QString error;
        QVERIFY(!gate.parse(message, nullptr, &error));
        QCOMPARE(error, QStringLiteral("xpc_control_request_output_invalid"));
        xpc_release(message);
    }

    void rejectsOversizedOperationAndAnyRequestBodyOrCapability() {
        FakeCodeSignaturePolicy policy;
        XpcControlRequestGate gate(QByteArrayLiteral("trusted"), policy);
        QString error;

        const QByteArray longOperation(17, 'x');
        xpc_object_t tooLong = xpc_dictionary_create(nullptr, nullptr, 0);
        QVERIFY(tooLong != nullptr);
        xpc_dictionary_set_string(tooLong, "operation", longOperation.constData());
        XpcControlRequest parsed;
        QVERIFY(!gate.parse(tooLong, &parsed, &error));
        QCOMPARE(error, QStringLiteral("xpc_control_request_operation_invalid"));
        xpc_release(tooLong);

        xpc_object_t withBody = request("status");
        QVERIFY(withBody != nullptr);
        QByteArray oversizedBody(64 * 1024 + 1, 'b');
        xpc_dictionary_set_data(withBody, "body", oversizedBody.constData(),
                                static_cast<size_t>(oversizedBody.size()));
        QVERIFY(!gate.parse(withBody, &parsed, &error));
        QCOMPARE(error, QStringLiteral("xpc_control_request_fields_invalid"));
        xpc_release(withBody);

        xpc_object_t withCapability = request("probe");
        QVERIFY(withCapability != nullptr);
        xpc_dictionary_set_data(withCapability, "capability", "secret", 6);
        QVERIFY(!gate.parse(withCapability, &parsed, &error));
        QCOMPARE(error, QStringLiteral("xpc_control_request_fields_invalid"));
        QCOMPARE(policy.calls, 3);
        xpc_release(withCapability);
    }

    void rejectsEveryOtherFieldIncludingLifecycleCommands() {
        const QList<const char *> forbiddenKeys = {"body", "capability", "anchor", "snapshot"};
        FakeCodeSignaturePolicy policy;
        XpcControlRequestGate gate(QByteArrayLiteral("trusted"), policy);
        for (const char *key : forbiddenKeys) {
            xpc_object_t message = request("status");
            QVERIFY(message != nullptr);
            xpc_dictionary_set_string(message, key, "Start");
            XpcControlRequest parsed;
            QString error;
            QVERIFY(!gate.parse(message, &parsed, &error));
            QCOMPARE(error, QStringLiteral("xpc_control_request_fields_invalid"));
            QCOMPARE(parsed.operation, XpcControlOperation::Invalid);
            xpc_release(message);
        }
        QCOMPARE(policy.calls, forbiddenKeys.size());
    }
};

} // namespace interceptor

QTEST_GUILESS_MAIN(interceptor::M6XpcControlRequestGateTests)
#include "M6XpcControlRequestGateTests.moc"
