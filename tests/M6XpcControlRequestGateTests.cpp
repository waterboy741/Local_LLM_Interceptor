#include "network/XpcControlRequestGate.hpp"

#include <QtTest>

#include <string>
#include <string_view>

#include <xpc/xpc.h>

namespace interceptor {

class FakeCodeSignaturePolicy final : public XpcPeerCodeSignaturePolicy {
  public:
    bool authenticate(xpc_object_t message, std::string_view expectedRequirement,
                      std::string *error) override {
        ++calls;
        seenMessage = message;
        seenRequirement = expectedRequirement;
        if (error)
            *error = policyError;
        return result;
    }

    int calls = 0;
    xpc_object_t seenMessage = nullptr;
    std::string seenRequirement;
    std::string policyError;
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
        XpcControlRequestGate gate("trusted local requirement", policy);
        policy.result = false;
        policy.policyError = "signature_requirement_rejected";
        XpcControlRequest parsed{XpcControlOperation::Status};
        std::string error;

        QVERIFY(!gate.parse(message, &parsed, &error));
        QCOMPARE(policy.calls, 1);
        QCOMPARE(policy.seenMessage, message);
        QCOMPARE(policy.seenRequirement, "trusted local requirement");
        QCOMPARE(error, "signature_requirement_rejected");
        QCOMPARE(parsed.operation, XpcControlOperation::Invalid);
        xpc_release(message);
    }

    void acceptsOnlyTheTwoBoundedReadOnlyRequestNames() {
        FakeCodeSignaturePolicy policy;
        XpcControlRequestGate gate("trusted", policy);
        std::string error = "stale";

        xpc_object_t probe = request("probe");
        QVERIFY(probe != nullptr);
        XpcControlRequest parsed{XpcControlOperation::Status};
        QVERIFY(gate.parse(probe, &parsed, &error));
        QCOMPARE(parsed.operation, XpcControlOperation::Probe);
        QCOMPARE(error, std::string());
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
        std::string requirement = "trusted requirement";
        XpcControlRequestGate gate(requirement, policy);
        requirement.assign(requirement.size(), 'x');

        xpc_object_t message = request("status");
        QVERIFY(message != nullptr);
        XpcControlRequest parsed;
        std::string error;
        QVERIFY(gate.parse(message, &parsed, &error));
        QCOMPARE(policy.seenRequirement, "trusted requirement");
        QCOMPARE(parsed.operation, XpcControlOperation::Status);
        xpc_release(message);
    }

    void rejectsInvalidTrustedRequirementsBeforeCallingPolicy() {
        xpc_object_t message = request("probe");
        QVERIFY(message != nullptr);
        const QList<std::string> invalidRequirements = {
            std::string(),
            std::string(1025, 'x'),
        };

        for (const std::string &requirement : invalidRequirements) {
            FakeCodeSignaturePolicy policy;
            XpcControlRequestGate gate(requirement, policy);
            XpcControlRequest parsed{XpcControlOperation::Status};
            std::string error;
            QVERIFY(!gate.parse(message, &parsed, &error));
            QCOMPARE(error, "xpc_peer_requirement_invalid");
            QCOMPARE(policy.calls, 0);
            QCOMPARE(parsed.operation, XpcControlOperation::Invalid);
        }
        xpc_release(message);
    }

    void rejectsUnsupportedAndMalformedOperations() {
        const QList<const char *> unsupported = {"Start", "Heartbeat", "Stop", "install", ""};
        FakeCodeSignaturePolicy policy;
        XpcControlRequestGate gate("trusted", policy);
        for (const char *value : unsupported) {
            xpc_object_t message = request(value);
            QVERIFY(message != nullptr);
            XpcControlRequest parsed{XpcControlOperation::Status};
            std::string error;
            QVERIFY(!gate.parse(message, &parsed, &error));
            QCOMPARE(error, value[0] == '\0' ? "xpc_control_request_operation_invalid"
                                             : "xpc_control_request_operation_unsupported");
            QCOMPARE(parsed.operation, XpcControlOperation::Invalid);
            xpc_release(message);
        }

        xpc_object_t message = xpc_dictionary_create(nullptr, nullptr, 0);
        QVERIFY(message != nullptr);
        xpc_dictionary_set_int64(message, "operation", 1);
        std::string error;
        QVERIFY(!gate.parse(message, nullptr, &error));
        QCOMPARE(error, "xpc_control_request_output_invalid");
        xpc_release(message);
    }

    void rejectsOversizedOperationAndAnyRequestBodyOrCapability() {
        FakeCodeSignaturePolicy policy;
        XpcControlRequestGate gate("trusted", policy);
        std::string error;

        const std::string longOperation(17, 'x');
        xpc_object_t tooLong = xpc_dictionary_create(nullptr, nullptr, 0);
        QVERIFY(tooLong != nullptr);
        xpc_dictionary_set_string(tooLong, "operation", longOperation.c_str());
        XpcControlRequest parsed;
        QVERIFY(!gate.parse(tooLong, &parsed, &error));
        QCOMPARE(error, "xpc_control_request_operation_invalid");
        xpc_release(tooLong);

        xpc_object_t withBody = request("status");
        QVERIFY(withBody != nullptr);
        std::string oversizedBody(64 * 1024 + 1, 'b');
        xpc_dictionary_set_data(withBody, "body", oversizedBody.c_str(),
                                static_cast<size_t>(oversizedBody.size()));
        QVERIFY(!gate.parse(withBody, &parsed, &error));
        QCOMPARE(error, "xpc_control_request_fields_invalid");
        xpc_release(withBody);

        xpc_object_t withCapability = request("probe");
        QVERIFY(withCapability != nullptr);
        xpc_dictionary_set_data(withCapability, "capability", "secret", 6);
        QVERIFY(!gate.parse(withCapability, &parsed, &error));
        QCOMPARE(error, "xpc_control_request_fields_invalid");
        QCOMPARE(policy.calls, 3);
        xpc_release(withCapability);
    }

    void rejectsEveryOtherFieldIncludingLifecycleCommands() {
        const QList<const char *> forbiddenKeys = {"body", "capability", "anchor", "snapshot"};
        FakeCodeSignaturePolicy policy;
        XpcControlRequestGate gate("trusted", policy);
        for (const char *key : forbiddenKeys) {
            xpc_object_t message = request("status");
            QVERIFY(message != nullptr);
            xpc_dictionary_set_string(message, key, "Start");
            XpcControlRequest parsed;
            std::string error;
            QVERIFY(!gate.parse(message, &parsed, &error));
            QCOMPARE(error, "xpc_control_request_fields_invalid");
            QCOMPARE(parsed.operation, XpcControlOperation::Invalid);
            xpc_release(message);
        }
        QCOMPARE(policy.calls, forbiddenKeys.size());
    }

    void requiresExplicitOptInForVersionedStart() {
        FakeCodeSignaturePolicy policy;
        XpcControlRequestGate readOnly("trusted", policy);
        XpcControlRequestGate synthetic("trusted", policy,
                                        XpcControlRequestGate::Mode::SyntheticLifecycle);
        xpc_object_t message = request("start");
        QVERIFY(message != nullptr);
        xpc_dictionary_set_uint64(message, "protocol_version", 1);
        XpcControlRequest parsed;
        std::string error;

        QVERIFY(!readOnly.parse(message, &parsed, &error));
        QCOMPARE(parsed.operation, XpcControlOperation::Invalid);
        QVERIFY(synthetic.parse(message, &parsed, &error));
        QCOMPARE(parsed.operation, XpcControlOperation::Start);
        QVERIFY(error.empty());
        QCOMPARE(policy.calls, 2);
        xpc_release(message);
    }

    void rejectsMalformedSyntheticStartFields() {
        FakeCodeSignaturePolicy policy;
        XpcControlRequestGate gate("trusted", policy,
                                   XpcControlRequestGate::Mode::SyntheticLifecycle);
        xpc_object_t message = request("start");
        QVERIFY(message != nullptr);
        XpcControlRequest parsed;
        std::string error;

        QVERIFY(!gate.parse(message, &parsed, &error));
        QCOMPARE(error, "xpc_control_request_fields_invalid");
        xpc_dictionary_set_int64(message, "protocol_version", 1);
        QVERIFY(!gate.parse(message, &parsed, &error));
        QCOMPARE(error, "xpc_control_request_version_invalid");
        xpc_dictionary_set_uint64(message, "protocol_version", 2);
        QVERIFY(!gate.parse(message, &parsed, &error));
        QCOMPARE(error, "xpc_control_request_version_invalid");
        xpc_dictionary_set_uint64(message, "protocol_version", 1);
        xpc_dictionary_set_string(message, "body", "unexpected");
        QVERIFY(!gate.parse(message, &parsed, &error));
        QCOMPARE(error, "xpc_control_request_fields_invalid");
        QCOMPARE(parsed.operation, XpcControlOperation::Invalid);
        QCOMPARE(policy.calls, 4);
        xpc_release(message);
    }

    void syntheticModeKeepsTheOneFieldStatusContract() {
        FakeCodeSignaturePolicy policy;
        XpcControlRequestGate gate("trusted", policy,
                                   XpcControlRequestGate::Mode::SyntheticLifecycle);
        xpc_object_t message = request("status");
        QVERIFY(message != nullptr);
        XpcControlRequest parsed;
        std::string error;

        QVERIFY(gate.parse(message, &parsed, &error));
        QCOMPARE(parsed.operation, XpcControlOperation::Status);
        xpc_dictionary_set_uint64(message, "protocol_version", 1);
        QVERIFY(!gate.parse(message, &parsed, &error));
        QCOMPARE(error, "xpc_control_request_fields_invalid");
        QCOMPARE(parsed.operation, XpcControlOperation::Invalid);
        xpc_release(message);
    }

    void authenticatesBeforeValidatingSyntheticStartVersion() {
        FakeCodeSignaturePolicy policy;
        policy.result = false;
        policy.policyError = "signature_requirement_rejected";
        XpcControlRequestGate gate("trusted", policy,
                                   XpcControlRequestGate::Mode::SyntheticLifecycle);
        xpc_object_t message = request("start");
        QVERIFY(message != nullptr);
        xpc_dictionary_set_string(message, "protocol_version", "1");
        XpcControlRequest parsed{XpcControlOperation::Status};
        std::string error;

        QVERIFY(!gate.parse(message, &parsed, &error));
        QCOMPARE(error, "signature_requirement_rejected");
        QCOMPARE(parsed.operation, XpcControlOperation::Invalid);
        QCOMPARE(policy.calls, 1);
        QCOMPARE(policy.seenMessage, message);
        xpc_release(message);
    }
};

} // namespace interceptor

QTEST_GUILESS_MAIN(interceptor::M6XpcControlRequestGateTests)
#include "M6XpcControlRequestGateTests.moc"
