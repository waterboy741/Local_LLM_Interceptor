#include "network/XpcControlRequestGate.hpp"
#include "network/XpcSessionControlReply.hpp"

#include <QtTest>

#include <string>
#include <vector>

#include <xpc/xpc.h>

namespace interceptor {

class FakeSessionControlPolicy final : public XpcPeerCodeSignaturePolicy {
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

class M6XpcSessionControlGrammarTests final : public QObject {
    Q_OBJECT

  private:
    static xpc_object_t sessionMessage(const char *operation) {
        xpc_object_t message = xpc_dictionary_create(nullptr, nullptr, 0);
        if (message) {
            xpc_dictionary_set_string(message, "operation", operation);
            xpc_dictionary_set_uint64(message, "protocol_version", 1);
        }
        return message;
    }
    static xpc_object_t heartbeatMessage(const char *sessionId, const size_t capabilityBytes) {
        xpc_object_t message = sessionMessage("heartbeat");
        if (message) {
            xpc_dictionary_set_string(message, "session_id", sessionId);
            const std::vector<unsigned char> capability(capabilityBytes, 0x5a);
            xpc_dictionary_set_data(message, "session_capability", capability.data(),
                                    capability.size());
        }
        return message;
    }

  private slots:
    void readOnlyModeRejectsTheNewGrammarUnchanged() {
        FakeSessionControlPolicy policy;
        XpcControlRequestGate gate("trusted", policy);
        XpcControlRequest parsed{XpcControlOperation::Status};
        std::string error;

        // Probe and status v1 stay answerable exactly as before.
        for (const char *operation : {"probe", "status"}) {
            xpc_object_t message = xpc_dictionary_create(nullptr, nullptr, 0);
            QVERIFY(message != nullptr);
            xpc_dictionary_set_string(message, "operation", operation);
            QVERIFY(gate.parse(message, &parsed, &error));
            QCOMPARE(parsed.operation,
                     operation[0] == 'p' ? XpcControlOperation::Probe : XpcControlOperation::Status);
            QVERIFY(parsed.sessionId.empty());
            QVERIFY(parsed.sessionCapability.empty());
            xpc_release(message);
        }

        // The new names alone stay unsupported; the new field shapes stay unparsed.
        for (const char *operation : {"start", "heartbeat", "stop"}) {
            xpc_object_t message = xpc_dictionary_create(nullptr, nullptr, 0);
            QVERIFY(message != nullptr);
            xpc_dictionary_set_string(message, "operation", operation);
            QVERIFY(!gate.parse(message, &parsed, &error));
            QCOMPARE(error, "xpc_control_request_operation_unsupported");
            QCOMPARE(parsed.operation, XpcControlOperation::Invalid);
            xpc_release(message);
        }
        xpc_object_t start = sessionMessage("start");
        QVERIFY(start != nullptr);
        QVERIFY(!gate.parse(start, &parsed, &error));
        QCOMPARE(error, "xpc_control_request_fields_invalid");
        QCOMPARE(parsed.operation, XpcControlOperation::Invalid);
        xpc_release(start);

        xpc_object_t heartbeat = heartbeatMessage("session-id", 32);
        QVERIFY(heartbeat != nullptr);
        QVERIFY(!gate.parse(heartbeat, &parsed, &error));
        QCOMPARE(error, "xpc_control_request_fields_invalid");
        QCOMPARE(parsed.operation, XpcControlOperation::Invalid);
        QVERIFY(parsed.sessionCapability.empty());
        xpc_release(heartbeat);
    }

    void syntheticModeAcceptsOnlyTheExactStartShape() {
        FakeSessionControlPolicy policy;
        XpcControlRequestGate gate("trusted", policy, XpcControlRequestGate::Mode::SyntheticLifecycle);
        XpcControlRequest parsed{XpcControlOperation::Status};
        std::string error;

        xpc_object_t start = sessionMessage("start");
        QVERIFY(start != nullptr);
        QVERIFY(gate.parse(start, &parsed, &error));
        QCOMPARE(parsed.operation, XpcControlOperation::Start);
        QVERIFY(parsed.sessionId.empty());
        QVERIFY(parsed.sessionCapability.empty());
        QCOMPARE(error, std::string());
        xpc_release(start);

        // A Start carries no snapshot, anchor, path, timestamp, or session field.
        for (const char *extra : {"session_id", "session_capability", "timestamp", "snapshot",
                                  "anchor", "path", "body"}) {
            xpc_object_t message = sessionMessage("start");
            QVERIFY(message != nullptr);
            xpc_dictionary_set_uint64(message, extra, 7);
            QVERIFY(!gate.parse(message, &parsed, &error));
            QCOMPARE(error, "xpc_control_request_fields_invalid");
            QCOMPARE(parsed.operation, XpcControlOperation::Invalid);
            xpc_release(message);
        }

        // Wrong or missing protocol version rejects the Start.
        xpc_object_t wrongVersion = sessionMessage("start");
        xpc_dictionary_set_uint64(wrongVersion, "protocol_version", 2);
        QVERIFY(!gate.parse(wrongVersion, &parsed, &error));
        QCOMPARE(error, "xpc_control_request_version_invalid");
        xpc_release(wrongVersion);
        xpc_object_t int64Version = sessionMessage("start");
        xpc_dictionary_set_int64(int64Version, "protocol_version", 1);
        QVERIFY(!gate.parse(int64Version, &parsed, &error));
        QCOMPARE(error, "xpc_control_request_version_invalid");
        xpc_release(int64Version);
        xpc_object_t noVersion = xpc_dictionary_create(nullptr, nullptr, 0);
        xpc_dictionary_set_string(noVersion, "operation", "start");
        QVERIFY(!gate.parse(noVersion, &parsed, &error));
        QCOMPARE(error, "xpc_control_request_fields_invalid");
        xpc_release(noVersion);
    }

    void syntheticModeAcceptsBoundedHeartbeatAndStopWithExactFieldCounts() {
        FakeSessionControlPolicy policy;
        XpcControlRequestGate gate("trusted", policy, XpcControlRequestGate::Mode::SyntheticLifecycle);
        XpcControlRequest parsed{XpcControlOperation::Status};
        std::string error;

        const std::string maximumId(48, 'A');
        for (const char *operation : {"heartbeat", "stop"}) {
            xpc_object_t message = sessionMessage(operation);
            QVERIFY(message != nullptr);
            xpc_dictionary_set_string(message, "session_id", maximumId.c_str());
            const std::vector<unsigned char> capability(32, 0x41);
            xpc_dictionary_set_data(message, "session_capability", capability.data(),
                                    capability.size());
            QVERIFY(gate.parse(message, &parsed, &error));
            QCOMPARE(parsed.operation,
                     operation[0] == 'h' ? XpcControlOperation::Heartbeat : XpcControlOperation::Stop);
            QCOMPARE(parsed.sessionId, maximumId);
            QCOMPARE(parsed.sessionCapability, capability);
            QCOMPARE(xpc_dictionary_get_count(message), xpcSessionControlRequestFieldCount);
            QVERIFY(parsed.sessionCapability.size() == xpcSessionControlCapabilityBytes);
            xpc_release(message);
        }

        // Any other key, or one key short, is rejected with the exact-count rule.
        xpc_object_t extraKey = heartbeatMessage("session-id", 32);
        xpc_dictionary_set_uint64(extraKey, "timestamp", 1);
        QVERIFY(!gate.parse(extraKey, &parsed, &error));
        QCOMPARE(error, "xpc_control_request_fields_invalid");
        xpc_release(extraKey);

        for (const char *dropped : {"protocol_version", "session_id", "session_capability"}) {
            xpc_object_t message = xpc_dictionary_create(nullptr, nullptr, 0);
            QVERIFY(message != nullptr);
            xpc_dictionary_set_string(message, "operation", "heartbeat");
            if (QString::fromLatin1(dropped) != QLatin1String("protocol_version"))
                xpc_dictionary_set_uint64(message, "protocol_version", 1);
            if (QString::fromLatin1(dropped) != QLatin1String("session_id"))
                xpc_dictionary_set_string(message, "session_id", "session-id");
            if (QString::fromLatin1(dropped) != QLatin1String("session_capability")) {
                const std::vector<unsigned char> capability(32, 0x5a);
                xpc_dictionary_set_data(message, "session_capability", capability.data(),
                                        capability.size());
            }
            QVERIFY(!gate.parse(message, &parsed, &error));
            QCOMPARE(parsed.operation, XpcControlOperation::Invalid);
            xpc_release(message);
        }
    }

    void syntheticModeRejectsWrongFieldTypes() {
        FakeSessionControlPolicy policy;
        XpcControlRequestGate gate("trusted", policy, XpcControlRequestGate::Mode::SyntheticLifecycle);
        XpcControlRequest parsed{XpcControlOperation::Status};
        std::string error;

        const auto reject = [&](xpc_object_t message, const char *expectedError) {
            QVERIFY(message != nullptr);
            QVERIFY(!gate.parse(message, &parsed, &error));
            QCOMPARE(error, expectedError);
            QCOMPARE(parsed.operation, XpcControlOperation::Invalid);
            QVERIFY(parsed.sessionCapability.empty());
            xpc_release(message);
        };

        xpc_object_t versionNotUint64 = heartbeatMessage("session-id", 32);
        xpc_dictionary_set_int64(versionNotUint64, "protocol_version", 1);
        reject(versionNotUint64, "xpc_control_request_version_invalid");

        xpc_object_t idAsData = heartbeatMessage("session-id", 32);
        xpc_dictionary_set_data(idAsData, "session_id", "session-id", 10);
        reject(idAsData, "xpc_control_request_session_id_invalid");

        xpc_object_t capabilityAsString = heartbeatMessage("session-id", 32);
        xpc_dictionary_set_string(capabilityAsString, "session_capability", "thirty-two-bytes");
        reject(capabilityAsString, "xpc_control_request_session_capability_invalid");

        xpc_object_t capabilityAsUint64 = heartbeatMessage("session-id", 32);
        xpc_dictionary_set_uint64(capabilityAsUint64, "session_capability", 32);
        reject(capabilityAsUint64, "xpc_control_request_session_capability_invalid");
    }

    void syntheticModeEnforcesCapabilityLengthBoundaries() {
        FakeSessionControlPolicy policy;
        XpcControlRequestGate gate("trusted", policy, XpcControlRequestGate::Mode::SyntheticLifecycle);
        XpcControlRequest parsed{XpcControlOperation::Status};
        std::string error;

        for (const size_t length : {size_t(0), size_t(31), size_t(33), size_t(64)}) {
            xpc_object_t message = heartbeatMessage("session-id", length);
            QVERIFY(message != nullptr);
            QVERIFY(!gate.parse(message, &parsed, &error));
            QCOMPARE(error, "xpc_control_request_session_capability_invalid");
            QCOMPARE(parsed.operation, XpcControlOperation::Invalid);
            QVERIFY(parsed.sessionCapability.empty());
            xpc_release(message);
        }
    }

    void syntheticModeEnforcesSessionIdLengthAndCharset() {
        FakeSessionControlPolicy policy;
        XpcControlRequestGate gate("trusted", policy, XpcControlRequestGate::Mode::SyntheticLifecycle);
        XpcControlRequest parsed{XpcControlOperation::Status};
        std::string error;

        const auto rejects = [&](const std::string &sessionId) {
            xpc_object_t message = heartbeatMessage(sessionId.c_str(), 32);
            QVERIFY(message != nullptr);
            QVERIFY(!gate.parse(message, &parsed, &error));
            QCOMPARE(error, "xpc_control_request_session_id_invalid");
            QCOMPARE(parsed.operation, XpcControlOperation::Invalid);
            xpc_release(message);
        };
        rejects("");                              // empty
        rejects(std::string(49, 'A'));            // one byte over the limit
        rejects("session id");                    // space is outside the charset
        rejects("session/id");                    // reserved path separator
        rejects(std::string("session\1id"));      // control byte
        rejects(std::string("session-id\xc3\xa9")); // non-ASCII byte sequence

        // The full charset is accepted at every length boundary.
        const std::vector<std::string> accepted = {
            std::string(1, 'a'), std::string(48, 'z'), std::string("A9_-1725cleanup"),
            std::string("session-id-01"),
        };
        for (const std::string &sessionId : accepted) {
            xpc_object_t message = heartbeatMessage(sessionId.c_str(), 32);
            QVERIFY(message != nullptr);
            QVERIFY2(gate.parse(message, &parsed, &error),
                     qPrintable(QString::fromStdString(error)));
            QCOMPARE(parsed.sessionId, sessionId);
            xpc_release(message);
        }
    }

    void authenticationPrecedesAnySessionFieldInspection() {
        FakeSessionControlPolicy policy;
        policy.result = false;
        policy.policyError = "signature_requirement_rejected";
        XpcControlRequestGate gate("trusted", policy, XpcControlRequestGate::Mode::SyntheticLifecycle);
        XpcControlRequest parsed{XpcControlOperation::Status};
        std::string error;

        xpc_object_t heartbeat = heartbeatMessage("session-id", 32);
        QVERIFY(heartbeat != nullptr);
        QVERIFY(!gate.parse(heartbeat, &parsed, &error));
        QCOMPARE(policy.calls, 1);
        QCOMPARE(policy.seenMessage, heartbeat);
        QCOMPARE(error, "signature_requirement_rejected");
        QCOMPARE(parsed.operation, XpcControlOperation::Invalid);
        QVERIFY(parsed.sessionCapability.empty());
        // A sender that fails the signature check is rejected without any reply body inspection
        // side effects: the invalid-requirement gate fires before the policy itself.
        xpc_object_t start = sessionMessage("start");
        QVERIFY(start != nullptr);
        XpcControlRequestGate invalidRequirement("",
                                                 policy, XpcControlRequestGate::Mode::SyntheticLifecycle);
        std::string invalidError = "stale";
        QVERIFY(!invalidRequirement.parse(start, &parsed, &invalidError));
        QCOMPARE(invalidError, "xpc_peer_requirement_invalid");
        xpc_release(start);
        xpc_release(heartbeat);
    }
};

} // namespace interceptor

QTEST_GUILESS_MAIN(interceptor::M6XpcSessionControlGrammarTests)
#include "M6XpcSessionControlGrammarTests.moc"
