#include "network/XpcControlRequestGate.hpp"

#include <QtTest>

#include <string>
#include <vector>

#include <xpc/xpc.h>

namespace interceptor {

class FakeInstalledGatePolicy final : public XpcPeerCodeSignaturePolicy {
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

class M6XpcInstalledStartGrammarTests final : public QObject {
    Q_OBJECT

  private:
    static xpc_object_t installedStartMessage() {
        xpc_object_t message = xpc_dictionary_create(nullptr, nullptr, 0);
        if (message) {
            xpc_dictionary_set_string(message, "operation", "start");
            xpc_dictionary_set_uint64(message, "protocol_version", 1);
            xpc_dictionary_set_string(message, "interface", "en0");
            xpc_dictionary_set_string(message, "client_ipv4", "192.0.2.10");
            xpc_dictionary_set_string(message, "upstream_ipv4", "192.0.2.30");
            xpc_dictionary_set_string(message, "listen_address", "192.0.2.20");
            xpc_dictionary_set_uint64(message, "upstream_port", 18081);
            xpc_dictionary_set_uint64(message, "listener_port", 11434);
            const std::vector<unsigned char> secret(32, 0x41);
            xpc_dictionary_set_data(message, "probe_secret", secret.data(), secret.size());
        }
        return message;
    }
    static XpcControlRequest parseWith(XpcControlRequestGate::Mode mode,
                                       xpc_object_t message, std::string *error) {
        FakeInstalledGatePolicy policy;
        XpcControlRequestGate gate("trusted", policy, mode);
        XpcControlRequest parsed{XpcControlOperation::Status};
        gate.parse(message, &parsed, error);
        return parsed;
    }

  private slots:
    void readOnlyHoldoutRejectsTheInstalledGrammarUnchanged() {
        FakeInstalledGatePolicy policy;
        XpcControlRequestGate gate("trusted", policy);
        XpcControlRequest parsed{XpcControlOperation::Status};
        std::string error;

        xpc_object_t start = installedStartMessage();
        QVERIFY(start != nullptr);
        QVERIFY(!gate.parse(start, &parsed, &error));
        QCOMPARE(error, "xpc_control_request_fields_invalid");
        QCOMPARE(parsed.operation, XpcControlOperation::Invalid);
        QVERIFY(parsed.probeSecret.empty());
        xpc_release(start);

        // The shared 4-key heartbeat/stop grammar also stays rejected in ReadOnly mode.
        xpc_object_t heartbeat = xpc_dictionary_create(nullptr, nullptr, 0);
        xpc_dictionary_set_string(heartbeat, "operation", "heartbeat");
        xpc_dictionary_set_uint64(heartbeat, "protocol_version", 1);
        xpc_dictionary_set_string(heartbeat, "session_id", "session-id");
        const std::vector<unsigned char> capability(32, 1);
        xpc_dictionary_set_data(heartbeat, "session_capability", capability.data(),
                                capability.size());
        QVERIFY(!gate.parse(heartbeat, &parsed, &error));
        QCOMPARE(error, "xpc_control_request_fields_invalid");
        xpc_release(heartbeat);

        // Probe/status keep their byte-identical single-key shape.
        xpc_object_t status = xpc_dictionary_create(nullptr, nullptr, 0);
        xpc_dictionary_set_string(status, "operation", "status");
        QVERIFY(gate.parse(status, &parsed, &error));
        QCOMPARE(parsed.operation, XpcControlOperation::Status);
        xpc_release(status);
    }

    void installedModeAcceptsTheExactNineKeyStart() {
        FakeInstalledGatePolicy policy;
        XpcControlRequestGate gate("trusted", policy, XpcControlRequestGate::Mode::InstalledLifecycle);
        XpcControlRequest parsed{XpcControlOperation::Status};
        std::string error;

        xpc_object_t message = installedStartMessage();
        QVERIFY(message != nullptr);
        QCOMPARE(xpc_dictionary_get_count(message), xpcInstalledStartRequestFieldCount);
        QVERIFY(gate.parse(message, &parsed, &error));
        QCOMPARE(parsed.operation, XpcControlOperation::Start);
        QCOMPARE(error, std::string());
        QCOMPARE(parsed.sessionInterface, std::string("en0"));
        QCOMPARE(parsed.sessionClientIpv4, std::string("192.0.2.10"));
        QCOMPARE(parsed.sessionUpstreamIpv4, std::string("192.0.2.30"));
        QCOMPARE(parsed.sessionListenAddress, std::string("192.0.2.20"));
        QCOMPARE(parsed.sessionUpstreamPort, std::uint64_t(18081));
        QCOMPARE(parsed.sessionListenerPort, std::uint64_t(11434));
        QCOMPARE(parsed.probeSecret.size(), std::size_t(xpcSessionControlCapabilityBytes));
        QVERIFY(parsed.sessionId.empty());
        QVERIFY(parsed.sessionCapability.empty());
        xpc_release(message);

        // No snapshot, anchor, path, timestamp, or arbitrary payload key may ride along.
        for (const char *extra : {"timestamp", "snapshot", "anchor", "session_id",
                                  "session_capability", "path", "body"}) {
            xpc_object_t extended = installedStartMessage();
            QVERIFY(extended != nullptr);
            xpc_object_t value = xpc_string_create("x");
            xpc_dictionary_set_value(extended, extra, value);
            xpc_release(value);
            QVERIFY(!gate.parse(extended, &parsed, &error));
            QCOMPARE(error, "xpc_control_request_fields_invalid");
            QCOMPARE(parsed.operation, XpcControlOperation::Invalid);
            QVERIFY(parsed.probeSecret.empty());
            xpc_release(extended);
        }

        // Any one dropped key rejects the whole request.
        const QList<QByteArray> keys = {"operation",  "protocol_version", "interface",
                                         "client_ipv4", "upstream_ipv4",   "listen_address",
                                         "upstream_port", "listener_port",  "probe_secret"};
        for (const QByteArray &key : keys) {
            xpc_object_t message2 = xpc_dictionary_create(nullptr, nullptr, 0);
            xpc_object_t source = installedStartMessage();
            xpc_dictionary_apply(source, ^bool(const char *name, xpc_object_t value) {
              if (std::string_view(name) != std::string_view(key.constData()))
                  xpc_dictionary_set_value(message2, name, value);
              return true;
            });
            xpc_release(source);
            QVERIFY2(!gate.parse(message2, &parsed, &error), key.constData());
            QCOMPARE(parsed.operation, XpcControlOperation::Invalid);
            xpc_release(message2);
        }
    }

    void installedModeRejectsWrongVersionsTypesAndBounds() {
        FakeInstalledGatePolicy policy;
        XpcControlRequestGate gate("trusted", policy,
                                   XpcControlRequestGate::Mode::InstalledLifecycle);
        XpcControlRequest parsed{XpcControlOperation::Status};
        std::string error;

        // protocol_version wrong value or wrong type.
        for (const auto mutate : std::vector<std::function<void(xpc_object_t)>>{
                 [](xpc_object_t m) { xpc_dictionary_set_uint64(m, "protocol_version", 2); },
                 [](xpc_object_t m) { xpc_dictionary_set_int64(m, "protocol_version", 1); },
                 [](xpc_object_t m) { xpc_dictionary_set_string(m, "protocol_version", "1"); },
             }) {
            xpc_object_t message = installedStartMessage();
            mutate(message);
            QVERIFY(!gate.parse(message, &parsed, &error));
            QCOMPARE(error, "xpc_control_request_version_invalid");
            xpc_release(message);
        }

        // Wrong types on the tuple string fields.
        for (const char *key : {"interface", "client_ipv4", "upstream_ipv4", "listen_address"}) {
            xpc_object_t message = installedStartMessage();
            xpc_dictionary_set_uint64(message, key, 7);
            QVERIFY(!gate.parse(message, &parsed, &error));
            QCOMPARE(error, "xpc_control_request_session_start_invalid");
            xpc_release(message);
        }
        for (const char *key : {"upstream_port", "listener_port"}) {
            xpc_object_t message = installedStartMessage();
            xpc_dictionary_set_string(message, key, "18081");
            QVERIFY(!gate.parse(message, &parsed, &error));
            QCOMPARE(error, "xpc_control_request_session_start_invalid");
            xpc_release(message);
        }
        {
            // probe_secret as a string instead of data rejects.
            xpc_object_t message = installedStartMessage();
            xpc_dictionary_set_string(message, "probe_secret", "not-a-secret");
            QVERIFY(!gate.parse(message, &parsed, &error));
            QCOMPARE(error, "xpc_control_request_session_start_invalid");
            xpc_release(message);
        }

        // Port bounds: zero, 65536 and above are invalid; valid bounds accepted.
        for (const uint64_t invalid : {0ULL, 65536ULL, 4294967296ULL}) {
            xpc_object_t message = installedStartMessage();
            xpc_dictionary_set_uint64(message, "upstream_port", invalid);
            QVERIFY(!gate.parse(message, &parsed, &error));
            QCOMPARE(error, "xpc_control_request_session_start_invalid");
            xpc_release(message);
        }
        xpc_object_t boundedPorts = installedStartMessage();
        xpc_dictionary_set_uint64(boundedPorts, "upstream_port", 65535);
        xpc_dictionary_set_uint64(boundedPorts, "listener_port", 1);
        QVERIFY(gate.parse(boundedPorts, &parsed, &error));
        QCOMPARE(parsed.sessionUpstreamPort, std::uint64_t(65535));
        xpc_release(boundedPorts);

        // IPv4 bounds: malformed dotted quads rejected.
        for (const QByteArray malformed : {"999.0.2.10", "1.2.3", "01.2.3.4", "1.2.3.4.5",
                                            "a.b.c.d", "1.2.3.256", "", "1..2.3"}) {
            xpc_object_t message = installedStartMessage();
            xpc_dictionary_set_string(message, "client_ipv4", malformed.constData());
            QVERIFY2(!gate.parse(message, &parsed, &error), malformed.constData());
            QCOMPARE(error, "xpc_control_request_session_start_invalid");
            xpc_release(message);
        }

        // listen_address must differ from both peers.
        {
            xpc_object_t message = installedStartMessage();
            xpc_dictionary_set_string(message, "listen_address", "192.0.2.10");
            QVERIFY(!gate.parse(message, &parsed, &error));
            QCOMPARE(error, "xpc_control_request_session_start_invalid");
            xpc_release(message);
        }
        {
            xpc_object_t message = installedStartMessage();
            xpc_dictionary_set_string(message, "listen_address", "192.0.2.30");
            QVERIFY(!gate.parse(message, &parsed, &error));
            QCOMPARE(error, "xpc_control_request_session_start_invalid");
            xpc_release(message);
        }

        // Interface name rules: bounded, charset-safe, alnum first character.
        const QList<QByteArray> invalidInterfaces = {
            QByteArrayLiteral(""), QByteArrayLiteral("_iface"),
            QByteArrayLiteral("has space"), QByteArrayLiteral("has/slash"), QByteArray(33, 'a'),
        };
        for (const QByteArray &invalid : invalidInterfaces) {
            xpc_object_t message = installedStartMessage();
            xpc_dictionary_set_string(message, "interface", invalid.constData());
            QVERIFY2(!gate.parse(message, &parsed, &error), invalid.constData());
            QCOMPARE(error, "xpc_control_request_session_start_invalid");
            xpc_release(message);
        }
        xpc_object_t validInterface = installedStartMessage();
        xpc_dictionary_set_string(validInterface, "interface", "bridge100");
        QVERIFY(gate.parse(validInterface, &parsed, &error));
        QCOMPARE(parsed.sessionInterface, std::string("bridge100"));
        xpc_release(validInterface);

        // probe_secret: wrong length or wrong type rejects; missing rejects on field count.
        for (const size_t length : {0, 16, 31, 33, 64}) {
            xpc_object_t message = installedStartMessage();
            const std::vector<unsigned char> secret(length, 0x41);
            xpc_dictionary_set_data(message, "probe_secret", secret.data(), secret.size());
            QVERIFY(!gate.parse(message, &parsed, &error));
            QCOMPARE(error, "xpc_control_request_session_start_invalid");
            QVERIFY(parsed.probeSecret.empty());
            xpc_release(message);
        }
        {
            xpc_object_t message = installedStartMessage();
            xpc_dictionary_set_string(message, "probe_secret", "x");
            QVERIFY(!gate.parse(message, &parsed, &error));
            QCOMPARE(error, "xpc_control_request_session_start_invalid");
            xpc_release(message);
        }
    }

    void installedModeSharesTheFourKeyHeartbeatStopGrammar() {
        FakeInstalledGatePolicy policy;
        XpcControlRequestGate gate("trusted", policy, XpcControlRequestGate::Mode::InstalledLifecycle);
        XpcControlRequest parsed{XpcControlOperation::Status};
        std::string error;
        const std::string maximumId(48, 'a');

        for (const char *operation : {"heartbeat", "stop"}) {
            xpc_object_t message = xpc_dictionary_create(nullptr, nullptr, 0);
            xpc_dictionary_set_string(message, "operation", operation);
            xpc_dictionary_set_uint64(message, "protocol_version", 1);
            xpc_dictionary_set_string(message, "session_id", maximumId.c_str());
            const std::vector<unsigned char> capability(32, 7);
            xpc_dictionary_set_data(message, "session_capability", capability.data(),
                                    capability.size());
            QVERIFY(gate.parse(message, &parsed, &error));
            QCOMPARE(parsed.operation,
                     operation[0] == 'h' ? XpcControlOperation::Heartbeat : XpcControlOperation::Stop);
            QCOMPARE(parsed.sessionId, maximumId);
            QCOMPARE(parsed.sessionCapability, capability);
            QVERIFY(parsed.probeSecret.empty());
            xpc_release(message);
        }

        // The 2-key synthetic start shape is not the installed start shape.
        xpc_object_t syntheticStart = xpc_dictionary_create(nullptr, nullptr, 0);
        xpc_dictionary_set_string(syntheticStart, "operation", "start");
        xpc_dictionary_set_uint64(syntheticStart, "protocol_version", 1);
        QVERIFY(!gate.parse(syntheticStart, &parsed, &error));
        QCOMPARE(error, "xpc_control_request_fields_invalid");
        xpc_release(syntheticStart);
    }

    void authenticationPrecedesInstalledStartFieldInspection() {
        FakeInstalledGatePolicy policy;
        policy.result = false;
        policy.policyError = "signature_requirement_rejected";
        XpcControlRequestGate gate("trusted", policy, XpcControlRequestGate::Mode::InstalledLifecycle);
        XpcControlRequest parsed{XpcControlOperation::Status};
        std::string error;

        xpc_object_t message = installedStartMessage();
        QVERIFY(message != nullptr);
        QVERIFY(!gate.parse(message, &parsed, &error));
        QCOMPARE(policy.calls, 1);
        QCOMPARE(policy.seenMessage, message);
        QCOMPARE(error, "signature_requirement_rejected");
        QCOMPARE(parsed.operation, XpcControlOperation::Invalid);
        QVERIFY(parsed.probeSecret.empty());
        xpc_release(message);

        // An invalid trusted requirement rejects before the policy ever runs.
        XpcControlRequestGate invalidRequirementGate(
            "", policy, XpcControlRequestGate::Mode::InstalledLifecycle);
        xpc_object_t second = installedStartMessage();
        std::string secondError = "stale";
        QVERIFY(!invalidRequirementGate.parse(second, &parsed, &secondError));
        QCOMPARE(secondError, "xpc_peer_requirement_invalid");
        QCOMPARE(policy.calls, 1); // unchanged: no policy call for the invalid requirement
        xpc_release(second);
    }
};

} // namespace interceptor

QTEST_GUILESS_MAIN(interceptor::M6XpcInstalledStartGrammarTests)
#include "M6XpcInstalledStartGrammarTests.moc"
