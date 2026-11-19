#include "network/XpcSessionControlReply.hpp"

#include <QtTest>

#include <string>
#include <vector>

#include <xpc/xpc.h>

namespace interceptor {

class M6XpcSessionControlReplyTests final : public QObject {
    Q_OBJECT

  private:
    static XpcSessionControlReply sampleReply() {
        XpcSessionControlReply reply;
        reply.ok = true;
        reply.state = xpcSessionControlStateActive;
        reply.sessionId = "bounded-session-id";
        reply.sessionCapability = std::vector<unsigned char>(32, 0x3c);
        return reply;
    }
    static xpc_object_t value(xpc_object_t dictionary, const char *key) {
        return xpc_dictionary_get_value(dictionary, key);
    }

  private slots:
    void stateVocabularyStaysWithinTheBoundedReplyWidth() {
        const QList<std::string_view> states = {
            xpcSessionControlStateUninitialized, xpcSessionControlStateInitFailed,
            xpcSessionControlStateRecoveryPending, xpcSessionControlStateReady,
            xpcSessionControlStateActive, xpcSessionControlStateCleanupPending,
            xpcSessionControlStateStopped,
        };
        for (const std::string_view state : states) {
            QVERIFY(!state.empty());
            QVERIFY(state.size() <= xpcSessionControlMaximumStateBytes);
        }
        QVERIFY(xpcSessionControlProtocolVersion == std::uint64_t(1));
        QVERIFY(xpcSessionControlMaximumStateBytes == std::size_t(16));
        QVERIFY(xpcSessionControlMaximumReasonBytes == std::size_t(64));
        QVERIFY(xpcSessionControlCapabilityBytes == std::size_t(32));
    }

    void encodesAnAcceptedStartReplyWithExactlyTheBoundedFields() {
        auto reply = sampleReply();
        xpc_object_t payload = encodeXpcSessionControlReply(reply);
        QVERIFY(payload != nullptr);
        QCOMPARE(xpc_dictionary_get_count(payload), std::size_t(5));
        QCOMPARE(xpc_dictionary_get_bool(payload, "ok"), true);
        QCOMPARE(xpc_dictionary_get_uint64(payload, "protocol_version"),
                  xpcSessionControlProtocolVersion);
        {
            xpc_object_t state = value(payload, "state");
            QVERIFY(state != nullptr);
            QCOMPARE(xpc_get_type(state), XPC_TYPE_STRING);
            QCOMPARE(xpc_string_get_string_ptr(state), "active");
        }
        {
            xpc_object_t id = value(payload, "session_id");
            QVERIFY(id != nullptr);
            QCOMPARE(xpc_string_get_string_ptr(id), "bounded-session-id");
        }
        {
            xpc_object_t capability = value(payload, "session_capability");
            QVERIFY(capability != nullptr);
            QCOMPARE(xpc_get_type(capability), XPC_TYPE_DATA);
            QCOMPARE(xpc_data_get_length(capability), xpcSessionControlCapabilityBytes);
            const auto *bytes =
                static_cast<const unsigned char *>(xpc_data_get_bytes_ptr(capability));
            QVERIFY(bytes != nullptr);
            bool allMatch = true;
            for (std::size_t i = 0; i < xpcSessionControlCapabilityBytes; ++i)
                allMatch = allMatch && bytes[i] == reply.sessionCapability[i];
            QVERIFY(allMatch);
        }
        QVERIFY(value(payload, "reason") == nullptr); // no reason on an accepted reply
        xpc_release(payload);
    }

    void encodesARejectedReplyWithReasonAndNoSessionAuthority() {
        XpcSessionControlReply reply;
        reply.ok = false;
        reply.state = xpcSessionControlStateCleanupPending;
        reply.reason = "session_binding_mismatch";
        xpc_object_t payload = encodeXpcSessionControlReply(reply);
        QVERIFY(payload != nullptr);
        QCOMPARE(xpc_dictionary_get_count(payload), std::size_t(4));
        QCOMPARE(xpc_dictionary_get_bool(payload, "ok"), false);
        QVERIFY(xpc_get_type(value(payload, "state")) == XPC_TYPE_STRING);
        QCOMPARE(xpc_string_get_string_ptr(value(payload, "state")), "cleanup_pending");
        QVERIFY(value(payload, "session_id") == nullptr);
        QVERIFY(value(payload, "session_capability") == nullptr);
        QVERIFY(xpc_get_type(value(payload, "reason")) == XPC_TYPE_STRING);
        xpc_release(payload);
    }

    void enforcesEveryDocumentedBoundBeforeEncoding() {
        const auto rejects = [](XpcSessionControlReply reply) {
            xpc_object_t payload = encodeXpcSessionControlReply(reply);
            QVERIFY(payload == nullptr);
        };
        rejects([] { auto r = sampleReply();
                     r.state.clear();
                     return r; }());
        rejects([] { auto r = sampleReply();
                     r.state.assign(17, 's');
                     return r; }());
        rejects([] { auto r = sampleReply();
                     r.sessionId = std::string(49, 'i');
                     return r; }());
        rejects([] { auto r = sampleReply();
                     r.reason = std::string(65, 'r');
                     return r; }());
        rejects([] { auto r = sampleReply();
                     r.sessionCapability = std::vector<unsigned char>(31, 1);
                     return r; }());
        rejects([] { auto r = sampleReply();
                     r.sessionCapability = std::vector<unsigned char>(33, 1);
                     return r; }());
        rejects([] { auto r = sampleReply();
                     r.protocolVersion = 2;
                     return r; }());
    }

    void acceptsEveryBoundaryLength() {
        XpcSessionControlReply bounded = sampleReply();
        bounded.state = xpcSessionControlStateRecoveryPending; // exactly 16 bytes
        QVERIFY(bounded.state.size() == std::size_t(16));
        bounded.reason = std::string(64, 'r');
        bounded.sessionId = std::string(48, 'i');
        xpc_object_t payload = encodeXpcSessionControlReply(bounded);
        QVERIFY(payload != nullptr);
        QCOMPARE(xpc_dictionary_get_count(payload), std::size_t(6));
        // A boundary-length reason is accepted alongside capability fields; the encoder
        // enforces shapes, the lifecycle runtime owns which reply carries which field.
        bounded.ok = false;
        xpc_object_t rejectedPayload = encodeXpcSessionControlReply(bounded);
        QVERIFY(rejectedPayload != nullptr);
        QVERIFY(value(rejectedPayload, "session_capability") != nullptr);
        xpc_release(rejectedPayload);
        xpc_release(payload);
    }

    void wipeReleasesTheCapabilityCopyAndKeepsNonSecretFields() {
        XpcSessionControlReply reply = sampleReply();
        std::vector<unsigned char> retainedBeforeWipe = reply.sessionCapability;
        const std::string retainedSessionId = reply.sessionId;
        const std::string retainedState = reply.state;
        wipeXpcSessionControlReply(reply);
        // The capability authority is released with the reply and cannot be re-used by accident.
        QVERIFY(reply.sessionCapability.empty());
        QVERIFY(retainedBeforeWipe.size() == xpcSessionControlCapabilityBytes);
        // Non-secret fields survive the wipe.
        QCOMPARE(reply.sessionId, retainedSessionId);
        QCOMPARE(reply.state, retainedState);
        QVERIFY(reply.sessionId.size() <= xpcSessionControlMaximumSessionIdBytes);

        // A fresh capability can be attached to the same reply object and encodes again.
        reply.sessionCapability = std::vector<unsigned char>(32, 0x7f);
        xpc_object_t payload = encodeXpcSessionControlReply(reply);
        QVERIFY(payload != nullptr);
        xpc_release(payload);

        // Wiping an already-empty capability is a safe no-op.
        XpcSessionControlReply empty;
        wipeXpcSessionControlReply(empty);
        QVERIFY(empty.sessionCapability.empty());
    }
};

} // namespace interceptor

QTEST_GUILESS_MAIN(interceptor::M6XpcSessionControlReplyTests)
#include "M6XpcSessionControlReplyTests.moc"
