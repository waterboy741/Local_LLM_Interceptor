#include "network/MachServicePeerAuthenticator.hpp"

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
        if (throws)
            throw 1;
        return result;
    }

    int calls = 0;
    xpc_object_t seenMessage = nullptr;
    std::string seenRequirement;
    std::string policyError;
    bool result = true;
    bool throws = false;
};

class M6MachServicePeerAuthenticatorTests final : public QObject {
    Q_OBJECT

  private slots:
    void rejectsNullAndNonDictionaryMessagesBeforeCallingPolicy() {
        FakeCodeSignaturePolicy policy;
        std::string error = "stale";

        QVERIFY(!authenticateXpcPeerMessage(nullptr, "trusted requirement", policy, &error));
        QCOMPARE(error, "xpc_peer_message_invalid");
        QCOMPARE(policy.calls, 0);

        xpc_object_t stringMessage = xpc_string_create("not a dictionary");
        QVERIFY(stringMessage != nullptr);
        QVERIFY(!authenticateXpcPeerMessage(stringMessage, "trusted requirement", policy, &error));
        QCOMPARE(error, "xpc_peer_message_invalid");
        QCOMPARE(policy.calls, 0);
        xpc_release(stringMessage);
    }

    void rejectsMalformedOrOversizeRequirementsBeforeCallingPolicy() {
        xpc_object_t message = xpc_dictionary_create(nullptr, nullptr, 0);
        QVERIFY(message != nullptr);
        FakeCodeSignaturePolicy policy;
        std::string error;

        const std::string oversized(1025, 'x');
        const std::string embeddedNul("valid\0suffix", 12);
        const QList<std::string> invalidRequirements = {
            std::string(),
            oversized,
            embeddedNul,
        };
        for (const std::string &requirement : invalidRequirements) {
            QVERIFY(!authenticateXpcPeerMessage(message, requirement, policy, &error));
            QCOMPARE(error, "xpc_peer_requirement_invalid");
            QCOMPARE(policy.calls, 0);
        }
        xpc_release(message);
    }

    void bindsAuthenticationToExplicitTrustedRequirement() {
        xpc_object_t message = xpc_dictionary_create(nullptr, nullptr, 0);
        QVERIFY(message != nullptr);
        xpc_dictionary_set_string(message, "requirement", "attacker-controlled-value");
        const std::string trustedRequirement =
            "anchor apple generic and identifier \"edu.example.llm-interceptor.helper\"";
        FakeCodeSignaturePolicy policy;
        std::string error = "stale";

        QVERIFY(authenticateXpcPeerMessage(message, trustedRequirement, policy, &error));
        QCOMPARE(error, std::string());
        QCOMPARE(policy.calls, 1);
        QCOMPARE(policy.seenMessage, message);
        QCOMPARE(policy.seenRequirement, trustedRequirement);
        xpc_release(message);
    }

    void reportsPolicyRejectionAndSuppliesFallbackForSilentFailure() {
        xpc_object_t message = xpc_dictionary_create(nullptr, nullptr, 0);
        QVERIFY(message != nullptr);
        FakeCodeSignaturePolicy policy;
        policy.result = false;
        policy.policyError = "signature_requirement_rejected";
        std::string error;

        QVERIFY(!authenticateXpcPeerMessage(message, "trusted", policy, &error));
        QCOMPARE(error, "signature_requirement_rejected");

        policy.policyError.clear();
        QVERIFY(!authenticateXpcPeerMessage(message, "trusted", policy, &error));
        QCOMPARE(error, "xpc_peer_code_requirement_failed");
        xpc_release(message);
    }

    void failsClosedWhenPolicyThrows() {
        xpc_object_t message = xpc_dictionary_create(nullptr, nullptr, 0);
        QVERIFY(message != nullptr);
        FakeCodeSignaturePolicy policy;
        policy.throws = true;
        std::string error;

        QVERIFY(!authenticateXpcPeerMessage(message, "trusted", policy, &error));
        QCOMPARE(error, "xpc_peer_code_requirement_failed");
        QCOMPARE(policy.calls, 1);
        xpc_release(message);
    }
};

} // namespace interceptor

QTEST_GUILESS_MAIN(interceptor::M6MachServicePeerAuthenticatorTests)
#include "M6MachServicePeerAuthenticatorTests.moc"
