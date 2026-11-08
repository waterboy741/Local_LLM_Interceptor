#include "network/MachServicePeerAuthenticator.hpp"

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
        if (throws)
            throw 1;
        return result;
    }

    int calls = 0;
    xpc_object_t seenMessage = nullptr;
    QByteArray seenRequirement;
    QString policyError;
    bool result = true;
    bool throws = false;
};

class M6MachServicePeerAuthenticatorTests final : public QObject {
    Q_OBJECT

  private slots:
    void rejectsNullAndNonDictionaryMessagesBeforeCallingPolicy() {
        FakeCodeSignaturePolicy policy;
        QString error = QStringLiteral("stale");

        QVERIFY(!authenticateXpcPeerMessage(nullptr, QByteArrayLiteral("trusted requirement"),
                                            policy, &error));
        QCOMPARE(error, QStringLiteral("xpc_peer_message_invalid"));
        QCOMPARE(policy.calls, 0);

        xpc_object_t stringMessage = xpc_string_create("not a dictionary");
        QVERIFY(stringMessage != nullptr);
        QVERIFY(!authenticateXpcPeerMessage(stringMessage, QByteArrayLiteral("trusted requirement"),
                                            policy, &error));
        QCOMPARE(error, QStringLiteral("xpc_peer_message_invalid"));
        QCOMPARE(policy.calls, 0);
        xpc_release(stringMessage);
    }

    void rejectsMalformedOrOversizeRequirementsBeforeCallingPolicy() {
        xpc_object_t message = xpc_dictionary_create(nullptr, nullptr, 0);
        QVERIFY(message != nullptr);
        FakeCodeSignaturePolicy policy;
        QString error;

        const QByteArray oversized(1025, 'x');
        const QByteArray embeddedNul("valid\0suffix", 12);
        const QList<QByteArray> invalidRequirements = {
            QByteArray(),
            oversized,
            embeddedNul,
        };
        for (const QByteArray &requirement : invalidRequirements) {
            QVERIFY(!authenticateXpcPeerMessage(message, requirement, policy, &error));
            QCOMPARE(error, QStringLiteral("xpc_peer_requirement_invalid"));
            QCOMPARE(policy.calls, 0);
        }
        xpc_release(message);
    }

    void bindsAuthenticationToExplicitTrustedRequirement() {
        xpc_object_t message = xpc_dictionary_create(nullptr, nullptr, 0);
        QVERIFY(message != nullptr);
        xpc_dictionary_set_string(message, "requirement", "attacker-controlled-value");
        const QByteArray trustedRequirement = QByteArrayLiteral(
            "anchor apple generic and identifier \"edu.example.llm-interceptor.helper\"");
        FakeCodeSignaturePolicy policy;
        QString error = QStringLiteral("stale");

        QVERIFY(authenticateXpcPeerMessage(message, trustedRequirement, policy, &error));
        QCOMPARE(error, QString());
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
        policy.policyError = QStringLiteral("signature_requirement_rejected");
        QString error;

        QVERIFY(!authenticateXpcPeerMessage(message, QByteArrayLiteral("trusted"), policy, &error));
        QCOMPARE(error, QStringLiteral("signature_requirement_rejected"));

        policy.policyError.clear();
        QVERIFY(!authenticateXpcPeerMessage(message, QByteArrayLiteral("trusted"), policy, &error));
        QCOMPARE(error, QStringLiteral("xpc_peer_code_requirement_failed"));
        xpc_release(message);
    }

    void failsClosedWhenPolicyThrows() {
        xpc_object_t message = xpc_dictionary_create(nullptr, nullptr, 0);
        QVERIFY(message != nullptr);
        FakeCodeSignaturePolicy policy;
        policy.throws = true;
        QString error;

        QVERIFY(!authenticateXpcPeerMessage(message, QByteArrayLiteral("trusted"), policy, &error));
        QCOMPARE(error, QStringLiteral("xpc_peer_code_requirement_failed"));
        QCOMPARE(policy.calls, 1);
        xpc_release(message);
    }
};

} // namespace interceptor

QTEST_GUILESS_MAIN(interceptor::M6MachServicePeerAuthenticatorTests)
#include "M6MachServicePeerAuthenticatorTests.moc"
