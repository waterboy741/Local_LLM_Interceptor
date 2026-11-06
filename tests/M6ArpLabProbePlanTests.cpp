#include "network/ArpCodec.hpp"
#include "network/ArpLabProbePlan.hpp"

#include <QtTest>

using namespace interceptor;

namespace {
ArpLabProbeInputs validInputs() {
    ArpLabProbeInputs inputs;
    inputs.selectedInterfaceName = "en0";
    inputs.observedInterfaceName = "en0";
    inputs.researchIp = "192.0.2.20";
    inputs.clientIp = "192.0.2.10";
    inputs.serverIp = "192.0.2.30";
    inputs.researchMac = "02:00:00:00:00:20";
    inputs.clientMac = "02:00:00:00:00:10";
    inputs.serverMac = "02:00:00:00:00:30";
    inputs.prefixLength = 24;
    return inputs;
}

QByteArray mac(QString text) { return QByteArray::fromHex(text.remove(':').toLatin1()); }

QByteArray validUnplannedReply() {
    return ArpCodec::encode({mac("02:00:00:00:00:20"), mac("02:00:00:00:00:44"),
                             mac("02:00:00:00:00:20"), mac("02:00:00:00:00:44"), "192.0.2.44",
                             "192.0.2.20", 2});
}
} // namespace

class M6ArpLabProbePlanTests : public QObject {
    Q_OBJECT
  private slots:
    void createsOneClientRedirectAndRestorationPair() {
        QString error;
        const auto plan = ArpLabProbePlan::create(validInputs(), &error);
        QVERIFY2(plan.has_value(), qPrintable(error));
        QCOMPARE(plan->interfaceName(), QString("en0"));
        QCOMPARE(plan->allowedFrames().size(), 2);
        QCOMPARE(plan->redirectionFrame().size(), 60);
        QCOMPARE(plan->restorationFrame().size(), 60);

        const auto redirect = ArpCodec::parse(plan->redirectionFrame());
        const auto restoration = ArpCodec::parse(plan->restorationFrame());
        QVERIFY(redirect.has_value());
        QVERIFY(restoration.has_value());
        QCOMPARE(redirect->operation, quint16(2));
        QCOMPARE(redirect->ethernetSource, mac("02:00:00:00:00:20"));
        QCOMPARE(redirect->ethernetDestination, mac("02:00:00:00:00:10"));
        QCOMPARE(redirect->senderMac, mac("02:00:00:00:00:20"));
        QCOMPARE(redirect->senderIp, QString("192.0.2.30"));
        QCOMPARE(redirect->targetMac, mac("02:00:00:00:00:10"));
        QCOMPARE(redirect->targetIp, QString("192.0.2.10"));
        QCOMPARE(restoration->operation, quint16(2));
        QCOMPARE(restoration->ethernetSource, mac("02:00:00:00:00:20"));
        QCOMPARE(restoration->ethernetDestination, mac("02:00:00:00:00:10"));
        QCOMPARE(restoration->senderMac, mac("02:00:00:00:00:30"));
        QCOMPARE(restoration->senderIp, QString("192.0.2.30"));
        QCOMPARE(restoration->targetMac, mac("02:00:00:00:00:10"));
        QCOMPARE(restoration->targetIp, QString("192.0.2.10"));
        QCOMPARE(plan->allowedFrames(),
                 QList<QByteArray>({plan->redirectionFrame(), plan->restorationFrame()}));
    }

    void rejectsMalformedAndMismatchedInterfaces() {
        auto inputs = validInputs();
        inputs.selectedInterfaceName = "../en0";
        QVERIFY(!ArpLabProbePlan::create(inputs));
        inputs = validInputs();
        inputs.observedInterfaceName = "en1";
        QVERIFY(!ArpLabProbePlan::create(inputs));
        inputs = validInputs();
        inputs.selectedInterfaceName.clear();
        QVERIFY(!ArpLabProbePlan::create(inputs));
    }

    void rejectsMalformedOffSubnetBroadcastAndMulticastIps() {
        auto inputs = validInputs();
        inputs.researchIp = "not-an-ip";
        QVERIFY(!ArpLabProbePlan::create(inputs));

        inputs = validInputs();
        inputs.serverIp = "198.51.100.30";
        QVERIFY(!ArpLabProbePlan::create(inputs));

        inputs = validInputs();
        inputs.serverIp = "192.0.2.255";
        QVERIFY(!ArpLabProbePlan::create(inputs));

        inputs = validInputs();
        inputs.clientIp = "192.0.2.0";
        QVERIFY(!ArpLabProbePlan::create(inputs));

        inputs = validInputs();
        inputs.serverIp = "224.0.0.1";
        QVERIFY(!ArpLabProbePlan::create(inputs));

        inputs = validInputs();
        inputs.researchIp = "127.0.0.1";
        QVERIFY(!ArpLabProbePlan::create(inputs));

        inputs = validInputs();
        inputs.researchIp = "169.254.1.20";
        QVERIFY(!ArpLabProbePlan::create(inputs));

        inputs = validInputs();
        inputs.serverIp = inputs.clientIp;
        QVERIFY(!ArpLabProbePlan::create(inputs));
    }

    void rejectsMalformedMulticastBroadcastAndCollidingMacs() {
        auto inputs = validInputs();
        inputs.researchMac = "invalid";
        QVERIFY(!ArpLabProbePlan::create(inputs));

        inputs = validInputs();
        inputs.researchMac = "01:00:00:00:00:20";
        QVERIFY(!ArpLabProbePlan::create(inputs));

        inputs = validInputs();
        inputs.clientMac = "ff:ff:ff:ff:ff:ff";
        QVERIFY(!ArpLabProbePlan::create(inputs));

        inputs = validInputs();
        inputs.serverMac = inputs.researchMac;
        QVERIFY(!ArpLabProbePlan::create(inputs));

        inputs = validInputs();
        inputs.clientMac = "00:00:00:00:00:00";
        QVERIFY(!ArpLabProbePlan::create(inputs));
    }
};

QTEST_GUILESS_MAIN(M6ArpLabProbePlanTests)
#include "M6ArpLabProbePlanTests.moc"
