#include "network/LaunchdMachServiceBootstrap.hpp"

#include <QtTest>

#include <fcntl.h>
#include <unistd.h>

namespace interceptor {

class M6LaunchdMachServiceBootstrapTests final : public QObject {
    Q_OBJECT

  private slots:
    void parsesEnabledConfigAndPreservesTrustedRequirement() {
        LaunchdMachServiceConfig config;
        QString error = QStringLiteral("stale");

        QVERIFY2(parseLaunchdMachServiceConfig(
                     QByteArrayLiteral("enabled=true\npeer-code-requirement=anchor apple\n"),
                     &config, &error),
                 qPrintable(error));
        QVERIFY(config.enabled);
        QCOMPARE(config.trustedPeerRequirement, QByteArrayLiteral("anchor apple"));
        QVERIFY(error.isEmpty());

        QVERIFY(parseLaunchdMachServiceConfig(
            QByteArrayLiteral("enabled=true\npeer-code-requirement=anchor apple"), &config,
            &error));
        QVERIFY(config.enabled);
        QCOMPARE(config.trustedPeerRequirement, QByteArrayLiteral("anchor apple"));
    }

    void rejectsDisabledAndMissingOrMalformedConfig() {
        LaunchdMachServiceConfig disabledConfig;
        QString disabledError;
        QVERIFY(!parseLaunchdMachServiceConfig(
            QByteArrayLiteral("enabled=false\npeer-code-requirement=anchor apple\n"),
            &disabledConfig, &disabledError));
        QCOMPARE(disabledError, QStringLiteral("launchd_mach_service_disabled"));
        QVERIFY(!disabledConfig.enabled);
        QVERIFY(disabledConfig.trustedPeerRequirement.isEmpty());

        const QList<QByteArray> malformed = {
            QByteArrayLiteral("enabled=true\n"),
            QByteArrayLiteral("enabled=true\npeer-code-requirement=\n"),
            QByteArrayLiteral("enabled=true\npeer-code-requirement=anchor apple\n"
                              "peer-code-requirement=anchor apple\n"),
            QByteArrayLiteral("enabled=true\npeer-code-requirement=anchor apple\nextra=value\n"),
            QByteArrayLiteral(
                "enabled=true\npeer-code-requirement=this is not a requirement !!!\n"),
        };

        for (const QByteArray &contents : malformed) {
            LaunchdMachServiceConfig config;
            QString error;
            QVERIFY(!parseLaunchdMachServiceConfig(contents, &config, &error));
            QVERIFY(!error.isEmpty());
            QVERIFY(!config.enabled);
            QVERIFY(config.trustedPeerRequirement.isEmpty());
        }
    }

    void invalidConfigurationsNeverInvokeListenerStart() {
        const QList<LaunchdMachServiceConfig> invalidConfigs = {
            LaunchdMachServiceConfig{},
            LaunchdMachServiceConfig{true, QByteArray()},
            LaunchdMachServiceConfig{true, QByteArrayLiteral("this is not a requirement !!!")},
            LaunchdMachServiceConfig{false, QByteArrayLiteral("anchor apple")},
        };

        for (const LaunchdMachServiceConfig &config : invalidConfigs) {
            int starts = 0;
            QString error;
            const bool started = startConfiguredLaunchdMachService(
                config,
                [&starts](const QByteArray &, const QByteArray &, QString *) {
                    ++starts;
                    return true;
                },
                &error);
            QVERIFY(!started);
            QCOMPARE(starts, 0);
            QVERIFY(!error.isEmpty());
        }
    }

    void startsOnlyFixedServiceWithValidatedLocalRequirement() {
        const LaunchdMachServiceConfig config{true, QByteArrayLiteral("anchor apple")};
        int starts = 0;
        QByteArray receivedServiceName;
        QByteArray receivedRequirement;
        QString error;

        QVERIFY2(startConfiguredLaunchdMachService(
                     config,
                     [&starts, &receivedServiceName, &receivedRequirement](
                         const QByteArray &serviceName, const QByteArray &requirement, QString *) {
                         ++starts;
                         receivedServiceName = serviceName;
                         receivedRequirement = requirement;
                         return true;
                     },
                     &error),
                 qPrintable(error));
        QCOMPARE(starts, 1);
        QCOMPARE(receivedServiceName, QByteArray(launchdMachServiceName));
        QCOMPARE(receivedRequirement, QByteArrayLiteral("anchor apple"));
        QVERIFY(error.isEmpty());
    }

    void missingConfigFileFailsClosedWithoutPrivilegedOperations() {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QByteArray directoryPath = QFile::encodeName(temporaryDirectory.path());
        const int stateDirectoryFd =
            ::open(directoryPath.constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        QVERIFY(stateDirectoryFd >= 0);

        LaunchdMachServiceConfig config;
        QString error;
        QVERIFY(!loadLaunchdMachServiceConfig(stateDirectoryFd, &config, &error));
        QCOMPARE(error, QStringLiteral("launchd_mach_service_config_open_failed"));
        ::close(stateDirectoryFd);
        QVERIFY(!config.enabled);
        QVERIFY(config.trustedPeerRequirement.isEmpty());

        int starts = 0;
        QVERIFY(!startConfiguredLaunchdMachService(
            config,
            [&starts](const QByteArray &, const QByteArray &, QString *) {
                ++starts;
                return true;
            },
            &error));
        QCOMPARE(starts, 0);
    }
};

} // namespace interceptor

QTEST_GUILESS_MAIN(interceptor::M6LaunchdMachServiceBootstrapTests)
#include "M6LaunchdMachServiceBootstrapTests.moc"
