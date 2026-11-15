#include "network/LaunchdMachServiceBootstrap.hpp"

#include <QtTest>

#include <fcntl.h>
#include <unistd.h>

namespace interceptor {

class M6LaunchdMachServiceBootstrapTests final : public QObject {
    Q_OBJECT

  private slots:
    void parsesEnabledConfigAndPreservesTrustedRequirement_data() {
        QTest::addColumn<QByteArray>("requirement");
        QTest::newRow("40 lowercase hex") << exactPeerRequirement();
        QTest::newRow("40 mixed case hex")
            << QByteArrayLiteral("cdhash H\"0123456789AbCdEf0123456789aBcDeF01234567\"");
    }

    void parsesEnabledConfigAndPreservesTrustedRequirement() {
        QFETCH(QByteArray, requirement);
        const QByteArray contents = "enabled=true\npeer-code-requirement=" + requirement;
        LaunchdMachServiceConfig config;
        QString error = QStringLiteral("stale");

        QVERIFY2(parseLaunchdMachServiceConfig(contents + '\n', &config, &error),
                 qPrintable(error));
        QVERIFY(config.enabled);
        QCOMPARE(config.trustedPeerRequirement, requirement);
        QVERIFY(error.isEmpty());

        QVERIFY(parseLaunchdMachServiceConfig(contents, &config, &error));
        QVERIFY(config.enabled);
        QCOMPARE(config.trustedPeerRequirement, requirement);
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
            QByteArrayLiteral("enabled=true\npeer-code-requirement=anchor apple\n"),
            QByteArrayLiteral("enabled=true\npeer-code-requirement=cdhash H\"01234567\"\n"),
            QByteArrayLiteral("enabled=true\npeer-code-requirement=cdhash "
                              "H\"0123456789abcdef0123456789abcdef0123456g\"\n"),
            "enabled=true\npeer-code-requirement=" + exactPeerRequirement() + " or anchor apple\n",
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
            LaunchdMachServiceConfig{true, QByteArrayLiteral("anchor apple")},
            LaunchdMachServiceConfig{true, exactPeerRequirement() + " or anchor apple"},
            LaunchdMachServiceConfig{true, exactPeerRequirement() + " "},
            LaunchdMachServiceConfig{true, exactPeerRequirement() + '\n'},
            LaunchdMachServiceConfig{false, exactPeerRequirement()},
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
        const LaunchdMachServiceConfig config{true, exactPeerRequirement()};
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
        QCOMPARE(receivedRequirement, config.trustedPeerRequirement);
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

  private:
    static QByteArray exactPeerRequirement() {
        return QByteArrayLiteral("cdhash H\"0123456789abcdef0123456789abcdef01234567\"");
    }
};

} // namespace interceptor

QTEST_GUILESS_MAIN(interceptor::M6LaunchdMachServiceBootstrapTests)
#include "M6LaunchdMachServiceBootstrapTests.moc"
