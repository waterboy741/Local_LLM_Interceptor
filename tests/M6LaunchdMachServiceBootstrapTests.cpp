#include "network/HelperStateDirectory.hpp"
#include "network/LaunchdMachServiceBootstrap.hpp"

#include <QtTest>

#include <string>
#include <string_view>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace interceptor {

class M6LaunchdMachServiceBootstrapTests final : public QObject {
    Q_OBJECT

  private slots:
    void parsesEnabledConfigAndPreservesTrustedRequirement_data() {
        QTest::addColumn<std::string>("requirement");
        QTest::newRow("40 lowercase hex") << exactPeerRequirement();
        QTest::newRow("40 mixed case hex")
            << std::string("cdhash H\"0123456789AbCdEf0123456789aBcDeF01234567\"");
    }

    void parsesEnabledConfigAndPreservesTrustedRequirement() {
        QFETCH(std::string, requirement);
        const std::string contents = "enabled=true\npeer-code-requirement=" + requirement;
        LaunchdMachServiceConfig config;
        std::string error = "stale";

        QVERIFY2(parseLaunchdMachServiceConfig(contents + '\n', &config, &error), error.c_str());
        QVERIFY(config.enabled);
        QCOMPARE(config.trustedPeerRequirement, requirement);
        QVERIFY(error.empty());

        QVERIFY(parseLaunchdMachServiceConfig(contents, &config, &error));
        QVERIFY(config.enabled);
        QCOMPARE(config.trustedPeerRequirement, requirement);
    }

    void rejectsDisabledAndMissingOrMalformedConfig() {
        LaunchdMachServiceConfig disabledConfig;
        std::string disabledError;
        QVERIFY(
            !parseLaunchdMachServiceConfig("enabled=false\npeer-code-requirement=anchor apple\n",
                                           &disabledConfig, &disabledError));
        QCOMPARE(disabledError, "launchd_mach_service_disabled");
        QVERIFY(!disabledConfig.enabled);
        QVERIFY(disabledConfig.trustedPeerRequirement.empty());

        const QList<std::string> malformed = {
            "enabled=true\npeer-code-requirement=anchor apple\n",
            "enabled=true\npeer-code-requirement=cdhash H\"01234567\"\n",
            "enabled=true\npeer-code-requirement=cdhash "
            "H\"0123456789abcdef0123456789abcdef0123456g\"\n",
            "enabled=true\npeer-code-requirement=" + exactPeerRequirement() + " or anchor apple\n",
            "enabled=true\n",
            "enabled=true\npeer-code-requirement=\n",
            "enabled=true\npeer-code-requirement=anchor apple\n"
            "peer-code-requirement=anchor apple\n",
            "enabled=true\npeer-code-requirement=anchor apple\nextra=value\n",
            "enabled=true\npeer-code-requirement=this is not a requirement !!!\n",
        };

        for (const std::string &contents : malformed) {
            LaunchdMachServiceConfig config;
            std::string error;
            QVERIFY(!parseLaunchdMachServiceConfig(contents, &config, &error));
            QVERIFY(!error.empty());
            QVERIFY(!config.enabled);
            QVERIFY(config.trustedPeerRequirement.empty());
        }
    }

    void invalidConfigurationsNeverInvokeListenerStart() {
        const QList<LaunchdMachServiceConfig> invalidConfigs = {
            LaunchdMachServiceConfig{},
            LaunchdMachServiceConfig{true, std::string()},
            LaunchdMachServiceConfig{true, "this is not a requirement !!!"},
            LaunchdMachServiceConfig{true, "anchor apple"},
            LaunchdMachServiceConfig{true, exactPeerRequirement() + " or anchor apple"},
            LaunchdMachServiceConfig{true, exactPeerRequirement() + " "},
            LaunchdMachServiceConfig{true, exactPeerRequirement() + '\n'},
            LaunchdMachServiceConfig{false, exactPeerRequirement()},
        };

        for (const LaunchdMachServiceConfig &config : invalidConfigs) {
            int starts = 0;
            std::string error;
            const bool started = startConfiguredLaunchdMachService(
                config,
                [&starts](std::string_view, std::string_view, std::string *) {
                    ++starts;
                    return true;
                },
                &error);
            QVERIFY(!started);
            QCOMPARE(starts, 0);
            QVERIFY(!error.empty());
        }
    }

    void startsOnlyFixedServiceWithValidatedLocalRequirement() {
        const LaunchdMachServiceConfig config{true, exactPeerRequirement()};
        int starts = 0;
        std::string receivedServiceName;
        std::string receivedRequirement;
        std::string error;

        QVERIFY2(
            startConfiguredLaunchdMachService(
                config,
                [&starts, &receivedServiceName, &receivedRequirement](
                    std::string_view serviceName, std::string_view requirement, std::string *) {
                    ++starts;
                    receivedServiceName = serviceName;
                    receivedRequirement = requirement;
                    return true;
                },
                &error),
            error.c_str());
        QCOMPARE(starts, 1);
        QCOMPARE(receivedServiceName, std::string(launchdMachServiceName));
        QCOMPARE(receivedRequirement, config.trustedPeerRequirement);
        QVERIFY(error.empty());
    }

    void stateDirectoryRequiresCanonicalPathCorrectOwnerAndPrivateMode() {
        QTemporaryDir fixture;
        QVERIFY(fixture.isValid());
        const QByteArray canonicalRoot = QFile::encodeName(QDir(fixture.path()).canonicalPath());
        const QByteArray path = canonicalRoot + "/state";
        QCOMPARE(::mkdir(path.constData(), 0700), 0);

        std::string error;
        const int fd = openHelperStateDirectory(path.constData(), ::geteuid(), &error);
        QVERIFY2(fd >= 0, error.c_str());
        QVERIFY(error.empty());
        const int flags = ::fcntl(fd, F_GETFD);
        QCOMPARE(::close(fd), 0);
        QVERIFY(flags >= 0 && (flags & FD_CLOEXEC) != 0);

        const QByteArray alias = canonicalRoot + "/alias";
        QCOMPARE(::symlink(path.constData(), alias.constData()), 0);
        QCOMPARE(openHelperStateDirectory(alias.constData(), ::geteuid(), &error), -1);
        QCOMPARE(error, "state_directory_missing_or_symlink");
        const QByteArray nonCanonical = canonicalRoot + "/./state";
        QCOMPARE(openHelperStateDirectory(nonCanonical.constData(), ::geteuid(), &error), -1);
        QCOMPARE(error, "canonical_state_directory_required");

        const uid_t wrongOwner = ::geteuid() == 0 ? 1 : 0;
        QCOMPARE(openHelperStateDirectory(path.constData(), wrongOwner, &error), -1);
        QCOMPARE(error, "unsafe_state_directory");
        QCOMPARE(::chmod(path.constData(), 0755), 0);
        QCOMPARE(openHelperStateDirectory(path.constData(), ::geteuid(), &error), -1);
        QCOMPARE(error, "unsafe_state_directory");
    }

    void stateDirectoryRejectsAnExtendedAclEvenWithPrivatePosixMode() {
        QTemporaryDir fixture;
        QVERIFY(fixture.isValid());
        const QString path = QDir(fixture.path()).canonicalPath() + QStringLiteral("/state");
        const QByteArray encodedPath = QFile::encodeName(path);
        QCOMPARE(::mkdir(encodedPath.constData(), 0700), 0);
        QCOMPARE(QProcess::execute(
                     QStringLiteral("/bin/chmod"),
                     {QStringLiteral("+a"), QStringLiteral("everyone allow add_file"), path}),
                 0);
        struct stat pathInfo{};
        QCOMPARE(::stat(encodedPath.constData(), &pathInfo), 0);
        QCOMPARE(pathInfo.st_mode & 07777, 0700);

        std::string error;
        QCOMPARE(openHelperStateDirectory(encodedPath.constData(), ::geteuid(), &error), -1);
        QCOMPARE(error, "unsafe_state_directory");
    }

    void fileAclCheckRejectsAnExtendedAclOnPrivateConfig() {
        QTemporaryDir fixture;
        QVERIFY(fixture.isValid());
        const QString path = fixture.filePath(QStringLiteral("mach-service.conf"));
        const QByteArray encodedPath = QFile::encodeName(path);
        const int fd =
            ::open(encodedPath.constData(), O_RDONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        QVERIFY(fd >= 0);
        const bool originallyPrivate = hasNoExtendedAcl(fd);
        const int chmodStatus =
            QProcess::execute(QStringLiteral("/bin/chmod"),
                              {QStringLiteral("+a"), QStringLiteral("everyone allow read"), path});
        const bool extendedAclAccepted = hasNoExtendedAcl(fd);
        QCOMPARE(::close(fd), 0);
        QVERIFY(originallyPrivate);
        QCOMPARE(chmodStatus, 0);
        QVERIFY(!extendedAclAccepted);
    }

    void missingConfigFileFailsClosedWithoutPrivilegedOperations() {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QByteArray directoryPath = QFile::encodeName(temporaryDirectory.path());
        const int stateDirectoryFd =
            ::open(directoryPath.constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        QVERIFY(stateDirectoryFd >= 0);

        LaunchdMachServiceConfig config;
        std::string error;
        QVERIFY(!loadLaunchdMachServiceConfig(stateDirectoryFd, &config, &error));
        QCOMPARE(error, "launchd_mach_service_config_open_failed");
        ::close(stateDirectoryFd);
        QVERIFY(!config.enabled);
        QVERIFY(config.trustedPeerRequirement.empty());

        int starts = 0;
        QVERIFY(!startConfiguredLaunchdMachService(
            config,
            [&starts](std::string_view, std::string_view, std::string *) {
                ++starts;
                return true;
            },
            &error));
        QCOMPARE(starts, 0);
    }

  private:
    static std::string exactPeerRequirement() {
        return "cdhash H\"0123456789abcdef0123456789abcdef01234567\"";
    }
};

} // namespace interceptor

QTEST_GUILESS_MAIN(interceptor::M6LaunchdMachServiceBootstrapTests)
#include "M6LaunchdMachServiceBootstrapTests.moc"
