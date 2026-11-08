#include <QFile>
#include <QProcess>
#include <QTemporaryDir>
#include <QtTest>

#include <unistd.h>

class M6InstalledHelperProcessTests final : public QObject {
    Q_OBJECT

  private:
    struct ProcessResult {
        QByteArray standardOutput;
        QByteArray standardError;
        int exitCode = -1;
        QProcess::ExitStatus exitStatus = QProcess::CrashExit;
        bool finished = false;
    };

    static ProcessResult runHelper(const QStringList &arguments) {
        QProcess process;
        process.start(QStringLiteral(INTERCEPTOR_HELPER_EXECUTABLE), arguments);
        if (!process.waitForStarted(5000) || !process.waitForFinished(5000))
            return {};
        return {process.readAllStandardOutput(), process.readAllStandardError(), process.exitCode(),
                process.exitStatus(), true};
    }

  private slots:
    void rejectsMalformedProcessInvocation() {
        const ProcessResult process =
            runHelper({QStringLiteral("--process"), QStringLiteral("--state-dir"),
                       QStringLiteral("/tmp/unused"), QStringLiteral("--bootstrap-fd"),
                       QStringLiteral("not-a-number")});

        QVERIFY2(process.finished, "The helper process must exit within the test deadline.");
        QCOMPARE(process.exitStatus, QProcess::NormalExit);
        QCOMPARE(process.exitCode, 2);
        QVERIFY(process.standardOutput.isEmpty());
        QVERIFY(process.standardError.contains("usage"));
    }

    void processModeFailsClosedBeforeBootstrapUse() {
        QTemporaryDir stateDirectory;
        QVERIFY(stateDirectory.isValid());
        QVERIFY(QFile::setPermissions(stateDirectory.path(), QFileDevice::ReadOwner |
                                                                 QFileDevice::WriteOwner |
                                                                 QFileDevice::ExeOwner));

        // This descriptor is deliberately not inherited or opened. The production entrypoint
        // must fail closed before trying to consume a bootstrap frame from it.
        const ProcessResult process = runHelper(
            {QStringLiteral("--process"), QStringLiteral("--state-dir"), stateDirectory.path(),
             QStringLiteral("--bootstrap-fd"), QStringLiteral("123")});

        QVERIFY2(process.finished, "The helper process must exit within the test deadline.");
        QCOMPARE(process.exitStatus, QProcess::NormalExit);
        QVERIFY(process.standardOutput.isEmpty());
        const QByteArray error = process.standardError;
        QVERIFY(!error.contains("ready"));
        if (::geteuid() == 0) {
            QCOMPARE(process.exitCode, 5);
            QVERIFY(error.contains("production_peer_authenticator_unavailable"));
        } else {
            QCOMPARE(process.exitCode, 3);
            QVERIFY(error.contains("effective_root_required"));
        }
    }
};

QTEST_GUILESS_MAIN(M6InstalledHelperProcessTests)
#include "M6InstalledHelperProcessTests.moc"
