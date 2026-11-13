#include "network/MachServiceIdentityPreviewCli.hpp"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>
#include <QtTest>

using namespace interceptor;

namespace {
const QStringList validArguments{QStringLiteral("mach_service_identity_preview"),
                                 QStringLiteral("--app"), QString()};

class FakeCodesignRunner final : public CodesignCommandRunner {
  public:
    QVector<CodesignCommandResult> preparedResults;
    QVector<QStringList> calls;
    QVector<int> timeouts;
    QVector<qsizetype> outputLimits;

    CodesignCommandResult run(const QStringList &arguments, int timeoutMs,
                              qsizetype outputLimitBytes) override {
        calls.append(arguments);
        timeouts.append(timeoutMs);
        outputLimits.append(outputLimitBytes);
        const qsizetype index = calls.size() - 1;
        if (index < preparedResults.size())
            return preparedResults.at(index);
        return {true, true, false, 0, {}, {}};
    }
};

class IdentityPreviewFixture {
  public:
    QTemporaryDir temporaryDirectory;
    QString appPath;
    QString canonicalAppPath;

    IdentityPreviewFixture() {
        appPath = temporaryDirectory.path() + QStringLiteral("/llm_interceptor.app");
        QDir directory;
        directory.mkpath(appPath + QStringLiteral("/Contents/MacOS"));
        QFile executable(appPath + QStringLiteral("/Contents/MacOS/llm_interceptor"));
        if (executable.open(QIODevice::WriteOnly)) {
            executable.write("synthetic test executable\n");
            executable.close();
        }
        canonicalAppPath = QFileInfo(appPath).canonicalFilePath();
    }

    QStringList arguments() const {
        auto result = validArguments;
        result[2] = appPath;
        return result;
    }
};

CodesignCommandResult success(const QByteArray &stdoutBytes = {},
                              const QByteArray &stderrBytes = {}) {
    return {true, true, false, 0, stdoutBytes, stderrBytes};
}

QByteArray errorText(const CodesignCommandResult &result) { return result.standardError; }

bool identityPreviewIsSupported() {
#if defined(Q_OS_MACOS)
    return true;
#else
    return false;
#endif
}
} // namespace

class M6MachServiceIdentityPreviewCliTests final : public QObject {
    Q_OBJECT

  private slots:
    void validExactCdhashProducesDisabledProposalAndFixedCommands() {
        if (!identityPreviewIsSupported())
            QSKIP("codesign identity preview is macOS-only");

        IdentityPreviewFixture fixture;
        QVERIFY(fixture.temporaryDirectory.isValid());
        FakeCodesignRunner runner;
        const QByteArray executableLine = QByteArrayLiteral("Executable=") +
                                          fixture.canonicalAppPath.toUtf8() +
                                          QByteArrayLiteral("/Contents/MacOS/llm_interceptor\n");
        const QByteArray designatedLine = QByteArrayLiteral(
            "# designated => cdhash H\"0123456789abcdef0123456789abcdef01234567\"\n");
        runner.preparedResults = {success(), success(designatedLine, executableLine)};

        const auto result = MachServiceIdentityPreviewCli::run(fixture.arguments(), runner);

        QVERIFY2(result.exitCode == 0, result.standardError.constData());
        QCOMPARE(
            result.standardOutput,
            QByteArrayLiteral(
                "enabled=false\n"
                "peer-code-requirement=cdhash H\"0123456789abcdef0123456789abcdef01234567\"\n"));
        QVERIFY(result.standardError.isEmpty());
        QCOMPARE(runner.calls.size(), 2);
        QCOMPARE(runner.calls.at(0),
                 (QStringList{QStringLiteral("--verify"), QStringLiteral("--strict"),
                              QStringLiteral("--deep"), fixture.canonicalAppPath}));
        QCOMPARE(runner.calls.at(1), (QStringList{QStringLiteral("-d"), QStringLiteral("-r-"),
                                                  fixture.canonicalAppPath}));
        QCOMPARE(runner.timeouts, (QVector<int>{5000, 5000}));
        QCOMPARE(runner.outputLimits, (QVector<qsizetype>{16 * 1024, 16 * 1024}));
        QCOMPARE(QDir(fixture.appPath).entryList(QDir::AllEntries | QDir::NoDotAndDotDot),
                 QStringList{QStringLiteral("Contents")});
        QCOMPARE(QDir(fixture.appPath + QStringLiteral("/Contents/MacOS"))
                     .entryList(QDir::AllEntries | QDir::NoDotAndDotDot),
                 QStringList{QStringLiteral("llm_interceptor")});
        QFile executable(fixture.appPath + QStringLiteral("/Contents/MacOS/llm_interceptor"));
        QVERIFY(executable.open(QIODevice::ReadOnly));
        QCOMPARE(executable.readAll(), QByteArrayLiteral("synthetic test executable\n"));
    }

    void absentMalformedAndBroadRequirementsFailClosed() {
        if (!identityPreviewIsSupported())
            QSKIP("codesign identity preview is macOS-only");

        const QList<QByteArray> rejectedOutputs = {
            {},
            QByteArrayLiteral("# designated => cdhash H\"not-a-hash\"\n"),
            QByteArrayLiteral("# designated => identifier \"com.example.llm\"\n"),
            QByteArrayLiteral("# designated => anchor apple generic and identifier \"x\"\n"),
            QByteArrayLiteral(
                "# designated => cdhash H\"0123456789abcdef0123456789abcdef01234567\"\n"
                "# designated => cdhash H\"1123456789abcdef0123456789abcdef01234567\"\n"),
            QByteArrayLiteral(
                "# designated => cdhash H\"0123456789abcdef0123456789abcdef01234567\"\0\n")};

        for (const QByteArray &output : rejectedOutputs) {
            IdentityPreviewFixture fixture;
            FakeCodesignRunner runner;
            runner.preparedResults = {success(), success({}, output)};
            const auto result = MachServiceIdentityPreviewCli::run(fixture.arguments(), runner);
            QVERIFY(result.exitCode != 0);
            QVERIFY(result.standardOutput.isEmpty());
            QCOMPARE(runner.calls.size(), 2);
        }
    }

    void actualCodesignFormatRequiresCommentAndExecutableFirst() {
        if (!identityPreviewIsSupported())
            QSKIP("codesign identity preview is macOS-only");

        IdentityPreviewFixture fixture;
        const QByteArray executableLine = QByteArrayLiteral("Executable=") +
                                          fixture.canonicalAppPath.toUtf8() +
                                          QByteArrayLiteral("/Contents/MacOS/llm_interceptor\n");
        const QByteArray designatedLine = QByteArrayLiteral(
            "# designated => cdhash H\"0123456789abcdef0123456789abcdef01234567\"\n");
        const QList<QByteArray> rejectedOutputs = {
            executableLine +
                QByteArrayLiteral(
                    "designated => cdhash H\"0123456789abcdef0123456789abcdef01234567\"\n"),
            designatedLine + executableLine};

        for (const QByteArray &output : rejectedOutputs) {
            FakeCodesignRunner runner;
            runner.preparedResults = {success(), success({}, output)};
            const auto result = MachServiceIdentityPreviewCli::run(fixture.arguments(), runner);
            QVERIFY(result.exitCode != 0);
            QVERIFY(result.standardOutput.isEmpty());
        }
    }

    void wrongBundlePathAndWrongExecutablePathAreRejected() {
        if (!identityPreviewIsSupported())
            QSKIP("codesign identity preview is macOS-only");

        IdentityPreviewFixture fixture;
        FakeCodesignRunner runner;
        auto arguments = fixture.arguments();
        arguments[2] = fixture.temporaryDirectory.path();
        const auto badBundle = MachServiceIdentityPreviewCli::run(arguments, runner);
        QVERIFY(badBundle.exitCode != 0);
        QCOMPARE(runner.calls.size(), 0);

        const QByteArray wrongExecutablePath = QByteArrayLiteral(
            "Executable=/tmp/attacker.app/Contents/MacOS/llm_interceptor\n"
            "# designated => cdhash H\"0123456789abcdef0123456789abcdef01234567\"\n");
        runner.preparedResults = {success(), success({}, wrongExecutablePath)};
        const auto wrongIdentity = MachServiceIdentityPreviewCli::run(fixture.arguments(), runner);
        QVERIFY(wrongIdentity.exitCode != 0);
        QVERIFY(wrongIdentity.standardOutput.isEmpty());
    }

    void symlinkedMacOsDirectoryIsRejectedBeforeCodesign() {
        if (!identityPreviewIsSupported())
            QSKIP("codesign identity preview is macOS-only");

        IdentityPreviewFixture fixture;
        const QString macOsPath = fixture.appPath + QStringLiteral("/Contents/MacOS");
        QVERIFY(QDir(macOsPath).removeRecursively());
        const QString externalDirectory =
            fixture.temporaryDirectory.path() + QStringLiteral("/external/MacOS");
        QVERIFY(QDir().mkpath(externalDirectory));
        QFile externalExecutable(externalDirectory + QStringLiteral("/llm_interceptor"));
        QVERIFY(externalExecutable.open(QIODevice::WriteOnly));
        externalExecutable.write("synthetic external executable\n");
        externalExecutable.close();
        QVERIFY(QFile::link(externalDirectory, macOsPath));
        QVERIFY(QFileInfo(macOsPath).isSymLink());

        FakeCodesignRunner runner;
        const auto result = MachServiceIdentityPreviewCli::run(fixture.arguments(), runner);

        QVERIFY(result.exitCode != 0);
        QCOMPARE(runner.calls.size(), 0);
    }

    void wrongIdentifierAndUnexpectedMetadataAreRejected() {
        if (!identityPreviewIsSupported())
            QSKIP("codesign identity preview is macOS-only");

        IdentityPreviewFixture fixture;
        const QList<QByteArray> outputs = {
            QByteArrayLiteral(
                "Identifier=com.example.impostor\n"
                "# designated => cdhash H\"0123456789abcdef0123456789abcdef01234567\"\n"),
            QByteArrayLiteral(
                "# designated => cdhash H\"0123456789abcdef0123456789abcdef01234567\"\n"
                "# designated => cdhash H\"0123456789abcdef0123456789abcdef01234567\"\n")};
        for (const auto &output : outputs) {
            FakeCodesignRunner runner;
            runner.preparedResults = {success(), success({}, output)};
            const auto result = MachServiceIdentityPreviewCli::run(fixture.arguments(), runner);
            QVERIFY(result.exitCode != 0);
            QVERIFY(result.standardOutput.isEmpty());
        }

        const QByteArray executableLine = QByteArrayLiteral("Executable=") +
                                          fixture.canonicalAppPath.toUtf8() +
                                          QByteArrayLiteral("/Contents/MacOS/llm_interceptor\n");
        FakeCodesignRunner duplicateExecutable;
        duplicateExecutable.preparedResults = {
            success(),
            success(
                {},
                executableLine + executableLine +
                    QByteArrayLiteral(
                        "# designated => cdhash H\"0123456789abcdef0123456789abcdef01234567\"\n"))};
        const auto duplicateResult =
            MachServiceIdentityPreviewCli::run(fixture.arguments(), duplicateExecutable);
        QVERIFY(duplicateResult.exitCode != 0);
        QVERIFY(duplicateResult.standardOutput.isEmpty());
    }

    void unsignedVerifyErrorsAndTimeoutsNeverEmitProposal() {
        if (!identityPreviewIsSupported())
            QSKIP("codesign identity preview is macOS-only");

        IdentityPreviewFixture fixture;
        const QList<CodesignCommandResult> verifyFailures = {
            {true, true, false, 1, {}, QByteArrayLiteral("code object is not signed")},
            {false, false, false, -1, {}, {}},
            {true, false, true, -1, {}, {}}};
        for (const auto &verifyResult : verifyFailures) {
            FakeCodesignRunner runner;
            runner.preparedResults = {verifyResult};
            const auto result = MachServiceIdentityPreviewCli::run(fixture.arguments(), runner);
            QVERIFY(result.exitCode != 0);
            QVERIFY(result.standardOutput.isEmpty());
            QCOMPARE(runner.calls.size(), 1);
        }

        FakeCodesignRunner identityTimeout;
        identityTimeout.preparedResults = {success(), {true, false, true, -1, {}, {}}};
        const auto timedOut =
            MachServiceIdentityPreviewCli::run(fixture.arguments(), identityTimeout);
        QVERIFY(timedOut.exitCode != 0);
        QVERIFY(errorText(timedOut).contains("timed_out"));
        QVERIFY(timedOut.standardOutput.isEmpty());
    }

    void excessiveOutputAndNonZeroIdentityDisplayFailClosed() {
        if (!identityPreviewIsSupported())
            QSKIP("codesign identity preview is macOS-only");

        IdentityPreviewFixture fixture;
        const QList<CodesignCommandResult> failures = {
            {true, true, false, 0, QByteArray(16 * 1024 + 1, 'x'), {}},
            {true, true, false, 0, {}, QByteArray(16 * 1024 + 1, 'x')},
            {true, true, false, 2, {}, QByteArrayLiteral("codesign failed")}};
        for (const auto &displayResult : failures) {
            FakeCodesignRunner runner;
            runner.preparedResults = {success(), displayResult};
            const auto result = MachServiceIdentityPreviewCli::run(fixture.arguments(), runner);
            QVERIFY(result.exitCode != 0);
            QVERIFY(result.standardOutput.isEmpty());
        }
    }

    void parserHelpAndInvalidBundleDoNotInvokeCodesign() {
        IdentityPreviewFixture fixture;
        FakeCodesignRunner runner;
        const auto invalidBundle = MachServiceIdentityPreviewCli::run(
            {QStringLiteral("mach_service_identity_preview"), QStringLiteral("--app"),
             fixture.temporaryDirectory.path()},
            runner);
        QVERIFY(invalidBundle.exitCode != 0);
        QCOMPARE(runner.calls.size(), 0);
    }
};

QTEST_GUILESS_MAIN(M6MachServiceIdentityPreviewCliTests)
#include "M6MachServiceIdentityPreviewCliTests.moc"
