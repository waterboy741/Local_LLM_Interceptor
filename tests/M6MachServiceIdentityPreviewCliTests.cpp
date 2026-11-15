#include "network/MachServiceIdentityPreviewCli.hpp"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>
#include <QtTest>

#include <functional>

#if defined(Q_OS_MACOS)
#include <Security/SecRequirement.h>
#endif

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
    std::function<void()> onSelfMatch;

    CodesignCommandResult run(const QStringList &arguments, int timeoutMs,
                              qsizetype outputLimitBytes) override {
        calls.append(arguments);
        timeouts.append(timeoutMs);
        outputLimits.append(outputLimitBytes);
        const qsizetype index = calls.size() - 1;
        if (index == 2 && onSelfMatch)
            onSelfMatch();
        if (index < preparedResults.size())
            return preparedResults.at(index);
        return {false, false, false, -1, {}, {}};
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
        runner.preparedResults = {success(), success(designatedLine, executableLine), success()};

        const auto result = MachServiceIdentityPreviewCli::run(fixture.arguments(), runner);

        QVERIFY2(result.exitCode == 0, result.standardError.constData());
        QCOMPARE(
            result.standardOutput,
            QByteArrayLiteral(
                "enabled=false\n"
                "peer-code-requirement=cdhash H\"0123456789abcdef0123456789abcdef01234567\"\n"));
        QVERIFY(result.standardError.isEmpty());
        QCOMPARE(runner.calls.size(), 3);
        QCOMPARE(runner.calls.at(0),
                 (QStringList{QStringLiteral("--verify"), QStringLiteral("--strict"),
                              QStringLiteral("--deep"), fixture.canonicalAppPath}));
        QCOMPARE(runner.calls.at(1), (QStringList{QStringLiteral("-d"), QStringLiteral("-r-"),
                                                  fixture.canonicalAppPath}));
        QCOMPARE(
            runner.calls.at(2),
            (QStringList{QStringLiteral("--verify"), QStringLiteral("--strict"),
                         QStringLiteral("--deep"),
                         QStringLiteral("-R=cdhash H\"0123456789abcdef0123456789abcdef01234567\""),
                         fixture.canonicalAppPath}));
        QCOMPARE(runner.timeouts, (QVector<int>{5000, 5000, 5000}));
        QCOMPARE(runner.outputLimits, (QVector<qsizetype>{16 * 1024, 16 * 1024, 16 * 1024}));
        QCOMPARE(QDir(fixture.appPath).entryList(QDir::AllEntries | QDir::NoDotAndDotDot),
                 QStringList{QStringLiteral("Contents")});
        QCOMPARE(QDir(fixture.appPath + QStringLiteral("/Contents/MacOS"))
                     .entryList(QDir::AllEntries | QDir::NoDotAndDotDot),
                 QStringList{QStringLiteral("llm_interceptor")});
        QFile executable(fixture.appPath + QStringLiteral("/Contents/MacOS/llm_interceptor"));
        QVERIFY(executable.open(QIODevice::ReadOnly));
        QCOMPARE(executable.readAll(), QByteArrayLiteral("synthetic test executable\n"));
    }

    void extendedCdhashProposalMatchesLocalRequirementCompiler() {
#if defined(Q_OS_MACOS)
        IdentityPreviewFixture fixture;
        FakeCodesignRunner runner;
        const QByteArray requirement = QByteArrayLiteral("cdhash H\"") + QByteArray(64, 'a') + '"';
        const QByteArray executableLine = QByteArrayLiteral("Executable=") +
                                          fixture.canonicalAppPath.toUtf8() +
                                          QByteArrayLiteral("/Contents/MacOS/llm_interceptor\n");
        runner.preparedResults = {
            success(), success({}, executableLine + "# designated => " + requirement + '\n'),
            success()};

        const CFStringRef requirementText = CFStringCreateWithCString(
            kCFAllocatorDefault, requirement.constData(), kCFStringEncodingUTF8);
        QVERIFY(requirementText);
        SecRequirementRef compiled = nullptr;
        const OSStatus status =
            SecRequirementCreateWithString(requirementText, kSecCSDefaultFlags, &compiled);
        CFRelease(requirementText);
        const bool supported = status == errSecSuccess && compiled != nullptr;
        if (compiled)
            CFRelease(compiled);

        const auto result = MachServiceIdentityPreviewCli::run(fixture.arguments(), runner);

        QCOMPARE(runner.calls.size(), supported ? 3 : 2);
        if (supported) {
            QVERIFY2(result.exitCode == 0, result.standardError.constData());
            QCOMPARE(result.standardOutput,
                     "enabled=false\npeer-code-requirement=" + requirement + '\n');
            QVERIFY(result.standardError.isEmpty());
        } else {
            QVERIFY(result.exitCode != 0);
            QVERIFY(result.standardOutput.isEmpty());
            QVERIFY(!result.standardError.isEmpty());
        }
#else
        QSKIP("codesign identity preview is macOS-only");
#endif
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
            const QByteArray executableLine =
                QByteArrayLiteral("Executable=") + fixture.canonicalAppPath.toUtf8() +
                QByteArrayLiteral("/Contents/MacOS/llm_interceptor\n");
            runner.preparedResults = {success(), success({}, executableLine + output)};
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

    void selfMatchFailuresNeverEmitProposal() {
        if (!identityPreviewIsSupported())
            QSKIP("codesign identity preview is macOS-only");

        IdentityPreviewFixture fixture;
        const QByteArray executableLine = QByteArrayLiteral("Executable=") +
                                          fixture.canonicalAppPath.toUtf8() +
                                          QByteArrayLiteral("/Contents/MacOS/llm_interceptor\n");
        const QByteArray designatedLine = QByteArrayLiteral(
            "# designated => cdhash H\"0123456789abcdef0123456789abcdef01234567\"\n");
        const QList<CodesignCommandResult> failures = {
            {true, true, false, 3, {}, QByteArrayLiteral("test requirement failed")},
            {false, false, false, -1, {}, {}},
            {true, false, false, -1, {}, {}},
            {true, false, true, -1, {}, {}},
            {true, true, false, 0, QByteArray(16 * 1024 + 1, 'x'), {}},
            {true, true, false, 0, {}, QByteArray(16 * 1024 + 1, 'x')},
            {true, true, false, 2, {}, QByteArrayLiteral("codesign failed")}};
        for (const auto &selfMatchResult : failures) {
            FakeCodesignRunner runner;
            runner.preparedResults = {success(), success(designatedLine, executableLine),
                                      selfMatchResult};
            const auto result = MachServiceIdentityPreviewCli::run(fixture.arguments(), runner);
            QVERIFY(result.exitCode != 0);
            QVERIFY(result.standardOutput.isEmpty());
            QVERIFY(result.standardError.contains(
                selfMatchResult.timedOut ? "codesign_requirement_verification_timed_out"
                                         : "codesign_requirement_verification_failed"));
            QCOMPARE(runner.calls.size(), 3);
        }
    }

    void executableChangeDuringSelfMatchNeverEmitsProposal() {
        if (!identityPreviewIsSupported())
            QSKIP("codesign identity preview is macOS-only");

        IdentityPreviewFixture fixture;
        const QString executablePath =
            fixture.canonicalAppPath + QStringLiteral("/Contents/MacOS/llm_interceptor");
        const QByteArray executableLine = "Executable=" + executablePath.toUtf8() + '\n';
        const QByteArray designatedLine = QByteArrayLiteral(
            "# designated => cdhash H\"0123456789abcdef0123456789abcdef01234567\"\n");
        FakeCodesignRunner runner;
        runner.preparedResults = {success(), success(designatedLine, executableLine), success()};
        bool executableChanged = false;
        runner.onSelfMatch = [&] {
            QFile executable(executablePath);
            const QByteArray appendedBytes = QByteArrayLiteral("changed during verification\n");
            executableChanged = executable.open(QIODevice::Append) &&
                                executable.write(appendedBytes) == appendedBytes.size();
        };

        const auto result = MachServiceIdentityPreviewCli::run(fixture.arguments(), runner);

        QVERIFY(executableChanged);
        QCOMPARE(runner.calls.size(), 3);
        QVERIFY(result.exitCode != 0);
        QVERIFY(result.standardOutput.isEmpty());
        QVERIFY(result.standardError.contains("app_executable_changed_during_preview"));
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
