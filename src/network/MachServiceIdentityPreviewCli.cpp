#include "MachServiceIdentityPreviewCli.hpp"

#include <QCommandLineParser>
#include <QElapsedTimer>
#include <QFileInfo>
#include <QProcess>
#include <QRegularExpression>
#include <sys/stat.h>
#include <utility>

namespace interceptor {
namespace {
constexpr int commandTimeoutMs = 5000;
constexpr qsizetype maximumOutputBytes = 16 * 1024;
const QString codesignPath = QStringLiteral("/usr/bin/codesign");

CodesignCommandResult failure(int code, const QString &message) {
    CodesignCommandResult result;
    result.exitCode = code;
    result.standardError = (message + QLatin1Char('\n')).toUtf8();
    return result;
}

class SystemCodesignCommandRunner final : public CodesignCommandRunner {
  public:
    CodesignCommandResult run(const QStringList &arguments, int timeoutMs,
                              qsizetype outputLimitBytes) override {
        QProcess process;
        process.setProgram(codesignPath);
        process.setArguments(arguments);
        process.setProcessChannelMode(QProcess::SeparateChannels);
        process.start();
        if (!process.waitForStarted(timeoutMs))
            return {false, false, false, -1, {}, {}};

        QByteArray out;
        QByteArray err;
        QElapsedTimer timer;
        timer.start();
        while (process.state() != QProcess::NotRunning) {
            process.waitForReadyRead(25);
            out += process.readAllStandardOutput();
            err += process.readAllStandardError();
            if (out.size() > outputLimitBytes || err.size() > outputLimitBytes) {
                process.kill();
                process.waitForFinished(1000);
                return {true, false, false, -1, {}, {}};
            }
            if (timer.elapsed() >= timeoutMs) {
                process.kill();
                process.waitForFinished(1000);
                return {true, false, true, -1, {}, {}};
            }
        }
        out += process.readAllStandardOutput();
        err += process.readAllStandardError();
        if (out.size() > outputLimitBytes || err.size() > outputLimitBytes)
            return {true, false, false, -1, {}, {}};
        return {true,           process.exitStatus() == QProcess::NormalExit,
                false,          process.exitCode(),
                std::move(out), std::move(err)};
    }
};

bool successful(const CodesignCommandResult &result) {
    return result.started && result.normalExit && !result.timedOut && result.exitCode == 0 &&
           result.standardOutput.size() <= maximumOutputBytes &&
           result.standardError.size() <= maximumOutputBytes;
}

QString canonicalAppPath(const QString &path) {
    const QFileInfo info(path);
    if (!info.exists() || !info.isDir() || info.isSymLink())
        return {};
    const QString canonical = info.canonicalFilePath();
    if (canonical.isEmpty() ||
        QFileInfo(canonical).fileName() != QStringLiteral("llm_interceptor.app"))
        return {};
    const QString contentsPath = canonical + QStringLiteral("/Contents");
    const QString macOsPath = contentsPath + QStringLiteral("/MacOS");
    const QFileInfo contents(contentsPath);
    const QFileInfo macOs(macOsPath);
    const QFileInfo executable(macOsPath + QStringLiteral("/llm_interceptor"));
    if (!contents.isDir() || contents.isSymLink() || !macOs.isDir() || macOs.isSymLink())
        return {};
    if (!executable.exists() || !executable.isFile() || executable.isSymLink())
        return {};
    return canonical;
}

struct ExecutableStamp {
    dev_t device{};
    ino_t inode{};
    off_t size{};
    time_t modified{};
};

bool executableStamp(const QString &appPath, ExecutableStamp *stamp) {
    if (!stamp)
        return false;
    const QByteArray path = (appPath + QStringLiteral("/Contents/MacOS/llm_interceptor")).toUtf8();
    struct stat info{};
    if (::lstat(path.constData(), &info) != 0 || !S_ISREG(info.st_mode))
        return false;
    *stamp = {info.st_dev, info.st_ino, info.st_size, info.st_mtime};
    return true;
}

bool sameExecutableStamp(const QString &appPath, const ExecutableStamp &before) {
    ExecutableStamp after;
    return executableStamp(appPath, &after) && before.device == after.device &&
           before.inode == after.inode && before.size == after.size &&
           before.modified == after.modified;
}

QString cdhashRequirement(const QByteArray &output, const QString &expectedExecutable) {
    if (output.isEmpty() || output.contains('\0'))
        return {};
    const QString text = QString::fromUtf8(output);
    if (text.toUtf8() != output)
        return {};

    // `codesign -d -r-` prints the requirement as a comment after the executable line.
    // Reject other metadata and only accept one literal cdhash designated requirement.
    static const QRegularExpression requirementPattern(
        QStringLiteral("^# designated => cdhash H\\\"([0-9a-fA-F]{40}|[0-9a-fA-F]{64})\\\"$"));
    static const QRegularExpression executablePattern(QStringLiteral("^Executable=(/.+)$"));
    QString requirement;
    bool executableSeen = false;
    const auto lines = text.split(QLatin1Char('\n'), Qt::KeepEmptyParts);
    for (QString line : lines) {
        if (line.endsWith(QLatin1Char('\r')))
            line.chop(1);
        if (line.isEmpty())
            continue;
        const auto match = requirementPattern.match(line);
        if (match.hasMatch()) {
            if (!executableSeen || !requirement.isEmpty())
                return {};
            requirement =
                QStringLiteral("cdhash H\"") + match.captured(1).toLower() + QStringLiteral("\"");
        } else {
            const auto executableMatch = executablePattern.match(line);
            if (!executableMatch.hasMatch() || executableSeen || !requirement.isEmpty() ||
                executableMatch.captured(1) != expectedExecutable)
                return {};
            executableSeen = true;
        }
    }
    return executableSeen ? requirement : QString{};
}

CodesignCommandResult runWithRunner(const QStringList &arguments, CodesignCommandRunner &runner) {
    QCommandLineParser parser;
    parser.setApplicationDescription(
        "Verify a local llm_interceptor.app signature and print a disabled mach-service.conf "
        "proposal. This command never installs or enables a service.");
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addOption({QStringLiteral("app"), QStringLiteral("Path to llm_interceptor.app"),
                      QStringLiteral("path")});
    if (!parser.parse(arguments) || !parser.positionalArguments().isEmpty())
        return failure(2, QStringLiteral("invalid_arguments"));
    if (parser.isSet(QStringLiteral("help")) || parser.isSet(QStringLiteral("help-all")))
        return {true, true, false, 0, parser.helpText().toUtf8(), {}};
    if (parser.isSet(QStringLiteral("version")))
        return {true, true, false, 0, QByteArrayLiteral("0.1.0\n"), {}};
    if (!parser.isSet(QStringLiteral("app")))
        return failure(2, QStringLiteral("app_path_required"));

    const QString appPath = canonicalAppPath(parser.value(QStringLiteral("app")));
    if (appPath.isEmpty())
        return failure(2, QStringLiteral("expected_llm_interceptor_app_bundle"));

#if !defined(Q_OS_MACOS)
    Q_UNUSED(runner);
    return failure(1, QStringLiteral("unsupported_platform"));
#else
    ExecutableStamp before;
    if (!executableStamp(appPath, &before))
        return failure(1, QStringLiteral("app_executable_identity_unavailable"));
    const auto verify = runner.run(
        {QStringLiteral("--verify"), QStringLiteral("--strict"), QStringLiteral("--deep"), appPath},
        commandTimeoutMs, maximumOutputBytes);
    if (!successful(verify))
        return failure(1, verify.timedOut ? QStringLiteral("codesign_verification_timed_out")
                                          : QStringLiteral("codesign_verification_failed"));
    if (!sameExecutableStamp(appPath, before))
        return failure(1, QStringLiteral("app_executable_changed_during_preview"));

    const auto display = runner.run({QStringLiteral("-d"), QStringLiteral("-r-"), appPath},
                                    commandTimeoutMs, maximumOutputBytes);
    if (!display.started || display.timedOut || !display.normalExit || display.exitCode != 0 ||
        display.standardOutput.size() > maximumOutputBytes ||
        display.standardError.size() > maximumOutputBytes)
        return failure(1, display.timedOut ? QStringLiteral("codesign_identity_timed_out")
                                           : QStringLiteral("codesign_identity_unavailable"));
    if (!sameExecutableStamp(appPath, before))
        return failure(1, QStringLiteral("app_executable_changed_during_preview"));

    // `codesign -d -r-` writes its Executable= line to stderr and the
    // designated-requirement comment to stdout. Keep that order for validation.
    QByteArray combined = display.standardError;
    if (!display.standardOutput.isEmpty()) {
        if (!combined.isEmpty())
            combined += '\n';
        combined += display.standardOutput;
    }
    const QString expectedExecutable = appPath + QStringLiteral("/Contents/MacOS/llm_interceptor");
    const QString requirement = cdhashRequirement(combined, expectedExecutable);
    if (requirement.isEmpty())
        return failure(1, QStringLiteral("exact_cdhash_requirement_unavailable"));

    const QString proposal =
        QStringLiteral("enabled=false\npeer-code-requirement=%1\n").arg(requirement);
    return {true, true, false, 0, proposal.toUtf8(), {}};
#endif
}
} // namespace

CodesignCommandResult MachServiceIdentityPreviewCli::run(const QStringList &arguments) {
    SystemCodesignCommandRunner runner;
    return runWithRunner(arguments, runner);
}

CodesignCommandResult MachServiceIdentityPreviewCli::run(const QStringList &arguments,
                                                         CodesignCommandRunner &runner) {
    return runWithRunner(arguments, runner);
}

} // namespace interceptor
