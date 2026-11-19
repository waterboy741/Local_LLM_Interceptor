#include "PosixSpawnTypedCommandProcess.hpp"

#include <chrono>

#include <algorithm>

namespace interceptor {
namespace {

std::string toCommandLineValue(const QString &text) {
    const QByteArray encoded = text.toUtf8();
    return std::string(encoded.constData(), static_cast<std::size_t>(encoded.size()));
}

std::vector<std::string> toArgumentVector(const QStringList &arguments) {
    std::vector<std::string> result;
    result.reserve(static_cast<std::size_t>(arguments.size()));
    for (const auto &argument : arguments)
        result.push_back(toCommandLineValue(argument));
    return result;
}

qsizetype boundedBytes(qsizetype maximumBytes) { return maximumBytes < 0 ? 0 : maximumBytes; }

std::size_t boundedChunk(qsizetype maximumBytes) {
    return static_cast<std::size_t>(std::min<qsizetype>(
        boundedBytes(maximumBytes), PosixSpawnChildProcess::maximumOutputBytes));
}

QByteArray toByteArray(const std::string &text) {
    return QByteArray(text.data(), static_cast<qsizetype>(text.size()));
}

} // namespace

PfAnchorPosixSpawnChild::PfAnchorPosixSpawnChild(const PfAnchorCommand &command)
    : program_(toCommandLineValue(command.program())),
      arguments_(toArgumentVector(command.arguments())),
      standardInput_(command.standardInput().constData(),
                     static_cast<std::size_t>(command.standardInput().size())) {}

bool PfAnchorPosixSpawnChild::start(int timeoutMs) {
    if (timeoutMs <= 0)
        return false;
    if (!engine_.start(program_, arguments_))
        return false;
    if (standardInput_.empty())
        engine_.closeWrite();
    return true;
}

bool PfAnchorPosixSpawnChild::started() const { return engine_.started(); }

qint64 PfAnchorPosixSpawnChild::write(const char *data, qint64 length) {
    if (length <= 0)
        return 0;
    return static_cast<qint64>(engine_.write(data, static_cast<std::size_t>(length)));
}

qint64 PfAnchorPosixSpawnChild::bytesToWrite() const {
    return static_cast<qint64>(engine_.bytesPending());
}

bool PfAnchorPosixSpawnChild::waitForBytesWritten(int timeoutMs) {
    return engine_.waitForBytesFlushed(timeoutMs);
}

void PfAnchorPosixSpawnChild::closeWriteChannel() { engine_.closeWrite(); }

bool PfAnchorPosixSpawnChild::waitForReadyRead(int timeoutMs) {
    return engine_.waitForReadable(timeoutMs);
}

QByteArray PfAnchorPosixSpawnChild::readStandardOutput(qint64 maximumBytes) {
    return toByteArray(engine_.readStandardOutput(boundedChunk(maximumBytes)));
}

QByteArray PfAnchorPosixSpawnChild::readStandardError(qint64 maximumBytes) {
    return toByteArray(engine_.readStandardError(boundedChunk(maximumBytes)));
}

bool PfAnchorPosixSpawnChild::isRunning() const { return engine_.isRunning(); }
bool PfAnchorPosixSpawnChild::normalExit() const { return engine_.normalExit(); }
int PfAnchorPosixSpawnChild::exitCode() const { return engine_.exitCode(); }
bool PfAnchorPosixSpawnChild::failed() const {
    return engine_.spawnFailed() || engine_.writeBroken() || engine_.exitedBySignal();
}
void PfAnchorPosixSpawnChild::kill() { engine_.kill(); }
bool PfAnchorPosixSpawnChild::waitForFinished(int timeoutMs) {
    return engine_.waitForFinished(timeoutMs);
}

std::unique_ptr<PfAnchorChildProcess>
PfAnchorPosixSpawnChildFactory::create(const PfAnchorCommand &command) {
#if defined(Q_OS_MACOS)
    return std::make_unique<PfAnchorPosixSpawnChild>(command);
#else
    (void)command;
    return {};
#endif
}

PfEnableReferencePosixSpawnChild::PfEnableReferencePosixSpawnChild(
    const PfEnableReferenceCommand &command)
    : program_(toCommandLineValue(command.program())),
      arguments_(toArgumentVector(command.arguments())) {}

bool PfEnableReferencePosixSpawnChild::start(int timeoutMs) {
    if (timeoutMs <= 0)
        return false;
    if (!engine_.start(program_, arguments_))
        return false;
    engine_.closeWrite();
    return true;
}

bool PfEnableReferencePosixSpawnChild::started() const { return engine_.started(); }
void PfEnableReferencePosixSpawnChild::closeWriteChannel() { engine_.closeWrite(); }
bool PfEnableReferencePosixSpawnChild::waitForReadyRead(int timeoutMs) {
    return engine_.waitForReadable(timeoutMs);
}

QByteArray PfEnableReferencePosixSpawnChild::readStandardOutput(qint64 maximumBytes) {
    return toByteArray(engine_.readStandardOutput(boundedChunk(maximumBytes)));
}

QByteArray PfEnableReferencePosixSpawnChild::readStandardError(qint64 maximumBytes) {
    return toByteArray(engine_.readStandardError(boundedChunk(maximumBytes)));
}

bool PfEnableReferencePosixSpawnChild::isRunning() const { return engine_.isRunning(); }
bool PfEnableReferencePosixSpawnChild::normalExit() const { return engine_.normalExit(); }
int PfEnableReferencePosixSpawnChild::exitCode() const { return engine_.exitCode(); }
bool PfEnableReferencePosixSpawnChild::failed() const {
    return engine_.spawnFailed() || engine_.writeBroken() || engine_.exitedBySignal();
}
void PfEnableReferencePosixSpawnChild::kill() { engine_.kill(); }
bool PfEnableReferencePosixSpawnChild::waitForFinished(int timeoutMs) {
    return engine_.waitForFinished(timeoutMs);
}

std::unique_ptr<PfEnableReferenceChildProcess>
PfEnableReferencePosixSpawnChildFactory::create(const PfEnableReferenceCommand &command) {
#if defined(Q_OS_MACOS)
    return std::make_unique<PfEnableReferencePosixSpawnChild>(command);
#else
    (void)command;
    return {};
#endif
}

bool PfctlPosixSpawnEnableTokenVerifier::parseActiveToken(const QByteArray &output, quint64 token) {
    // A line that names the reference and contains the token's exact decimal value reports the
    // reference active. A false positive only repeats cleanup elsewhere; a slipped-through
    // active reference stays visible through the journal, so matching is kept broad for Active.
    for (const auto &rawLine : output.split('\n')) {
        const auto line = QByteArray(rawLine).trimmed().toLower();
        if (!line.contains("token"))
            continue;
        int index = 0;
        while (index < line.size()) {
            const char character = line.at(index);
            if (character < '0' || character > '9') {
                ++index;
                continue;
            }
            int end = index;
            while (end < line.size() && line.at(end) >= '0' && line.at(end) <= '9')
                ++end;
            bool valid = false;
            const quint64 value = line.mid(index, end - index).toULongLong(&valid);
            if (valid && value == token)
                return true;
            index = end;
        }
    }
    return false;
}

bool PfctlPosixSpawnEnableTokenVerifier::parseEmptyReferenceTable(const QByteArray &output) {
    // Absent requires a recognized, fully empty reference table; any unrecognized nonempty line
    // keeps the state Unknown so the cleanup obligation is never cleared on hope.
    bool recognized = false;
    for (const auto &rawLine : output.split('\n')) {
        const auto line = QByteArray(rawLine).trimmed();
        if (line.isEmpty())
            continue;
        const auto lower = QByteArray(line).toLower();
        if (lower == "no references" || lower == "references: 0" || lower == "refs: 0") {
            recognized = true;
            continue;
        }
        return false;
    }
    return recognized;
}

PfEnableReferenceTokenState PfctlPosixSpawnEnableTokenVerifier::verifyToken(quint64 token) {
    if (token == 0)
        return PfEnableReferenceTokenState::Unknown;
    PosixSpawnChildProcess engine;
    if (!engine.start("/sbin/pfctl", {"-s", "References"}))
        return PfEnableReferenceTokenState::Unknown;
    engine.closeWrite();

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(commandTimeoutMs);
    QByteArray collected;
    for (;;) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                                   deadline - std::chrono::steady_clock::now())
                                   .count();
        const int waitMs = remaining < 0 ? 0 : static_cast<int>(remaining);
        if (collected.size() > maximumOutputBytes)
            return PfEnableReferenceTokenState::Unknown;
        if (!engine.waitForReadable(waitMs))
            break;
        const std::size_t remainingBytes =
            collected.size() >= maximumOutputBytes
                ? 0
                : static_cast<std::size_t>(maximumOutputBytes - collected.size());
        collected += toByteArray(engine.readStandardOutput(remainingBytes));
        collected += toByteArray(engine.readStandardError(
            remainingBytes > static_cast<std::size_t>(collected.size())
                ? remainingBytes - static_cast<std::size_t>(collected.size())
                : 0));
    }
    if (!engine.waitForFinished(reapTimeoutMs) || !engine.normalExit() || engine.exitCode() != 0)
        return PfEnableReferenceTokenState::Unknown;
    if (parseActiveToken(collected, token))
        return PfEnableReferenceTokenState::Active;
    if (parseEmptyReferenceTable(collected))
        return PfEnableReferenceTokenState::Absent;
    return PfEnableReferenceTokenState::Unknown;
}

} // namespace interceptor
