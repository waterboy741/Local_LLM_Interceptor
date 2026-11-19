#pragma once

#include "PfAnchorQProcessRunner.hpp"
#include "PfEnableReferenceJournal.hpp"
#include "PfEnableReferenceQProcessRunner.hpp"
#include "PosixSpawnChildProcess.hpp"

#include <memory>
#include <string>
#include <vector>

namespace interceptor {

// Adapters that back the typed PF command child-process seams with the Qt-free
// PosixSpawnChildProcess engine, so a system-library-only helper could execute the same bounded
// typed commands without QProcess. The existing runner/operation/coordinator layers and their
// execute loops are reused unchanged; only this child factory differs.
class PfAnchorPosixSpawnChild final : public PfAnchorChildProcess {
  public:
    explicit PfAnchorPosixSpawnChild(const PfAnchorCommand &command);

    bool start(int timeoutMs) override;
    bool started() const override;
    qint64 write(const char *data, qint64 length) override;
    qint64 bytesToWrite() const override;
    bool waitForBytesWritten(int timeoutMs) override;
    void closeWriteChannel() override;
    bool waitForReadyRead(int timeoutMs) override;
    QByteArray readStandardOutput(qint64 maximumBytes) override;
    QByteArray readStandardError(qint64 maximumBytes) override;
    bool isRunning() const override;
    bool normalExit() const override;
    int exitCode() const override;
    bool failed() const override;
    void kill() override;
    bool waitForFinished(int timeoutMs) override;

  private:
    std::string program_;
    std::vector<std::string> arguments_;
    std::string standardInput_;
    mutable PosixSpawnChildProcess engine_;
};

class PfAnchorPosixSpawnChildFactory final : public PfAnchorChildProcessFactory {
  public:
    std::unique_ptr<PfAnchorChildProcess> create(const PfAnchorCommand &command) override;
};

class PfEnableReferencePosixSpawnChild final : public PfEnableReferenceChildProcess {
  public:
    explicit PfEnableReferencePosixSpawnChild(const PfEnableReferenceCommand &command);

    bool start(int timeoutMs) override;
    bool started() const override;
    void closeWriteChannel() override;
    bool waitForReadyRead(int timeoutMs) override;
    QByteArray readStandardOutput(qint64 maximumBytes) override;
    QByteArray readStandardError(qint64 maximumBytes) override;
    bool isRunning() const override;
    bool normalExit() const override;
    int exitCode() const override;
    bool failed() const override;
    void kill() override;
    bool waitForFinished(int timeoutMs) override;

  private:
    std::string program_;
    std::vector<std::string> arguments_;
    mutable PosixSpawnChildProcess engine_;
};

class PfEnableReferencePosixSpawnChildFactory final : public PfEnableReferenceChildProcessFactory {
  public:
    std::unique_ptr<PfEnableReferenceChildProcess>
    create(const PfEnableReferenceCommand &command) override;
};

// Read-only `pfctl -s References` token check for the enable-reference journal. It runs the
// bounded spawn engine directly (no QProcess, no PATH search, fixed /sbin/pfctl argv). An
// exactly matching active token number reports Active; a recognized empty reference table
// reports Absent; anything else (nonzero exit, unknown output shape, over-limit output, or
// output that is neither recognized shape) is Unknown, so a journal cleanup obligation is
// retained fail-closed instead of cleared on hope.
class PfctlPosixSpawnEnableTokenVerifier final : public PfEnableReferenceTokenVerifier {
  public:
    static constexpr int commandTimeoutMs = 3000;
    static constexpr int reapTimeoutMs = 1000;
    static constexpr qsizetype maximumOutputBytes = 4096;

    PfEnableReferenceTokenState verifyToken(quint64 token) override;

    static bool parseActiveToken(const QByteArray &output, quint64 token);
    static bool parseEmptyReferenceTable(const QByteArray &output);
};

} // namespace interceptor
