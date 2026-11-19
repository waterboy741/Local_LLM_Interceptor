#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace interceptor {

// Qt-free, bounded child-process engine for the system-library-only helper. It executes one
// fixed program with an explicit argument vector through posix_spawn (no shell, no PATH search,
// no caller-supplied environment), gives the child only the three standard descriptors, and
// bounds everything: pending stdin at maximumStdinBytes, combined captured output at
// maximumOutputBytes, and every wait at a caller-supplied millisecond deadline. Found defects in
// the child (crash, EPIPE, spawn failure) are reported like the QProcess-backed runners report
// them; a reaped process is never re-waited.
class PosixSpawnChildProcess final {
  public:
    static constexpr std::size_t maximumStdinBytes = 64 * 1024;
    static constexpr std::size_t maximumOutputBytes = 256 * 1024;

    PosixSpawnChildProcess();
    PosixSpawnChildProcess(const PosixSpawnChildProcess &) = delete;
    PosixSpawnChildProcess &operator=(const PosixSpawnChildProcess &) = delete;
    PosixSpawnChildProcess(PosixSpawnChildProcess &&) = delete;
    PosixSpawnChildProcess &operator=(PosixSpawnChildProcess &&) = delete;
    ~PosixSpawnChildProcess();

    // Spawns the program with the exact argument vector (program included). Returns true after
    // a successful spawn; a failed spawn leaves the object reusable-fail (spawnFailed).
    bool start(const std::string &program, const std::vector<std::string> &arguments);
    bool started() const noexcept { return started_; }
    bool spawnFailed() const noexcept { return spawnFailed_; }
    bool writeBroken() const noexcept { return writeBroken_; }

    // Stdin streaming; writing closes once the child's pipe breaks. Accepted bytes are buffered
    // (bounded) and flushed by waitForBytesFlushed; write returns the accepted byte count.
    std::size_t write(const char *data, std::size_t length);
    std::size_t bytesPending() const noexcept { return stdinPending_.size(); }
    bool waitForBytesFlushed(int timeoutMs);
    void closeWrite();

    // True when output bytes are readable or one stream reached end-of-file within the deadline.
    bool waitForReadable(int timeoutMs);
    std::string readStandardOutput(std::size_t maximumBytes);
    std::string readStandardError(std::size_t maximumBytes);

    bool isRunning();
    bool normalExit() const noexcept;
    int exitCode() const noexcept;
    bool exitedBySignal() const noexcept;
    void kill();
    bool waitForFinished(int timeoutMs);

  private:
    void closeParentEnds() noexcept;
    void drainStreams();
    void pullStream(int descriptor, std::string &buffer, bool &eof);
    bool reaped() const noexcept { return reaped_; }
    bool pollChild();

    int stdinWrite_ = -1;
    int stdoutRead_ = -1;
    int stderrRead_ = -1;
    long pid_ = -1;
    int waitStatus_ = 0;
    std::string stdinPending_;
    std::string stdoutBuffer_;
    std::string stderrBuffer_;
    std::size_t capturedBytes_ = 0;
    bool started_ = false;
    bool spawnFailed_ = false;
    bool writeClosed_ = false;
    bool writeBroken_ = false;
    bool stdoutEof_ = false;
    bool stderrEof_ = false;
    bool reaped_ = false;
};

} // namespace interceptor
