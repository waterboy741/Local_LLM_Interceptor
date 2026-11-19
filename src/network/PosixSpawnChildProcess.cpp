#include "PosixSpawnChildProcess.hpp"

#include <cerrno>
#include <chrono>
#include <cstring>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

namespace interceptor {
namespace {

int remainingDeadlineMs(std::chrono::steady_clock::time_point started, int timeoutMs) {
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    const auto remaining = static_cast<std::int64_t>(timeoutMs) - elapsed.count();
    return remaining < 0
               ? 0
               : (remaining > static_cast<std::int64_t>(timeoutMs) ? timeoutMs
                                                                   : static_cast<int>(remaining));
}

void setNonBlocking(int descriptor) { (void)::fcntl(descriptor, F_SETFL, O_NONBLOCK); }

} // namespace

PosixSpawnChildProcess::PosixSpawnChildProcess() = default;

PosixSpawnChildProcess::~PosixSpawnChildProcess() {
    if (started_ && !reaped_) {
        (void)::kill(static_cast<pid_t>(pid_), SIGKILL);
        for (;;) {
            const pid_t reaped = ::waitpid(static_cast<pid_t>(pid_), &waitStatus_, 0);
            if (reaped == static_cast<pid_t>(pid_) || (reaped < 0 && errno != EINTR))
                break;
        }
        reaped_ = true;
    }
    closeParentEnds();
}

void PosixSpawnChildProcess::closeParentEnds() noexcept {
    for (int *descriptor : {&stdinWrite_, &stdoutRead_, &stderrRead_}) {
        if (*descriptor >= 0) {
            (void)::close(*descriptor);
            *descriptor = -1;
        }
    }
}

bool PosixSpawnChildProcess::start(const std::string &program,
                                   const std::vector<std::string> &arguments) {
    if (started_ || spawnFailed_)
        return false;
    if (program.empty() || program.find('\0') != std::string::npos ||
        program.find('/') == std::string::npos)
        return false;
    for (const auto &argument : arguments) {
        if (argument.find('\0') != std::string::npos)
            return false;
    }

    int stdinPipe[2] = {-1, -1}, stdoutPipe[2] = {-1, -1}, stderrPipe[2] = {-1, -1};
    const auto closePipes = [&]() {
        for (const auto descriptor : {stdinPipe[0], stdinPipe[1], stdoutPipe[0], stdoutPipe[1],
                                      stderrPipe[0], stderrPipe[1]}) {
            if (descriptor >= 0)
                (void)::close(descriptor);
        }
    };
    if (::pipe2(stdinPipe, O_CLOEXEC) != 0 || ::pipe2(stdoutPipe, O_CLOEXEC) != 0 ||
        ::pipe2(stderrPipe, O_CLOEXEC) != 0) {
        closePipes();
        spawnFailed_ = true;
        return false;
    }

    posix_spawn_file_actions_t actions;
    if (::posix_spawn_file_actions_init(&actions) != 0) {
        closePipes();
        spawnFailed_ = true;
        return false;
    }

    posix_spawnattr_t attributes;
    ::posix_spawnattr_init(&attributes);
#if defined(__APPLE__)
    // The child starts with every descriptor closed except the three standard descriptors.
    (void)::posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT);
#endif

    bool ok = ::posix_spawn_file_actions_adddup2(&actions, stdinPipe[0], STDIN_FILENO) == 0 &&
              ::posix_spawn_file_actions_adddup2(&actions, stdoutPipe[1], STDOUT_FILENO) == 0 &&
              ::posix_spawn_file_actions_adddup2(&actions, stderrPipe[1], STDERR_FILENO) == 0;

    // argv[0] is the program; every caller argument is passed through verbatim in order.
    std::vector<std::vector<char>> argumentStorage;
    std::vector<char *> argumentPointers;
    if (ok) {
        argumentStorage.reserve(arguments.size() + 1);
        argumentPointers.reserve(arguments.size() + 2);
        const auto emitEntry = [&argumentStorage, &argumentPointers](const std::string &text) {
            argumentStorage.emplace_back(text.begin(), text.end());
            argumentStorage.back().push_back('\0');
            argumentPointers.push_back(argumentStorage.back().data());
        };
        emitEntry(program);
        for (const auto &argument : arguments)
            emitEntry(argument);
        argumentPointers.push_back(nullptr);
    }

    pid_t spawnedPid = -1;
    const int spawnResult = ok ? ::posix_spawn(&spawnedPid, program.c_str(), &actions, &attributes,
                                               argumentPointers.data(), environ)
                               : -1;
    (void)::posix_spawnattr_destroy(&attributes);
    (void)::posix_spawn_file_actions_destroy(&actions);
    for (const auto descriptor : {stdinPipe[0], stdoutPipe[1], stderrPipe[1]}) {
        if (descriptor >= 0)
            (void)::close(descriptor);
    }
    if (spawnResult != 0) {
        (void)::close(stdinPipe[1]);
        (void)::close(stdoutPipe[0]);
        (void)::close(stderrPipe[0]);
        spawnFailed_ = true;
        return false;
    }

    pid_ = static_cast<long>(spawnedPid);
    stdinWrite_ = stdinPipe[1];
    stdoutRead_ = stdoutPipe[0];
    stderrRead_ = stderrPipe[0];
    setNonBlocking(stdinWrite_);
    setNonBlocking(stdoutRead_);
    setNonBlocking(stderrRead_);
    started_ = true;
    return true;
}

std::size_t PosixSpawnChildProcess::write(const char *data, std::size_t length) {
    if (writeBroken_)
        return 0;
    const std::size_t capacity =
        stdinPending_.size() >= maximumStdinBytes ? 0 : maximumStdinBytes - stdinPending_.size();
    const std::size_t accepted = length < capacity ? length : capacity;
    stdinPending_.append(data, accepted);
    if (accepted < length || !stdinPending_.empty()) {
        // opportunistic flush keeps small commands single-pass
        (void)waitForBytesFlushed(0);
    }
    return accepted;
}

bool PosixSpawnChildProcess::waitForBytesFlushed(int timeoutMs) {
    if (writeBroken_)
        return false;
    if (timeoutMs < 0)
        timeoutMs = 0;
    const auto started = std::chrono::steady_clock::now();
    for (;;) {
        if (stdinPending_.empty())
            return true;
        if (writeClosed_) {
            // The caller closed the channel while data is pending; it can no longer flush.
            stdinPending_.clear();
            return false;
        }
        const int remaining = remainingDeadlineMs(started, timeoutMs);
        pollfd descriptor{stdinWrite_, POLLOUT, 0};
        const int polled = ::poll(&descriptor, 1, remaining);
        if (polled < 0) {
            if (errno == EINTR)
                continue;
            writeBroken_ = true;
            stdinPending_.clear();
            return false;
        }
        if (polled == 0)
            return false; // deadline reached with bytes pending
        if ((descriptor.revents & (POLLERR | POLLHUP)) != 0) {
            writeBroken_ = true;
            stdinPending_.clear();
            (void)::close(stdinWrite_);
            stdinWrite_ = -1;
            return false;
        }
        const auto chunk = stdinPending_.size() > 4096 ? std::size_t{4096} : stdinPending_.size();
        const ssize_t written = ::write(stdinWrite_, stdinPending_.data(), chunk);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            writeBroken_ = true;
            stdinPending_.clear();
            (void)::close(stdinWrite_);
            stdinWrite_ = -1;
            return false;
        }
        stdinPending_.erase(0, static_cast<std::size_t>(written));
    }
}

void PosixSpawnChildProcess::closeWrite() {
    if (stdinWrite_ >= 0) {
        (void)::close(stdinWrite_);
        stdinWrite_ = -1;
    }
    writeClosed_ = true;
}

void PosixSpawnChildProcess::pullStream(int descriptor, std::string &buffer, bool &eof) {
    if (descriptor < 0 || eof)
        return;
    if (capturedBytes_ >= maximumOutputBytes) {
        eof = true; // refuse unbounded capture; the caller reports its own output limit
        return;
    }
    char fragment[4096];
    for (;;) {
        const std::size_t capacity = maximumOutputBytes - capturedBytes_ < sizeof(fragment)
                                         ? maximumOutputBytes - capturedBytes_
                                         : sizeof(fragment);
        if (capacity == 0) {
            eof = true;
            return;
        }
        const ssize_t received = ::read(descriptor, fragment, capacity);
        if (received > 0) {
            buffer.append(fragment, static_cast<std::size_t>(received));
            capturedBytes_ += static_cast<std::size_t>(received);
            continue;
        }
        if (received == 0) {
            eof = true;
            return;
        }
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;
        eof = true;
        return;
    }
}

void PosixSpawnChildProcess::drainStreams() {
    pullStream(stdoutRead_, stdoutBuffer_, stdoutEof_);
    pullStream(stderrRead_, stderrBuffer_, stderrEof_);
}

bool PosixSpawnChildProcess::waitForReadable(int timeoutMs) {
    if (stdoutRead_ < 0 && stderrRead_ < 0)
        return false;
    if (timeoutMs < 0)
        timeoutMs = 0;
    const auto started = std::chrono::steady_clock::now();
    for (;;) {
        if (!stdoutBuffer_.empty() || !stderrBuffer_.empty())
            return true;
        if ((stdoutEof_ && stderrEof_) || reaped_)
            return false;
        pollfd descriptors[2] = {{stdoutRead_, POLLIN, 0}, {stderrRead_, POLLIN, 0}};
        const int polled = ::poll(descriptors, 2, remainingDeadlineMs(started, timeoutMs));
        if (polled < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (polled == 0)
            return false;
        if ((descriptors[0].revents & (POLLIN | POLLHUP)) != 0)
            pullStream(stdoutRead_, stdoutBuffer_, stdoutEof_);
        if ((descriptors[1].revents & (POLLIN | POLLHUP)) != 0)
            pullStream(stderrRead_, stderrBuffer_, stderrEof_);
        if (!stdoutBuffer_.empty() || !stderrBuffer_.empty())
            return true;
        if ((descriptors[0].revents | descriptors[1].revents) & (POLLERR | POLLHUP)) {
            (void)pollChild();
            if (reaped_)
                return false;
        }
    }
}

std::string PosixSpawnChildProcess::readStandardOutput(std::size_t maximumBytes) {
    drainStreams();
    const std::size_t count =
        maximumBytes < stdoutBuffer_.size() ? maximumBytes : stdoutBuffer_.size();
    std::string chunk = stdoutBuffer_.substr(0, count);
    stdoutBuffer_.erase(0, count);
    return chunk;
}

std::string PosixSpawnChildProcess::readStandardError(std::size_t maximumBytes) {
    drainStreams();
    const std::size_t count =
        maximumBytes < stderrBuffer_.size() ? maximumBytes : stderrBuffer_.size();
    std::string chunk = stderrBuffer_.substr(0, count);
    stderrBuffer_.erase(0, count);
    return chunk;
}

bool PosixSpawnChildProcess::pollChild() {
    if (reaped_ || !started_)
        return reaped_;
    int status = 0;
    const pid_t result = ::waitpid(static_cast<pid_t>(pid_), &status, WNOHANG);
    if (result == static_cast<pid_t>(pid_)) {
        waitStatus_ = status;
        reaped_ = true;
        return true;
    }
    if (result < 0 && errno != EINTR)
        reaped_ = true; // lost child; treat as failed rather than loop forever
    return reaped_;
}

bool PosixSpawnChildProcess::isRunning() {
    if (reaped_ || !started_)
        return false;
    drainStreams();
    (void)pollChild();
    return !reaped_;
}

bool PosixSpawnChildProcess::normalExit() const noexcept {
    return reaped_ && WIFEXITED(waitStatus_);
}

int PosixSpawnChildProcess::exitCode() const noexcept {
    return reaped_ && WIFEXITED(waitStatus_) ? WEXITSTATUS(waitStatus_) : -1;
}

bool PosixSpawnChildProcess::exitedBySignal() const noexcept {
    return reaped_ && WIFSIGNALED(waitStatus_);
}

void PosixSpawnChildProcess::kill() {
    if (started_ && !reaped_)
        (void)::kill(static_cast<pid_t>(pid_), SIGKILL);
}

bool PosixSpawnChildProcess::waitForFinished(int timeoutMs) {
    if (!started_)
        return false;
    if (timeoutMs < 0)
        timeoutMs = 0;
    const auto started = std::chrono::steady_clock::now();
    for (;;) {
        drainStreams();
        if (pollChild())
            return true;
        const int remaining = remainingDeadlineMs(started, timeoutMs);
        if ((stdoutEof_ && stderrEof_) || (stdoutRead_ < 0 && stderrRead_ < 0)) {
            // Nothing left to drain: a bounded yield before the next reap attempt avoids a
            // tight poll spin (poll would return immediately on the closed pipes).
            if (remaining == 0)
                return false;
            ::usleep(static_cast<useconds_t>(remaining < 5 ? remaining : 5) * 1000);
            continue;
        }
        pollfd descriptors[2] = {{stdoutRead_, POLLIN, 0}, {stderrRead_, POLLIN, 0}};
        const int polled = ::poll(descriptors, 2, remaining < 5 ? remaining : 5);
        if (polled < 0 && errno != EINTR)
            return pollChild();
        if (remainingDeadlineMs(started, timeoutMs) == 0 && pollChild())
            return true;
        if (remainingDeadlineMs(started, timeoutMs) == 0)
            return false;
    }
}

} // namespace interceptor
