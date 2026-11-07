#include "LeasedUnixHelperCommandListener.hpp"

#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QThread>

#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstring>

namespace interceptor {
namespace {
constexpr mode_t privateDirectoryMode = 0700;
constexpr mode_t privateSocketMode = 0600;

void setError(QString *error, const QString &value) {
    if (error)
        *error = value;
}

bool privateDirectoryFd(int fd, struct stat *info = nullptr) {
    struct stat local{};
    if (::fstat(fd, &local) != 0 || !S_ISDIR(local.st_mode) || local.st_uid != ::geteuid() ||
        (local.st_mode & 07777) != privateDirectoryMode)
        return false;
    if (info)
        *info = local;
    return true;
}

bool matchingSocketAt(int directoryFd, const char *basename, quint64 device, quint64 inode,
                      struct stat *info = nullptr) {
    struct stat current{};
    if (::fstatat(directoryFd, basename, &current, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISSOCK(current.st_mode) || current.st_uid != ::geteuid() ||
        static_cast<quint64>(current.st_dev) != device ||
        static_cast<quint64>(current.st_ino) != inode)
        return false;
    if (info)
        *info = current;
    return true;
}

void unlinkIfOwned(int directoryFd, const char *basename, quint64 device, quint64 inode) {
    if (matchingSocketAt(directoryFd, basename, device, inode))
        (void)::unlinkat(directoryFd, basename, 0);
}

class ScopedFd final {
  public:
    explicit ScopedFd(int fd = -1) : fd_(fd) {}
    ScopedFd(const ScopedFd &) = delete;
    ScopedFd &operator=(const ScopedFd &) = delete;
    ~ScopedFd() {
        if (fd_ >= 0)
            ::close(fd_);
    }
    int get() const { return fd_; }
    int release() {
        const int result = fd_;
        fd_ = -1;
        return result;
    }

  private:
    int fd_;
};

HelperListenerServeResult serveResult(HelperListenerServeStatus status, QString detail = {}) {
    return {status, std::move(detail)};
}

bool hostCanServe(const LeasedHelperHost &host) {
    const auto state = host.state();
    return state == NetworkSession::State::Active || state == NetworkSession::State::CleanupPending;
}

class StopHostOnFailure final {
  public:
    StopHostOnFailure(LeasedHelperHost &host, QString *error) : host_(host), error_(error) {}
    StopHostOnFailure(const StopHostOnFailure &) = delete;
    StopHostOnFailure &operator=(const StopHostOnFailure &) = delete;

    ~StopHostOnFailure() {
        if (dismissed_ || host_.state() != NetworkSession::State::Active)
            return;
        QString cleanupError;
        if (!host_.stop(&cleanupError) && error_)
            *error_ += QStringLiteral(";cleanup_failed:") + cleanupError;
    }

    void dismiss() { dismissed_ = true; }

  private:
    LeasedHelperHost &host_;
    QString *error_ = nullptr;
    bool dismissed_ = false;
};
} // namespace

LeasedUnixHelperCommandListener::LeasedUnixHelperCommandListener(int listenerFd, int directoryFd,
                                                                 QString socketPath, quint64 device,
                                                                 quint64 inode,
                                                                 LeasedHelperHost &host)
    : listenerFd_(listenerFd), directoryFd_(directoryFd), socketPath_(std::move(socketPath)),
      device_(device), inode_(inode), host_(host), ownerThreadId_(QThread::currentThreadId()) {}

std::unique_ptr<LeasedUnixHelperCommandListener>
LeasedUnixHelperCommandListener::create(const QString &socketPath, int trustedDirectoryFd,
                                        LeasedHelperHost &host, QString *error) {
    if (error)
        error->clear();
    if (host.state() != NetworkSession::State::Active) {
        setError(error, QStringLiteral("active_helper_host_required"));
        return {};
    }
    StopHostOnFailure stopHostOnFailure(host, error);

    struct stat trustedInfo{};
    if (!privateDirectoryFd(trustedDirectoryFd, &trustedInfo)) {
        setError(error, QStringLiteral("trusted_private_directory_required"));
        return {};
    }
    const QFileInfo requested(socketPath);
    if (!requested.isAbsolute() || requested.fileName() != QString::fromLatin1(socketBasename)) {
        setError(error, QStringLiteral("fixed_absolute_socket_path_required"));
        return {};
    }
    const QString canonicalParent = QFileInfo(requested.absolutePath()).canonicalFilePath();
    if (canonicalParent.isEmpty()) {
        setError(error, QStringLiteral("socket_parent_unavailable"));
        return {};
    }
    struct stat parentInfo{};
    const QByteArray parentPathBytes = QFile::encodeName(canonicalParent);
    if (::stat(parentPathBytes.constData(), &parentInfo) != 0 ||
        parentInfo.st_dev != trustedInfo.st_dev || parentInfo.st_ino != trustedInfo.st_ino) {
        setError(error, QStringLiteral("socket_parent_directory_mismatch"));
        return {};
    }
    const QString canonicalSocketPath =
        QDir(canonicalParent).filePath(QString::fromLatin1(socketBasename));
    const QByteArray socketPathBytes = QFile::encodeName(canonicalSocketPath);
    sockaddr_un address{};
    if (socketPathBytes.isEmpty() ||
        socketPathBytes.size() >= static_cast<qsizetype>(sizeof(address.sun_path))) {
        setError(error, QStringLiteral("socket_path_too_long"));
        return {};
    }

    const int directoryDuplicate = ::fcntl(trustedDirectoryFd, F_DUPFD_CLOEXEC, 0);
    if (directoryDuplicate < 0) {
        setError(error, QStringLiteral("socket_directory_duplication_failed"));
        return {};
    }
    ScopedFd directoryGuard(directoryDuplicate);
    struct stat existing{};
    if (::fstatat(directoryDuplicate, socketBasename, &existing, AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT) {
        setError(error, QStringLiteral("socket_path_already_exists"));
        return {};
    }

    ScopedFd listener(::socket(AF_UNIX, SOCK_STREAM, 0));
    if (listener.get() < 0) {
        setError(error, QStringLiteral("socket_creation_failed"));
        return {};
    }
    const int descriptorFlags = ::fcntl(listener.get(), F_GETFD);
    const int statusFlags = ::fcntl(listener.get(), F_GETFL);
    if (descriptorFlags < 0 ||
        ::fcntl(listener.get(), F_SETFD, descriptorFlags | FD_CLOEXEC) != 0 || statusFlags < 0 ||
        ::fcntl(listener.get(), F_SETFL, statusFlags | O_NONBLOCK) != 0) {
        setError(error, QStringLiteral("socket_configuration_failed"));
        return {};
    }

    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, socketPathBytes.constData(),
                static_cast<size_t>(socketPathBytes.size()));
    address.sun_path[socketPathBytes.size()] = '\0';
    if (::bind(listener.get(), reinterpret_cast<const sockaddr *>(&address), sizeof(address)) !=
        0) {
        setError(error, QStringLiteral("socket_bind_failed"));
        return {};
    }

    struct stat bound{};
    if (::fstatat(directoryDuplicate, socketBasename, &bound, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISSOCK(bound.st_mode) || bound.st_uid != ::geteuid()) {
        setError(error, QStringLiteral("bound_socket_ownership_unverified"));
        return {};
    }
    const quint64 device = static_cast<quint64>(bound.st_dev);
    const quint64 inode = static_cast<quint64>(bound.st_ino);
    if (::fchmodat(directoryDuplicate, socketBasename, privateSocketMode, AT_SYMLINK_NOFOLLOW) !=
            0 ||
        ::listen(listener.get(), listenBacklog) != 0) {
        unlinkIfOwned(directoryDuplicate, socketBasename, device, inode);
        setError(error, QStringLiteral("socket_permissions_or_listen_failed"));
        return {};
    }
    struct stat verified{};
    struct stat pathInfo{};
    if (!matchingSocketAt(directoryDuplicate, socketBasename, device, inode, &verified) ||
        (verified.st_mode & 07777) != privateSocketMode ||
        ::lstat(socketPathBytes.constData(), &pathInfo) != 0 ||
        pathInfo.st_dev != verified.st_dev || pathInfo.st_ino != verified.st_ino) {
        unlinkIfOwned(directoryDuplicate, socketBasename, device, inode);
        setError(error, QStringLiteral("socket_ownership_verification_failed"));
        return {};
    }

    auto result = std::unique_ptr<LeasedUnixHelperCommandListener>(
        new LeasedUnixHelperCommandListener(listener.release(), directoryGuard.release(),
                                            canonicalSocketPath, device, inode, host));
    stopHostOnFailure.dismiss();
    return result;
}

LeasedUnixHelperCommandListener::~LeasedUnixHelperCommandListener() {
    Q_ASSERT(QThread::currentThreadId() == ownerThreadId_);
    Q_ASSERT(!serving_);
    close();
}

HelperListenerServeResult LeasedUnixHelperCommandListener::serveOne(int timeoutMs) {
    if (QThread::currentThreadId() != ownerThreadId_)
        return serveResult(HelperListenerServeStatus::Failed,
                           QStringLiteral("listener_owner_thread_required"));
    if (listenerFd_ < 0 || serving_)
        return serveResult(HelperListenerServeStatus::ListenerUnavailable,
                           QStringLiteral("listener_unavailable"));
    if (!hostCanServe(host_)) {
        close();
        return serveResult(HelperListenerServeStatus::ListenerUnavailable,
                           QStringLiteral("helper_host_not_active"));
    }
    if (timeoutMs < 0 || timeoutMs > maximumWaitMs)
        return serveResult(HelperListenerServeStatus::Failed,
                           QStringLiteral("timeout_out_of_bounds"));
    serving_ = true;
    const auto resetServing = [this](void *) {
        serving_ = false;
        if (closeAfterServe_ || !hostCanServe(host_)) {
            closeAfterServe_ = false;
            close();
        }
    };
    std::unique_ptr<void, decltype(resetServing)> servingGuard(reinterpret_cast<void *>(1),
                                                               resetServing);

    QElapsedTimer elapsed;
    elapsed.start();
    pollfd descriptor{listenerFd_, POLLIN, 0};
    int pollResult = 0;
    do {
        const int remaining = qMax(0, timeoutMs - static_cast<int>(elapsed.elapsed()));
        pollResult = ::poll(&descriptor, 1, remaining);
    } while (pollResult < 0 && errno == EINTR && elapsed.elapsed() < timeoutMs);
    if (pollResult == 0)
        return serveResult(HelperListenerServeStatus::TimedOut, QStringLiteral("accept_timeout"));
    if (pollResult < 0 || (descriptor.revents & (POLLERR | POLLNVAL)) != 0)
        return serveResult(HelperListenerServeStatus::Failed,
                           QStringLiteral("listener_poll_failed"));
    if ((descriptor.revents & POLLIN) == 0)
        return serveResult(HelperListenerServeStatus::TimedOut, QStringLiteral("accept_timeout"));

    const int acceptedFd = ::accept(listenerFd_, nullptr, nullptr);
    if (acceptedFd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return serveResult(HelperListenerServeStatus::TimedOut,
                               QStringLiteral("no_pending_client"));
        return serveResult(HelperListenerServeStatus::Failed, QStringLiteral("accept_failed"));
    }
    ScopedFd accepted(acceptedFd);
    const int acceptedFlags = ::fcntl(acceptedFd, F_GETFD);
    if (acceptedFlags < 0 || ::fcntl(acceptedFd, F_SETFD, acceptedFlags | FD_CLOEXEC) != 0)
        return serveResult(HelperListenerServeStatus::Failed,
                           QStringLiteral("accepted_socket_configuration_failed"));

    QString dispatchError;
    bool handled = false;
    try {
        handled = host_.dispatchOne(acceptedFd, &dispatchError);
    } catch (...) {
        closeAfterServe_ = true;
        return serveResult(HelperListenerServeStatus::Failed,
                           QStringLiteral("helper_dispatch_exception"));
    }
    if (!hostCanServe(host_))
        closeAfterServe_ = true;
    return handled ? serveResult(HelperListenerServeStatus::RequestHandled)
                   : serveResult(HelperListenerServeStatus::RequestRejected, dispatchError);
}

void LeasedUnixHelperCommandListener::close() noexcept {
    if (QThread::currentThreadId() != ownerThreadId_)
        return;
    if (serving_) {
        closeAfterServe_ = true;
        return;
    }
    if (listenerFd_ >= 0) {
        ::close(listenerFd_);
        listenerFd_ = -1;
    }
    if (directoryFd_ >= 0) {
        unlinkIfOwned(directoryFd_, socketBasename, device_, inode_);
        ::close(directoryFd_);
        directoryFd_ = -1;
    }
}

} // namespace interceptor
