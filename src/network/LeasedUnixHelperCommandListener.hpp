#pragma once

#include "LeasedHelperHost.hpp"

#include <QString>
#include <QThread>

#include <memory>

namespace interceptor {

enum class HelperListenerServeStatus {
    RequestHandled,
    RequestRejected,
    TimedOut,
    ListenerUnavailable,
    Failed
};

struct HelperListenerServeResult {
    HelperListenerServeStatus status = HelperListenerServeStatus::Failed;
    QString detail;
};

// Bounded local Heartbeat/Stop listener. It creates no Start command path and does not verify app
// signing; LeasedHelperHost and kernel peer credentials perform dispatch authorization. The host
// must outlive the listener. Creation duplicates trustedDirectoryFd, so callers may close their fd
// afterward. serveOne() and close() must run on the creating thread; destruction must also happen
// there. close() is idempotent; wrong-thread calls fail closed, while same-thread calls during
// serveOne() defer cleanup until that call returns. The caller must close the listener when
// destroying the host. It closes automatically once host state is Idle and remains available for
// Stop retries while host cleanup is pending. State getters are creating-thread-only.
class LeasedUnixHelperCommandListener final {
  public:
    static constexpr int maximumWaitMs = 1000;
    static constexpr int listenBacklog = 4;
    static constexpr auto socketBasename = "llm_interceptor.helper.sock";

    static std::unique_ptr<LeasedUnixHelperCommandListener> create(const QString &socketPath,
                                                                   int trustedDirectoryFd,
                                                                   LeasedHelperHost &host,
                                                                   QString *error = nullptr);

    LeasedUnixHelperCommandListener(const LeasedUnixHelperCommandListener &) = delete;
    LeasedUnixHelperCommandListener &operator=(const LeasedUnixHelperCommandListener &) = delete;
    ~LeasedUnixHelperCommandListener();

    HelperListenerServeResult serveOne(int timeoutMs = 0);
    // Idempotent. A wrong-thread or reentrant call is ignored; destroy on the creating thread.
    void close() noexcept;
    bool isListening() const noexcept {
        return QThread::currentThreadId() == ownerThreadId_ && listenerFd_ >= 0;
    }
    QString socketPath() const { return socketPath_; }

  private:
    LeasedUnixHelperCommandListener(int listenerFd, int directoryFd, QString socketPath,
                                    quint64 device, quint64 inode, LeasedHelperHost &host);

    int listenerFd_ = -1;
    int directoryFd_ = -1;
    QString socketPath_;
    quint64 device_ = 0;
    quint64 inode_ = 0;
    LeasedHelperHost &host_;
    Qt::HANDLE ownerThreadId_ = nullptr;
    bool serving_ = false;
    bool closeAfterServe_ = false;
};

} // namespace interceptor
