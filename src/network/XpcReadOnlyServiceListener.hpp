#pragma once

#include "XpcControlRequestGate.hpp"

#include <dispatch/dispatch.h>
#include <xpc/xpc.h>

#include <QByteArray>
#include <QString>

#include <atomic>
#include <memory>
#include <vector>

namespace interceptor {

// Creates only fixed, bounded replies to authenticated probe/status requests.
// The returned XPC object is retained (+1) for the caller; rejected requests
// receive no reply.
class XpcReadOnlyControlAdapter final {
  public:
    explicit XpcReadOnlyControlAdapter(XpcControlRequestGate &gate);

    bool isConfigured() const;
    static xpc_object_t createBoundedReplyPayload(XpcControlOperation operation);
    xpc_object_t handleMessage(xpc_object_t message) const;

  private:
    XpcControlRequestGate &gate_;
};

// Native launchd Mach-service listener foundation. The service name must
// already be installed and bound by a trusted launchd configuration. This
// class never installs a plist or registers a service itself.
class XpcReadOnlyServiceListener final {
  public:
    XpcReadOnlyServiceListener(QByteArray serviceName, XpcReadOnlyControlAdapter &adapter);
    ~XpcReadOnlyServiceListener();

    XpcReadOnlyServiceListener(const XpcReadOnlyServiceListener &) = delete;
    XpcReadOnlyServiceListener &operator=(const XpcReadOnlyServiceListener &) = delete;

    bool start(QString *error = nullptr);
    void stop();
    bool isRunning() const;

  private:
    friend class M6XpcReadOnlyServiceListenerTestAccess;

    struct CallbackGuard;
    struct PeerConnection {
        xpc_connection_t connection = nullptr;
        size_t messageCount = 0;
    };

    void acceptConnection(xpc_connection_t connection);
    void handleEvent(xpc_connection_t connection, xpc_object_t event);
    // Test-only seam. Consumes the listener's +1 reference on every path.
    bool startWithAnonymousListenerForTesting(xpc_connection_t listener, QString *error);
    void installListenerOnQueue();
    void stopOnQueue();

    const QByteArray serviceName_;
    XpcReadOnlyControlAdapter &adapter_;
    dispatch_queue_t queue_ = nullptr;
    xpc_connection_t listener_ = nullptr;
    std::vector<PeerConnection> peers_;
    std::shared_ptr<CallbackGuard> callbackGuard_;
    size_t peersAccepted_ = 0;
    size_t messagesReceived_ = 0;
    bool running_ = false;
};

} // namespace interceptor
