#include "XpcReadOnlyServiceListener.hpp"

#include <algorithm>
#include <string>

namespace interceptor {
namespace {
constexpr qsizetype maximumServiceNameLength = 128;
constexpr size_t maximumPeerConnections = 16;
constexpr size_t maximumMessagesPerPeer = 128;
constexpr size_t maximumAcceptedPeers = 256;
constexpr size_t maximumMessagesPerRun = 4096;

bool fail(QString *error, const char *reason) {
    if (error)
        *error = QString::fromLatin1(reason);
    return false;
}

void cancelAndRelease(xpc_connection_t connection) {
    xpc_connection_activate(connection);
    xpc_connection_cancel(connection);
    xpc_release(connection);
}

bool validServiceName(const QByteArray &name) {
    if (name.isEmpty() || name.size() > maximumServiceNameLength || name.startsWith('.') ||
        name.endsWith('.') || !name.contains('.'))
        return false;

    bool previousWasDot = true;
    for (const char value : name) {
        const bool isDot = value == '.';
        const bool isAlphaNumeric = (value >= 'a' && value <= 'z') ||
                                    (value >= 'A' && value <= 'Z') ||
                                    (value >= '0' && value <= '9');
        if (!isDot && value != '-' && !isAlphaNumeric)
            return false;
        if (isDot && previousWasDot)
            return false;
        previousWasDot = isDot;
    }
    return !previousWasDot && !name.contains('\0');
}

} // namespace

struct XpcReadOnlyServiceListener::CallbackGuard {
    std::atomic_bool alive{true};
    XpcReadOnlyServiceListener *owner = nullptr;
};

XpcReadOnlyControlAdapter::XpcReadOnlyControlAdapter(XpcControlRequestGate &gate) : gate_(gate) {}

bool XpcReadOnlyControlAdapter::isConfigured() const { return gate_.isConfigured(); }

xpc_object_t XpcReadOnlyControlAdapter::createBoundedReplyPayload(XpcControlOperation operation) {
    if (operation != XpcControlOperation::Probe && operation != XpcControlOperation::Status)
        return nullptr;
    xpc_object_t reply = xpc_dictionary_create(nullptr, nullptr, 0);
    if (!reply)
        return nullptr;
    xpc_dictionary_set_bool(reply, "ok", true);
    xpc_dictionary_set_string(reply, "service", "llm_interceptor");
    xpc_dictionary_set_uint64(reply, "protocol_version", 1);
    if (operation == XpcControlOperation::Status)
        xpc_dictionary_set_string(reply, "state", "inactive");
    return reply;
}

xpc_object_t XpcReadOnlyControlAdapter::handleMessage(xpc_object_t message) const {
    XpcControlRequest request;
    if (!gate_.parse(message, &request))
        return nullptr;

    xpc_object_t reply = xpc_dictionary_create_reply(message);
    if (!reply)
        return nullptr;
    xpc_object_t payload = createBoundedReplyPayload(request.operation);
    if (!payload) {
        xpc_release(reply);
        return nullptr;
    }
    xpc_dictionary_apply(payload, ^bool(const char *key, xpc_object_t value) {
      xpc_dictionary_set_value(reply, key, value);
      return true;
    });
    xpc_release(payload);
    return reply;
}

XpcReadOnlyServiceListener::XpcReadOnlyServiceListener(QByteArray serviceName,
                                                       XpcReadOnlyControlAdapter &adapter)
    : serviceName_(std::move(serviceName)), adapter_(adapter),
      queue_(
          dispatch_queue_create("org.local-llm-interceptor.xpc-listener", DISPATCH_QUEUE_SERIAL)),
      callbackGuard_(std::make_shared<CallbackGuard>()) {
    callbackGuard_->owner = this;
}

XpcReadOnlyServiceListener::~XpcReadOnlyServiceListener() {
    if (queue_) {
        dispatch_sync(queue_, ^{
          stopOnQueue();
          callbackGuard_->alive.store(false);
          callbackGuard_->owner = nullptr;
        });
        dispatch_release(queue_);
    }
}

bool XpcReadOnlyServiceListener::start(QString *error) {
    if (error)
        error->clear();
    if (!queue_)
        return fail(error, "xpc_listener_create_failed");
    if (!validServiceName(serviceName_))
        return fail(error, "xpc_listener_service_name_invalid");
    if (!adapter_.isConfigured())
        return fail(error, "xpc_listener_trusted_requirement_missing");

    __block bool started = false;
    __block QString startError;
    dispatch_sync(queue_, ^{
      if (running_) {
          started = true;
          return;
      }
      peersAccepted_ = 0;
      messagesReceived_ = 0;

      const std::string service(serviceName_.constData(), static_cast<size_t>(serviceName_.size()));
      listener_ = xpc_connection_create_mach_service(service.c_str(), queue_,
                                                     XPC_CONNECTION_MACH_SERVICE_LISTENER);
      if (!listener_) {
          startError = QStringLiteral("xpc_listener_create_failed");
          return;
      }
      installListenerOnQueue();
      running_ = true;
      started = true;
    });

    if (!started)
        return fail(error, startError.isEmpty() ? "xpc_listener_create_failed"
                                                : startError.toUtf8().constData());
    return true;
}

bool XpcReadOnlyServiceListener::startWithAnonymousListenerForTesting(xpc_connection_t listener,
                                                                      QString *error) {
    if (error)
        error->clear();
    if (!listener)
        return fail(error, "xpc_listener_create_failed");
    if (!queue_) {
        cancelAndRelease(listener);
        return fail(error, "xpc_listener_create_failed");
    }
    if (!validServiceName(serviceName_)) {
        cancelAndRelease(listener);
        return fail(error, "xpc_listener_service_name_invalid");
    }
    if (!adapter_.isConfigured()) {
        cancelAndRelease(listener);
        return fail(error, "xpc_listener_trusted_requirement_missing");
    }

    __block bool started = false;
    dispatch_sync(queue_, ^{
      if (running_) {
          cancelAndRelease(listener);
          started = true;
          return;
      }
      peersAccepted_ = 0;
      messagesReceived_ = 0;
      listener_ = listener;
      installListenerOnQueue();
      running_ = true;
      started = true;
    });
    return started;
}

void XpcReadOnlyServiceListener::installListenerOnQueue() {
    const std::shared_ptr<CallbackGuard> guard = callbackGuard_;
    xpc_connection_set_target_queue(listener_, queue_);
    xpc_connection_set_event_handler(listener_, ^(xpc_object_t event) {
      if (!guard->alive.load() || !guard->owner)
          return;
      if (xpc_get_type(event) == XPC_TYPE_CONNECTION)
          guard->owner->acceptConnection(reinterpret_cast<xpc_connection_t>(event));
      else if (xpc_get_type(event) == XPC_TYPE_ERROR)
          guard->owner->handleEvent(guard->owner->listener_, event);
    });
    xpc_connection_activate(listener_);
}

void XpcReadOnlyServiceListener::stop() {
    if (queue_)
        dispatch_sync(queue_, ^{
          stopOnQueue();
        });
}

bool XpcReadOnlyServiceListener::isRunning() const {
    if (!queue_)
        return false;
    __block bool running = false;
    dispatch_sync(queue_, ^{
      running = running_;
    });
    return running;
}

void XpcReadOnlyServiceListener::acceptConnection(xpc_connection_t connection) {
    if (!connection)
        return;
    if (!running_ || peers_.size() >= maximumPeerConnections ||
        peersAccepted_ >= maximumAcceptedPeers) {
        xpc_connection_cancel(connection);
        if (running_ && peersAccepted_ >= maximumAcceptedPeers)
            stopOnQueue();
        return;
    }
    ++peersAccepted_;
    xpc_retain(connection);
    xpc_connection_set_target_queue(connection, queue_);
    peers_.push_back(PeerConnection{connection, 0});
    const std::shared_ptr<CallbackGuard> guard = callbackGuard_;
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
      if (guard->alive.load() && guard->owner)
          guard->owner->handleEvent(connection, event);
    });
    xpc_connection_activate(connection);
}

void XpcReadOnlyServiceListener::handleEvent(xpc_connection_t connection, xpc_object_t event) {
    if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
        const auto peer =
            std::find_if(peers_.begin(), peers_.end(), [connection](const auto &entry) {
                return entry.connection == connection;
            });
        if (peer == peers_.end())
            return;
        if (peer->messageCount >= maximumMessagesPerPeer ||
            messagesReceived_ >= maximumMessagesPerRun) {
            xpc_connection_cancel(connection);
            xpc_release(peer->connection);
            peers_.erase(peer);
            if (messagesReceived_ >= maximumMessagesPerRun)
                stopOnQueue();
            return;
        }
        ++peer->messageCount;
        ++messagesReceived_;
        xpc_object_t reply = adapter_.handleMessage(event);
        if (reply) {
            xpc_connection_send_message(connection, reply);
            xpc_release(reply);
        }
        return;
    }

    if (xpc_get_type(event) != XPC_TYPE_ERROR)
        return;
    if (connection == listener_) {
        xpc_connection_cancel(listener_);
        xpc_connection_set_event_handler(listener_, ^(xpc_object_t){
                                         });
        xpc_release(listener_);
        listener_ = nullptr;
        for (const auto &peer : peers_) {
            xpc_connection_set_event_handler(peer.connection, ^(xpc_object_t){
                                             });
            xpc_connection_cancel(peer.connection);
            xpc_release(peer.connection);
        }
        peers_.clear();
        running_ = false;
        return;
    }
    const auto peer = std::find_if(peers_.begin(), peers_.end(), [connection](const auto &entry) {
        return entry.connection == connection;
    });
    if (peer != peers_.end()) {
        xpc_release(peer->connection);
        peers_.erase(peer);
    }
}

void XpcReadOnlyServiceListener::stopOnQueue() {
    if (listener_) {
        xpc_connection_set_event_handler(listener_, ^(xpc_object_t){
                                         });
        xpc_connection_cancel(listener_);
        xpc_release(listener_);
        listener_ = nullptr;
    }
    for (const auto &peer : peers_) {
        xpc_connection_set_event_handler(peer.connection, ^(xpc_object_t){
                                         });
        xpc_connection_cancel(peer.connection);
        xpc_release(peer.connection);
    }
    peers_.clear();
    running_ = false;
}

} // namespace interceptor
