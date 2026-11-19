#include "XpcSessionControlClient.hpp"

#include "LaunchdMachServiceBootstrap.hpp"

#include <dispatch/dispatch.h>

#include <cstring>
#include <memory>

namespace interceptor {
namespace {

constexpr std::uint64_t sessionProtocolVersion = 1;
constexpr size_t maximumStateBytes = 16;
constexpr size_t maximumSessionIdBytes = 48;
constexpr size_t maximumReasonBytes = 64;

struct ReplyState final {
    ReplyState() : semaphore(dispatch_semaphore_create(0)) {}
    ~ReplyState() {
        if (reply)
            xpc_release(reply);
        if (semaphore)
            dispatch_release(semaphore);
    }

    dispatch_semaphore_t semaphore = nullptr;
    xpc_object_t reply = nullptr;
};

XpcSessionControlClientResult failed(XpcSessionControlClientStatus status) {
    XpcSessionControlClientResult result;
    result.status = status;
    return result;
}

bool boundedString(xpc_object_t reply, const char *key, size_t maximumBytes, QString *out) {
    xpc_object_t value = xpc_dictionary_get_value(reply, key);
    if (!value)
        return true; // optional field
    if (xpc_get_type(value) != XPC_TYPE_STRING)
        return false;
    const size_t length = xpc_string_get_length(value);
    const char *chars = xpc_string_get_string_ptr(value);
    if (!chars || length > maximumBytes)
        return false;
    if (out)
        *out = QString::fromLatin1(QByteArray(chars, int(length)));
    return true;
}

XpcSessionControlClientResult parseReply(xpc_object_t reply) {
    if (!reply || xpc_get_type(reply) != XPC_TYPE_DICTIONARY)
        return failed(XpcSessionControlClientStatus::InvalidReply);

    xpc_object_t okValue = xpc_dictionary_get_value(reply, "ok");
    if (xpc_get_type(okValue) != XPC_TYPE_BOOL)
        return failed(XpcSessionControlClientStatus::InvalidReply);
    if (xpc_dictionary_get_count(reply) < 3)
        return failed(XpcSessionControlClientStatus::InvalidReply);
    xpc_object_t versionValue = xpc_dictionary_get_value(reply, "protocol_version");
    if (xpc_get_type(versionValue) != XPC_TYPE_UINT64 ||
        xpc_uint64_get_value(versionValue) != sessionProtocolVersion)
        return failed(XpcSessionControlClientStatus::InvalidReply);

    XpcSessionControlClientResult result;
    result.ok = xpc_dictionary_get_bool(reply, "ok");
    if (!boundedString(reply, "state", maximumStateBytes, &result.state) ||
        !boundedString(reply, "session_id", maximumSessionIdBytes, &result.sessionId) ||
        !boundedString(reply, "reason", maximumReasonBytes, &result.reason))
        return failed(XpcSessionControlClientStatus::InvalidReply);

    xpc_object_t capabilityValue = xpc_dictionary_get_value(reply, "session_capability");
    if (capabilityValue) {
        if (!result.ok)
            return failed(XpcSessionControlClientStatus::InvalidReply);
        if (xpc_get_type(capabilityValue) != XPC_TYPE_DATA ||
            xpc_data_get_length(capabilityValue) != XpcSessionControlClient::capabilityBytes)
            return failed(XpcSessionControlClientStatus::InvalidReply);
        const void *bytes = xpc_data_get_bytes_ptr(capabilityValue);
        result.sessionCapability = QByteArray(reinterpret_cast<const char *>(bytes),
                                              int(xpc_data_get_length(capabilityValue)));
    }

    result.status = XpcSessionControlClientStatus::Success;
    return result;
}

void wipe(QByteArray &bytes) {
    for (char &value : bytes)
        value = '\0';
    bytes.clear();
}

} // namespace

XpcSessionControlClientResult
XpcSessionControlClient::start(const XpcSessionControlClientTuple &tuple,
                               const QByteArray &probeSecret, const QByteArray &helperRequirement,
                               int timeoutMs) {
    QByteArray secret(probeSecret);
    XpcSessionControlClientResult result = request(Operation::Start, timeoutMs, helperRequirement,
                                                   nullptr, &tuple, &secret, nullptr, nullptr);
    wipe(secret);
    return result;
}

XpcSessionControlClientResult
XpcSessionControlClient::heartbeat(const QString &sessionId, const QByteArray &capability,
                                   const QByteArray &helperRequirement, int timeoutMs) {
    return request(Operation::Heartbeat, timeoutMs, helperRequirement, nullptr, nullptr, nullptr,
                   &sessionId, &capability);
}

XpcSessionControlClientResult XpcSessionControlClient::stop(const QString &sessionId,
                                                            const QByteArray &capability,
                                                            const QByteArray &helperRequirement,
                                                            int timeoutMs) {
    return request(Operation::Stop, timeoutMs, helperRequirement, nullptr, nullptr, nullptr,
                   &sessionId, &capability);
}

XpcSessionControlClientResult XpcSessionControlClient::status(const QByteArray &helperRequirement,
                                                              int timeoutMs) {
    return request(Operation::Status, timeoutMs, helperRequirement);
}

XpcSessionControlClientResult XpcSessionControlClient::startWithEndpointForTesting(
    xpc_endpoint_t endpoint, const XpcSessionControlClientTuple &tuple,
    const QByteArray &probeSecret, const QByteArray &helperRequirement, int timeoutMs) {
    QByteArray secret(probeSecret);
    XpcSessionControlClientResult result = request(Operation::Start, timeoutMs, helperRequirement,
                                                   endpoint, &tuple, &secret, nullptr, nullptr);
    wipe(secret);
    return result;
}

XpcSessionControlClientResult XpcSessionControlClient::sessionWithEndpointForTesting(
    xpc_endpoint_t endpoint, Operation operation, const QString &sessionId,
    const QByteArray &capability, const QByteArray &helperRequirement, int timeoutMs) {
    return request(operation, timeoutMs, helperRequirement, endpoint, nullptr, nullptr, &sessionId,
                   &capability);
}

XpcSessionControlClientResult XpcSessionControlClient::statusWithEndpointForTesting(
    xpc_endpoint_t endpoint, const QByteArray &helperRequirement, int timeoutMs) {
    return request(Operation::Status, timeoutMs, helperRequirement, endpoint);
}

XpcSessionControlClientResult XpcSessionControlClient::request(
    Operation operation, int timeoutMs, const QByteArray &helperRequirement,
    xpc_endpoint_t testEndpoint, const XpcSessionControlClientTuple *tuple,
    const QByteArray *probeSecret, const QString *sessionId, const QByteArray *capability) {
    if (timeoutMs < 1 || timeoutMs > maximumTimeoutMs)
        return failed(XpcSessionControlClientStatus::InvalidTimeout);
    if (helperRequirement.isEmpty())
        return failed(XpcSessionControlClientStatus::InvalidPeerRequirement);
    if (!exactRequirementCompiles(
            std::string_view(helperRequirement.constData(), size_t(helperRequirement.size()))))
        return failed(XpcSessionControlClientStatus::InvalidPeerRequirement);
    if (operation == Operation::Start && !tuple)
        return failed(XpcSessionControlClientStatus::InvalidRequest);
    if ((operation == Operation::Heartbeat || operation == Operation::Stop) &&
        (!sessionId || sessionId->isEmpty() || !capability ||
         capability->size() != capabilityBytes))
        return failed(XpcSessionControlClientStatus::InvalidRequest);

    xpc_connection_t connection = nullptr;
    if (testEndpoint) {
        connection = xpc_connection_create_from_endpoint(testEndpoint);
    } else {
        const std::string serviceName(launchdMachServiceName);
        connection = xpc_connection_create_mach_service(serviceName.c_str(), nullptr,
                                                        XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
    }
    if (!connection)
        return failed(XpcSessionControlClientStatus::ConnectionFailed);

    bool requirementInstalled = false;
    if (__builtin_available(macOS 12.0, *)) {
        requirementInstalled = xpc_connection_set_peer_code_signing_requirement(
                                   connection, helperRequirement.constData()) == 0;
    }
    xpc_connection_set_event_handler(connection, ^(xpc_object_t){
                                     });
    xpc_connection_activate(connection);
    if (!requirementInstalled) {
        xpc_connection_cancel(connection);
        xpc_release(connection);
        return failed(XpcSessionControlClientStatus::PeerVerificationSetupFailed);
    }

    xpc_object_t message = xpc_dictionary_create(nullptr, nullptr, 0);
    if (!message) {
        xpc_connection_cancel(connection);
        xpc_release(connection);
        return failed(XpcSessionControlClientStatus::ConnectionFailed);
    }
    xpc_dictionary_set_string(message, "operation",
                              operation == Operation::Start       ? "start"
                              : operation == Operation::Heartbeat ? "heartbeat"
                              : operation == Operation::Stop      ? "stop"
                                                                  : "status");
    if (operation == Operation::Start) {
        xpc_dictionary_set_uint64(message, "protocol_version", sessionProtocolVersion);
        xpc_dictionary_set_string(message, "interface", tuple->interfaceName.toUtf8().constData());
        xpc_dictionary_set_string(message, "client_ipv4", tuple->clientIpv4.toUtf8().constData());
        xpc_dictionary_set_string(message, "upstream_ipv4",
                                  tuple->upstreamIpv4.toUtf8().constData());
        xpc_dictionary_set_string(message, "listen_address",
                                  tuple->listenAddress.toUtf8().constData());
        xpc_dictionary_set_uint64(message, "upstream_port", tuple->upstreamPort);
        xpc_dictionary_set_uint64(message, "listener_port", tuple->listenerPort);
        xpc_dictionary_set_data(message, "probe_secret", probeSecret->constData(),
                                size_t(probeSecret->size()));
    } else if (operation == Operation::Heartbeat || operation == Operation::Stop) {
        xpc_dictionary_set_uint64(message, "protocol_version", sessionProtocolVersion);
        xpc_dictionary_set_string(message, "session_id", sessionId->toUtf8().constData());
        xpc_dictionary_set_data(message, "session_capability", capability->constData(),
                                size_t(capability->size()));
    }

    auto state = std::make_shared<ReplyState>();
    if (!state->semaphore) {
        xpc_release(message);
        xpc_connection_cancel(connection);
        xpc_release(connection);
        return failed(XpcSessionControlClientStatus::ConnectionFailed);
    }
    dispatch_queue_t replyQueue = dispatch_queue_create(
        "org.local-llm-interceptor.session-client-reply", DISPATCH_QUEUE_SERIAL);
    if (!replyQueue) {
        xpc_release(message);
        xpc_connection_cancel(connection);
        xpc_release(connection);
        return failed(XpcSessionControlClientStatus::ConnectionFailed);
    }

    xpc_connection_send_message_with_reply(connection, message, replyQueue, ^(xpc_object_t reply) {
      state->reply = xpc_retain(reply);
      dispatch_semaphore_signal(state->semaphore);
    });
    xpc_release(message);

    const dispatch_time_t deadline =
        dispatch_time(DISPATCH_TIME_NOW, static_cast<int64_t>(timeoutMs) * NSEC_PER_MSEC);
    const long waitResult = dispatch_semaphore_wait(state->semaphore, deadline);
    xpc_connection_cancel(connection);
    xpc_release(connection);
    dispatch_release(replyQueue);

    if (waitResult != 0)
        return failed(XpcSessionControlClientStatus::TimedOut);
    if (__builtin_available(macOS 12.0, *)) {
        if (state->reply == XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT)
            return failed(XpcSessionControlClientStatus::PeerIdentityMismatch);
    }
    if (xpc_get_type(state->reply) == XPC_TYPE_ERROR)
        return failed(XpcSessionControlClientStatus::ServiceUnavailable);
    return parseReply(state->reply);
}

} // namespace interceptor
