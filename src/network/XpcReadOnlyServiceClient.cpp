#include "XpcReadOnlyServiceClient.hpp"

#include "LaunchdMachServiceBootstrap.hpp"

#include <dispatch/dispatch.h>

#include <cstring>
#include <memory>

namespace interceptor {
namespace {

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

XpcReadOnlyClientResult failed(XpcReadOnlyClientStatus status) {
    XpcReadOnlyClientResult result;
    result.status = status;
    return result;
}

bool hasString(xpc_object_t reply, const char *key, const char *expected) {
    xpc_object_t value = xpc_dictionary_get_value(reply, key);
    if (!value || xpc_get_type(value) != XPC_TYPE_STRING)
        return false;
    const char *string = xpc_string_get_string_ptr(value);
    const size_t expectedLength = std::strlen(expected);
    return string && xpc_string_get_length(value) == expectedLength &&
           std::memcmp(string, expected, expectedLength) == 0;
}

XpcReadOnlyClientResult parseReply(xpc_object_t reply, XpcReadOnlyClientOperation operation) {
    if (!reply || xpc_get_type(reply) != XPC_TYPE_DICTIONARY)
        return failed(XpcReadOnlyClientStatus::InvalidReply);

    if (operation == XpcReadOnlyClientOperation::Probe) {
        if (xpc_dictionary_get_count(reply) != 3 ||
            xpc_get_type(xpc_dictionary_get_value(reply, "ok")) != XPC_TYPE_BOOL ||
            !xpc_dictionary_get_bool(reply, "ok") ||
            !hasString(reply, "service", "llm_interceptor") ||
            xpc_get_type(xpc_dictionary_get_value(reply, "protocol_version")) != XPC_TYPE_UINT64 ||
            xpc_dictionary_get_uint64(reply, "protocol_version") != 1)
            return failed(XpcReadOnlyClientStatus::InvalidReply);
    } else {
        if (xpc_dictionary_get_count(reply) != 4 ||
            xpc_get_type(xpc_dictionary_get_value(reply, "ok")) != XPC_TYPE_BOOL ||
            !xpc_dictionary_get_bool(reply, "ok") ||
            !hasString(reply, "service", "llm_interceptor") ||
            xpc_get_type(xpc_dictionary_get_value(reply, "protocol_version")) != XPC_TYPE_UINT64 ||
            xpc_dictionary_get_uint64(reply, "protocol_version") != 1 ||
            !hasString(reply, "state", "inactive"))
            return failed(XpcReadOnlyClientStatus::InvalidReply);
    }

    XpcReadOnlyClientResult result;
    result.status = XpcReadOnlyClientStatus::Success;
    result.ok = true;
    result.service = QStringLiteral("llm_interceptor");
    result.protocolVersion = 1;
    if (operation == XpcReadOnlyClientOperation::Status)
        result.state = QStringLiteral("inactive");
    return result;
}

} // namespace

XpcReadOnlyClientResult XpcReadOnlyServiceClient::probe(int timeoutMs) const {
    return request(XpcReadOnlyClientOperation::Probe, timeoutMs, nullptr);
}

XpcReadOnlyClientResult XpcReadOnlyServiceClient::status(int timeoutMs) const {
    return request(XpcReadOnlyClientOperation::Status, timeoutMs, nullptr);
}

XpcReadOnlyClientResult XpcReadOnlyServiceClient::requestWithEndpointForTesting(
    xpc_endpoint_t endpoint, XpcReadOnlyClientOperation operation, int timeoutMs) {
    return request(operation, timeoutMs, endpoint);
}

XpcReadOnlyClientResult XpcReadOnlyServiceClient::request(XpcReadOnlyClientOperation operation,
                                                          int timeoutMs,
                                                          xpc_endpoint_t testEndpoint) {
    if (timeoutMs < 1 || timeoutMs > maximumTimeoutMs)
        return failed(XpcReadOnlyClientStatus::InvalidTimeout);
    if (operation != XpcReadOnlyClientOperation::Probe &&
        operation != XpcReadOnlyClientOperation::Status)
        return failed(XpcReadOnlyClientStatus::InvalidReply);

    xpc_connection_t connection = nullptr;
    if (testEndpoint) {
        connection = xpc_connection_create_from_endpoint(testEndpoint);
    } else {
        const std::string serviceName(launchdMachServiceName);
        connection = xpc_connection_create_mach_service(serviceName.c_str(), nullptr, 0);
    }
    if (!connection)
        return failed(XpcReadOnlyClientStatus::ConnectionFailed);

    xpc_connection_set_event_handler(connection, ^(xpc_object_t){
                                     });
    xpc_connection_activate(connection);

    const char *operationName = operation == XpcReadOnlyClientOperation::Probe ? "probe" : "status";
    xpc_object_t message = xpc_dictionary_create(nullptr, nullptr, 0);
    if (!message) {
        xpc_connection_cancel(connection);
        xpc_release(connection);
        return failed(XpcReadOnlyClientStatus::ConnectionFailed);
    }
    xpc_dictionary_set_string(message, "operation", operationName);

    auto state = std::make_shared<ReplyState>();
    if (!state->semaphore) {
        xpc_release(message);
        xpc_connection_cancel(connection);
        xpc_release(connection);
        return failed(XpcReadOnlyClientStatus::ConnectionFailed);
    }
    dispatch_queue_t replyQueue =
        dispatch_queue_create("org.local-llm-interceptor.xpc-client-reply", DISPATCH_QUEUE_SERIAL);
    if (!replyQueue) {
        xpc_release(message);
        xpc_connection_cancel(connection);
        xpc_release(connection);
        return failed(XpcReadOnlyClientStatus::ConnectionFailed);
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
        return failed(XpcReadOnlyClientStatus::TimedOut);
    if (xpc_get_type(state->reply) == XPC_TYPE_ERROR)
        return failed(XpcReadOnlyClientStatus::ServiceUnavailable);
    return parseReply(state->reply, operation);
}

} // namespace interceptor
