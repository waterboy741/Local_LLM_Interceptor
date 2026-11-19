#include "XpcSessionControlServiceAdapter.hpp"

#include <os/log.h>

namespace interceptor {
namespace {

// One bounded, non-sensitive reason line per refused or unanswered authenticated message. The
// text is exclusively the fixed control-request reason vocabulary (no sender, identity, or path
// data), so a live rejection can be traced without weakening the trust boundary.
void logRefusal(const char *reason) {
    if (reason && *reason)
        os_log_error(OS_LOG_DEFAULT, "llm_interceptor.session-control refused request: %{public}s",
                     reason);
}

} // namespace

XpcSessionControlServiceAdapter::XpcSessionControlServiceAdapter(XpcControlRequestGate &gate,
                                                                 InstalledSessionControlCore &core)
    : gate_(gate), core_(core) {}

bool XpcSessionControlServiceAdapter::isConfigured() const { return gate_.isConfigured(); }

xpc_object_t XpcSessionControlServiceAdapter::handleMessage(xpc_object_t message) const {
    std::string parseError;
    XpcControlRequest request;
    if (!gate_.parse(message, &request, &parseError)) {
        logRefusal(parseError.empty() ? "xpc_control_request_rejected" : parseError.c_str());
        return nullptr;
    }

    // Probe/status stay the byte-identical read-only v1 protocol (fixed "inactive" state); the
    // lifecycle state reaches the GUI only through Start/Heartbeat/Stop replies.
    if (request.operation == XpcControlOperation::Probe ||
        request.operation == XpcControlOperation::Status) {
        xpc_object_t reply = xpc_dictionary_create_reply(message);
        if (!reply) {
            logRefusal("xpc_control_reply_create_failed");
            return nullptr;
        }
        xpc_object_t payload =
            XpcReadOnlyControlAdapter::createBoundedReplyPayload(request.operation);
        if (!payload) {
            xpc_release(reply);
            logRefusal("xpc_control_reply_payload_unavailable");
            return nullptr;
        }
        xpc_dictionary_apply(payload, ^bool(const char *key, xpc_object_t value) {
          xpc_dictionary_set_value(reply, key, value);
          return true;
        });
        xpc_release(payload);
        return reply;
    }

    // Start/Heartbeat/Stop: the core owns the state machine; capability bytes are wiped
    // immediately after encoding so no secret outlives this call.
    XpcSessionControlReply controlReply = core_.handleControlRequest(request);
    xpc_object_t reply = encodeXpcSessionControlReply(controlReply);
    wipeXpcSessionControlReply(controlReply);
    if (!reply) {
        logRefusal("xpc_control_reply_encode_failed");
        return nullptr;
    }
    xpc_object_t routed = xpc_dictionary_create_reply(message);
    if (!routed) {
        xpc_release(reply);
        logRefusal("xpc_control_reply_create_failed");
        return nullptr;
    }
    xpc_dictionary_apply(reply, ^bool(const char *key, xpc_object_t value) {
      xpc_dictionary_set_value(routed, key, value);
      return true;
    });
    xpc_release(reply);
    return routed;
}

} // namespace interceptor
