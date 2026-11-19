#include "XpcSessionControlServiceAdapter.hpp"

namespace interceptor {

XpcSessionControlServiceAdapter::XpcSessionControlServiceAdapter(XpcControlRequestGate &gate,
                                                                 InstalledSessionControlCore &core)
    : gate_(gate), core_(core) {}

bool XpcSessionControlServiceAdapter::isConfigured() const { return gate_.isConfigured(); }

xpc_object_t XpcSessionControlServiceAdapter::handleMessage(xpc_object_t message) const {
    XpcControlRequest request;
    if (!gate_.parse(message, &request))
        return nullptr;

    if (request.operation == XpcControlOperation::Probe ||
        request.operation == XpcControlOperation::Status) {
        xpc_object_t reply = xpc_dictionary_create_reply(message);
        if (!reply)
            return nullptr;
        xpc_object_t payload =
            XpcReadOnlyControlAdapter::createBoundedReplyPayload(request.operation);
        if (!payload) {
            xpc_release(reply);
            return nullptr;
        }
        if (request.operation == XpcControlOperation::Status)
            xpc_dictionary_set_string(payload, "state", std::string(core_.state()).c_str());
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
    if (!reply)
        return nullptr;
    xpc_object_t routed = xpc_dictionary_create_reply(message);
    if (!routed) {
        xpc_release(reply);
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
