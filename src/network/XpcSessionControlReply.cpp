#define __STDC_WANT_LIB_EXT1__ 1
#include "XpcSessionControlReply.hpp"

#include <string_view>

#include <string.h>

namespace interceptor {

void wipeXpcSessionControlReply(XpcSessionControlReply &reply) noexcept {
    if (!reply.sessionCapability.empty())
        (void)memset_s(reply.sessionCapability.data(),
                       static_cast<rsize_t>(reply.sessionCapability.size()), 0,
                       static_cast<rsize_t>(reply.sessionCapability.size()));
    reply.sessionCapability.clear();
}

xpc_object_t encodeXpcSessionControlReply(const XpcSessionControlReply &reply) {
    const std::string_view state(reply.state);
    const std::string_view sessionId(reply.sessionId);
    const std::string_view reason(reply.reason);
    if (reply.protocolVersion != xpcSessionControlProtocolVersion)
        return nullptr;
    if (state.empty() || state.size() > xpcSessionControlMaximumStateBytes)
        return nullptr;
    if (sessionId.size() > xpcSessionControlMaximumSessionIdBytes)
        return nullptr;
    if (reason.size() > xpcSessionControlMaximumReasonBytes)
        return nullptr;
    if (!reply.sessionCapability.empty() &&
        reply.sessionCapability.size() != xpcSessionControlCapabilityBytes)
        return nullptr;

    xpc_object_t payload = xpc_dictionary_create(nullptr, nullptr, 0);
    if (!payload)
        return nullptr;
    xpc_dictionary_set_bool(payload, "ok", reply.ok);
    xpc_dictionary_set_uint64(payload, "protocol_version", reply.protocolVersion);
    xpc_dictionary_set_string(payload, "state", reply.state.c_str());
    if (!reply.sessionId.empty())
        xpc_dictionary_set_string(payload, "session_id", reply.sessionId.c_str());
    if (!reply.sessionCapability.empty())
        (void)xpc_dictionary_set_data(payload, "session_capability", reply.sessionCapability.data(),
                                      reply.sessionCapability.size());
    if (!reply.reason.empty())
        xpc_dictionary_set_string(payload, "reason", reply.reason.c_str());
    return payload;
}

} // namespace interceptor
