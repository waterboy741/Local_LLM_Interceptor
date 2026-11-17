#pragma once

#include <string>
#include <string_view>

#include <xpc/xpc.h>

namespace interceptor {

// This policy is the trust boundary for messages received from a launchd Mach service.
// The requirement must come from trusted local configuration, never from the XPC message.
class XpcPeerCodeSignaturePolicy {
  public:
    virtual ~XpcPeerCodeSignaturePolicy() = default;
    virtual bool authenticate(xpc_object_t message, std::string_view expectedRequirement,
                              std::string *error) = 0;
};

// Uses Security.framework's XPC-message API, which resolves the sender using the
// message's kernel-associated audit token, then checks its code against the requirement.
class MacXpcPeerCodeSignaturePolicy final : public XpcPeerCodeSignaturePolicy {
  public:
    bool authenticate(xpc_object_t message, std::string_view expectedRequirement,
                      std::string *error) override;
};

// Common validation and injectable policy seam for received XPC dictionary messages.
// This authenticates process code identity only; it does not authorize network actions.
bool authenticateXpcPeerMessage(xpc_object_t message, std::string_view expectedRequirement,
                                XpcPeerCodeSignaturePolicy &policy, std::string *error = nullptr);

} // namespace interceptor
