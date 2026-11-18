#pragma once

#include "MachServicePeerAuthenticator.hpp"

namespace interceptor {

enum class XpcControlOperation {
    Invalid,
    Probe,
    Status,
    Start,
};

struct XpcControlRequest {
    XpcControlOperation operation = XpcControlOperation::Invalid;
};

// Owns the locally trusted code requirement. Authenticates the sender before
// inspecting protocol fields. Probe and status accept only the operation key.
// SyntheticLifecycle also accepts start with protocol_version (uint64 1).
// This gate performs no response encoding or dispatch. The injected policy
// must outlive the gate, and calls must be serialized by the caller. The XPC
// message is borrowed and inspected synchronously.
class XpcControlRequestGate final {
  public:
    enum class Mode { ReadOnly, SyntheticLifecycle };

    XpcControlRequestGate(std::string trustedRequirement, XpcPeerCodeSignaturePolicy &policy,
                          Mode mode = Mode::ReadOnly);

    bool isConfigured() const;
    bool parse(xpc_object_t message, XpcControlRequest *request,
               std::string *error = nullptr) const;

  private:
    const std::string trustedRequirement_;
    XpcPeerCodeSignaturePolicy &policy_;
    const Mode mode_;
};

} // namespace interceptor
