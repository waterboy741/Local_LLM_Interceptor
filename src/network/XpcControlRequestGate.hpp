#pragma once

#include "MachServicePeerAuthenticator.hpp"

namespace interceptor {

enum class XpcControlOperation {
    Invalid,
    Probe,
    Status,
};

struct XpcControlRequest {
    XpcControlOperation operation = XpcControlOperation::Invalid;
};

// Owns the locally trusted code requirement. Authenticates the sender before
// inspecting protocol fields. The accepted dictionary contains exactly one
// key (`operation`) with value `probe` or `status`; this gate performs no
// response encoding, dispatch, or privileged operation. The injected policy
// must outlive the gate, and calls must be serialized by the caller. The XPC
// message is borrowed and inspected synchronously.
class XpcControlRequestGate final {
  public:
    XpcControlRequestGate(QByteArray trustedRequirement, XpcPeerCodeSignaturePolicy &policy);

    bool isConfigured() const;
    bool parse(xpc_object_t message, XpcControlRequest *request, QString *error = nullptr) const;

  private:
    const QByteArray trustedRequirement_;
    XpcPeerCodeSignaturePolicy &policy_;
};

} // namespace interceptor
