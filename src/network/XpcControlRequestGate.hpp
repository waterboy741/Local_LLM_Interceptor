#pragma once

#include "MachServicePeerAuthenticator.hpp"

#include <cstddef>

#include <string>
#include <vector>

namespace interceptor {

enum class XpcControlOperation {
    Invalid,
    Probe,
    Status,
    Start,
    Heartbeat,
    Stop,
};

// Session-control fixture limits. Heartbeat and Stop are parsed only in the constructor-opt-in
// SyntheticLifecycle mode used by the offline lifecycle fixture; the installed --mach-service
// path constructs the ReadOnly gate and never accepts these operations. The session id bound must
// match the helper session id pattern, and the capability length matches the fixed helper session
// capability size (HelperSessionIdentity::capabilityRandomBytes, asserted by
// HelperLifecycleRuntime).
inline constexpr std::size_t xpcSessionControlRequestFieldCount = 4;
inline constexpr std::size_t xpcSessionControlMaximumSessionIdBytes = 48;
inline constexpr std::size_t xpcSessionControlCapabilityBytes = 32;

struct XpcControlRequest {
    XpcControlOperation operation = XpcControlOperation::Invalid;
    // Heartbeat/Stop only. The session id is not secret and is never authorization by itself.
    std::string sessionId;
    // Heartbeat/Stop only. Exactly xpcSessionControlCapabilityBytes when parsed.
    std::vector<unsigned char> sessionCapability;
};

// Owns the locally trusted code requirement. Authenticates the sender before
// inspecting protocol fields. Probe and status accept only the operation key.
// SyntheticLifecycle also accepts start with protocol_version (uint64 1), plus heartbeat and stop
// with protocol_version, session_id, and session_capability, per the session-control contract.
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
