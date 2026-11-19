#pragma once

#include "InstalledSessionControl.hpp"
#include "XpcControlRequestGate.hpp"
#include "XpcReadOnlyServiceListener.hpp"

namespace interceptor {

// Session-control responder for the operator-gated installed service. Wraps one
// InstalledLifecycle gate (per-message pinned-cdhash authentication) and one
// InstalledSessionControlCore. Probe and status replies are shape-identical to the read-only
// v1 protocol; status additionally reports the core's current lifecycle state instead of the
// fixed "inactive" string used when no session control is configured. Rejected or
// unauthenticated requests receive no reply at all. The interface is const-mutable only through
// the core; the owner dispatch queue serializes all calls.
class XpcSessionControlServiceAdapter final : public XpcServiceMessageHandler {
  public:
    XpcSessionControlServiceAdapter(XpcControlRequestGate &gate, InstalledSessionControlCore &core);

    bool isConfigured() const override;
    xpc_object_t handleMessage(xpc_object_t message) const override;

  private:
    XpcControlRequestGate &gate_;
    InstalledSessionControlCore &core_;
};

} // namespace interceptor
