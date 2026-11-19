#pragma once

#include "InstalledSessionControl.hpp"
#include "XpcControlRequestGate.hpp"
#include "XpcReadOnlyServiceListener.hpp"

namespace interceptor {

// Session-control responder for the operator-gated installed service. Wraps one
// InstalledLifecycle gate (per-message pinned-cdhash authentication) and one
// InstalledSessionControlCore. Probe and status replies are byte-identical to the read-only v1
// protocol (including the fixed "inactive" state; the read-only client accepts nothing else);
// the lifecycle state reaches the GUI only through Start/Heartbeat/Stop replies. Rejected or
// unauthenticated requests receive no reply at all, each with one bounded non-sensitive log
// line. The interface is const-mutable only through the core; the owner dispatch queue
// serializes all calls.
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
