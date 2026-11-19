#pragma once

#include "XpcControlRequestGate.hpp"

#include <xpc/xpc.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace interceptor {

inline constexpr std::uint64_t xpcSessionControlProtocolVersion = 1;
inline constexpr std::size_t xpcSessionControlMaximumStateBytes = 16;
inline constexpr std::size_t xpcSessionControlMaximumReasonBytes = 64;

// Fixed reply-state vocabulary, at most xpcSessionControlMaximumStateBytes each. Every state
// names a lifecycle fact the runtime can prove; none carries a session secret or prompt data.
inline constexpr std::string_view xpcSessionControlStateUninitialized = "uninitialized";
inline constexpr std::string_view xpcSessionControlStateInitFailed = "init_failed";
inline constexpr std::string_view xpcSessionControlStateRecoveryPending = "recovery_pending";
inline constexpr std::string_view xpcSessionControlStateReady = "ready";
inline constexpr std::string_view xpcSessionControlStateActive = "active";
inline constexpr std::string_view xpcSessionControlStateCleanupPending = "cleanup_pending";
inline constexpr std::string_view xpcSessionControlStateStopped = "stopped";

// Bounded reply for the fixture-only session-control surface. `ok` is true only when the
// requested transition is achieved and verified. `sessionCapability` is the one-time session
// capability: it is delivered only in the accepted Start reply, exactly once per session, and is
// empty in every other reply. The caller owns any capability copy and must wipe it after use.
struct XpcSessionControlReply {
    bool ok = false;
    std::uint64_t protocolVersion = xpcSessionControlProtocolVersion;
    std::string state;
    std::string sessionId;
    std::vector<unsigned char> sessionCapability;
    std::string reason;
};

// Zeroes and clears the capability bytes retained by `reply`. Non-secret fields are left intact.
void wipeXpcSessionControlReply(XpcSessionControlReply &reply) noexcept;

// Encodes exactly the bounded v1 reply fields: ok (bool), protocol_version (uint64 1), state
// (string), and, only when non-empty, session_id (string), session_capability (data), and reason
// (string). Returns a retained (+1) XPC dictionary the caller owns, or nullptr when any field
// violates its documented bound. It performs no reply transmission.
xpc_object_t encodeXpcSessionControlReply(const XpcSessionControlReply &reply);

} // namespace interceptor
