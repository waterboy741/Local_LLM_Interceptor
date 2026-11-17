#include "MachServicePeerAuthenticator.hpp"

#include <Security/SecCode.h>
#include <Security/SecRequirement.h>

namespace interceptor {
namespace {
constexpr size_t maximumRequirementLength = 1024;

bool fail(std::string *error, const char *reason) {
    if (error)
        *error = reason;
    return false;
}

bool validRequirement(std::string_view requirement) {
    return !requirement.empty() && requirement.size() <= maximumRequirementLength &&
           requirement.find('\0') == std::string_view::npos;
}
} // namespace

bool MacXpcPeerCodeSignaturePolicy::authenticate(xpc_object_t message,
                                                 std::string_view expectedRequirement,
                                                 std::string *error) {
    if (error)
        error->clear();
    if (!message || xpc_get_type(message) != XPC_TYPE_DICTIONARY)
        return fail(error, "xpc_peer_message_invalid");
    if (!validRequirement(expectedRequirement))
        return fail(error, "xpc_peer_requirement_invalid");

    CFStringRef requirementText = CFStringCreateWithBytes(
        kCFAllocatorDefault, reinterpret_cast<const UInt8 *>(expectedRequirement.data()),
        static_cast<CFIndex>(expectedRequirement.size()), kCFStringEncodingUTF8, false);
    if (!requirementText)
        return fail(error, "xpc_peer_requirement_encoding_invalid");

    SecCodeRef peerCode = nullptr;
    SecRequirementRef requirement = nullptr;
    const OSStatus peerStatus = SecCodeCreateWithXPCMessage(message, kSecCSDefaultFlags, &peerCode);
    const OSStatus requirementStatus =
        SecRequirementCreateWithString(requirementText, kSecCSDefaultFlags, &requirement);
    CFRelease(requirementText);

    bool authenticated = false;
    if (peerStatus == errSecSuccess && peerCode && requirementStatus == errSecSuccess &&
        requirement &&
        SecCodeCheckValidity(peerCode, kSecCSDefaultFlags, requirement) == errSecSuccess)
        authenticated = true;

    if (requirement)
        CFRelease(requirement);
    if (peerCode)
        CFRelease(peerCode);
    return authenticated ? true : fail(error, "xpc_peer_code_requirement_failed");
}

bool authenticateXpcPeerMessage(xpc_object_t message, std::string_view expectedRequirement,
                                XpcPeerCodeSignaturePolicy &policy, std::string *error) {
    if (error)
        error->clear();
    if (!message || xpc_get_type(message) != XPC_TYPE_DICTIONARY)
        return fail(error, "xpc_peer_message_invalid");
    if (!validRequirement(expectedRequirement))
        return fail(error, "xpc_peer_requirement_invalid");
    try {
        if (policy.authenticate(message, expectedRequirement, error))
            return true;
    } catch (...) {
    }
    if (error && error->empty())
        *error = "xpc_peer_code_requirement_failed";
    return false;
}

} // namespace interceptor
