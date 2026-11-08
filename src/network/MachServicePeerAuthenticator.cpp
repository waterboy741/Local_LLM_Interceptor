#include "MachServicePeerAuthenticator.hpp"

#include <Security/SecCode.h>
#include <Security/SecRequirement.h>

namespace interceptor {
namespace {
constexpr qsizetype maximumRequirementLength = 1024;

bool fail(QString *error, const char *reason) {
    if (error)
        *error = QString::fromLatin1(reason);
    return false;
}

bool validRequirement(const QByteArray &requirement) {
    return !requirement.isEmpty() && requirement.size() <= maximumRequirementLength &&
           !requirement.contains('\0');
}
} // namespace

bool MacXpcPeerCodeSignaturePolicy::authenticate(xpc_object_t message,
                                                 const QByteArray &expectedRequirement,
                                                 QString *error) {
    if (error)
        error->clear();
    if (!message || xpc_get_type(message) != XPC_TYPE_DICTIONARY)
        return fail(error, "xpc_peer_message_invalid");
    if (!validRequirement(expectedRequirement))
        return fail(error, "xpc_peer_requirement_invalid");

    const QByteArray utf8Requirement = expectedRequirement;
    CFStringRef requirementText = CFStringCreateWithBytes(
        kCFAllocatorDefault, reinterpret_cast<const UInt8 *>(utf8Requirement.constData()),
        static_cast<CFIndex>(utf8Requirement.size()), kCFStringEncodingUTF8, false);
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

bool authenticateXpcPeerMessage(xpc_object_t message, const QByteArray &expectedRequirement,
                                XpcPeerCodeSignaturePolicy &policy, QString *error) {
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
    if (error && error->isEmpty())
        *error = QStringLiteral("xpc_peer_code_requirement_failed");
    return false;
}

} // namespace interceptor
