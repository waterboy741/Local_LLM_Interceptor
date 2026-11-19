#include "XpcControlRequestGate.hpp"

#include <cstdint>
#include <string_view>
#include <utility>

#include <cctype>

namespace interceptor {
namespace {
constexpr size_t maximumOperationLength = 16;
constexpr size_t maximumRequirementLength = 1024;
constexpr uint64_t syntheticProtocolVersion = 1;

bool validSessionId(std::string_view sessionId) {
    for (const char character : sessionId) {
        const bool lower = character >= 'a' && character <= 'z';
        const bool upper = character >= 'A' && character <= 'Z';
        const bool digit = character >= '0' && character <= '9';
        if (!lower && !upper && !digit && character != '_' && character != '-')
            return false;
    }
    return true;
}

bool validInterfaceName(std::string_view name) {
    if (name.empty() || name.size() > 32 || !validSessionId(name))
        return false;
    // Aligned with SessionConfig: interface names must begin with a letter.
    const char first = name.front();
    const bool lower = first >= 'a' && first <= 'z';
    const bool upper = first >= 'A' && first <= 'Z';
    return lower || upper;
}

bool decimalOctet(std::string_view text) {
    if (text.empty() || text.size() > 3)
        return false;
    int value = 0;
    for (const char character : text) {
        if (character < '0' || character > '9')
            return false;
        value = value * 10 + (character - '0');
    }
    return text.size() > 1 && text.front() == '0' ? false : value <= 255;
}

bool validIpv4(std::string_view text) {
    if (text.size() < 7 || text.size() > 15)
        return false;
    size_t octets = 0, start = 0;
    for (size_t index = 0; index <= text.size(); ++index) {
        if (index == text.size() || text[index] == '.') {
            if (!decimalOctet(text.substr(start, index - start)))
                return false;
            ++octets;
            start = index + 1;
        }
    }
    return octets == 4;
}

bool validPort(uint64_t port) { return port >= 1 && port <= 65535; }

bool fail(std::string *error, const char *reason) {
    if (error)
        *error = reason;
    return false;
}

} // namespace

XpcControlRequestGate::XpcControlRequestGate(std::string trustedRequirement,
                                             XpcPeerCodeSignaturePolicy &policy, Mode mode)
    : trustedRequirement_(std::move(trustedRequirement)), policy_(policy), mode_(mode) {}

bool XpcControlRequestGate::isConfigured() const {
    return !trustedRequirement_.empty() && trustedRequirement_.size() <= maximumRequirementLength &&
           trustedRequirement_.find('\0') == std::string::npos;
}

bool XpcControlRequestGate::parse(xpc_object_t message, XpcControlRequest *request,
                                  std::string *error) const {
    if (error)
        error->clear();
    if (request)
        *request = XpcControlRequest{};
    if (!request)
        return fail(error, "xpc_control_request_output_invalid");

    if (!authenticateXpcPeerMessage(message, trustedRequirement_, policy_, error))
        return false;

    const size_t fieldCount = xpc_dictionary_get_count(message);
    const bool sessionLifecycleMode =
        mode_ == Mode::SyntheticLifecycle || mode_ == Mode::InstalledLifecycle;
    const bool syntheticStartFields = mode_ == Mode::SyntheticLifecycle && fieldCount == 2;
    const bool syntheticSessionControlFields = sessionLifecycleMode && fieldCount == 4;
    const bool installedStartFields =
        mode_ == Mode::InstalledLifecycle && fieldCount == xpcInstalledStartRequestFieldCount;
    if (fieldCount != 1 && !syntheticStartFields && !syntheticSessionControlFields &&
        !installedStartFields)
        return fail(error, "xpc_control_request_fields_invalid");

    xpc_object_t operationValue = xpc_dictionary_get_value(message, "operation");
    if (!operationValue || xpc_get_type(operationValue) != XPC_TYPE_STRING)
        return fail(error, "xpc_control_request_operation_invalid");

    const size_t operationLength = xpc_string_get_length(operationValue);
    if (operationLength == 0 || operationLength > maximumOperationLength)
        return fail(error, "xpc_control_request_operation_invalid");
    const char *operation = xpc_string_get_string_ptr(operationValue);
    if (!operation)
        return fail(error, "xpc_control_request_operation_invalid");

    const std::string_view value(operation, operationLength);

    if (value == "start" && mode_ == Mode::InstalledLifecycle) {
        if (fieldCount != xpcInstalledStartRequestFieldCount)
            return fail(error, "xpc_control_request_fields_invalid");
        xpc_object_t version = xpc_dictionary_get_value(message, "protocol_version");
        if (!version || xpc_get_type(version) != XPC_TYPE_UINT64 ||
            xpc_uint64_get_value(version) != syntheticProtocolVersion)
            return fail(error, !version ? "xpc_control_request_fields_invalid"
                                        : "xpc_control_request_version_invalid");
        const auto &stringField = [&](const char *key, const char **chars, size_t *length) {
            xpc_object_t field = xpc_dictionary_get_value(message, key);
            if (!field)
                return false;
            if (xpc_get_type(field) != XPC_TYPE_STRING)
                return false;
            *chars = xpc_string_get_string_ptr(field);
            *length = xpc_string_get_length(field);
            return *chars != nullptr;
        };
        const char *interfaceChars = nullptr, *clientChars = nullptr, *upstreamChars = nullptr,
                   *listenChars = nullptr;
        size_t interfaceLength = 0, clientLength = 0, upstreamLength = 0, listenLength = 0;
        if (!stringField("interface", &interfaceChars, &interfaceLength) ||
            !stringField("client_ipv4", &clientChars, &clientLength) ||
            !stringField("upstream_ipv4", &upstreamChars, &upstreamLength) ||
            !stringField("listen_address", &listenChars, &listenLength))
            return fail(error, "xpc_control_request_session_start_invalid");
        if (!validInterfaceName(std::string_view(interfaceChars, interfaceLength)) ||
            !validIpv4(std::string_view(clientChars, clientLength)) ||
            !validIpv4(std::string_view(upstreamChars, upstreamLength)) ||
            !validIpv4(std::string_view(listenChars, listenLength)) ||
            std::string_view(listenChars, listenLength) ==
                std::string_view(clientChars, clientLength) ||
            std::string_view(listenChars, listenLength) ==
                std::string_view(upstreamChars, upstreamLength))
            return fail(error, "xpc_control_request_session_start_invalid");
        xpc_object_t upstreamPort = xpc_dictionary_get_value(message, "upstream_port");
        xpc_object_t listenerPort = xpc_dictionary_get_value(message, "listener_port");
        if (!upstreamPort || !listenerPort)
            return fail(error, "xpc_control_request_fields_invalid");
        if (xpc_get_type(upstreamPort) != XPC_TYPE_UINT64 ||
            !validPort(xpc_uint64_get_value(upstreamPort)) ||
            xpc_get_type(listenerPort) != XPC_TYPE_UINT64 ||
            !validPort(xpc_uint64_get_value(listenerPort)))
            return fail(error, "xpc_control_request_session_start_invalid");
        xpc_object_t probeSecret = xpc_dictionary_get_value(message, "probe_secret");
        if (!probeSecret)
            return fail(error, "xpc_control_request_fields_invalid");
        if (xpc_get_type(probeSecret) != XPC_TYPE_DATA ||
            xpc_data_get_length(probeSecret) != xpcSessionControlCapabilityBytes)
            return fail(error, "xpc_control_request_session_start_invalid");
        const auto *secretBytes =
            static_cast<const unsigned char *>(xpc_data_get_bytes_ptr(probeSecret));
        if (!secretBytes)
            return fail(error, "xpc_control_request_session_start_invalid");
        request->operation = XpcControlOperation::Start;
        request->sessionInterface.assign(interfaceChars, interfaceLength);
        request->sessionClientIpv4.assign(clientChars, clientLength);
        request->sessionUpstreamIpv4.assign(upstreamChars, upstreamLength);
        request->sessionListenAddress.assign(listenChars, listenLength);
        request->sessionUpstreamPort = xpc_uint64_get_value(upstreamPort);
        request->sessionListenerPort = xpc_uint64_get_value(listenerPort);
        request->probeSecret.assign(secretBytes, secretBytes + xpcSessionControlCapabilityBytes);
        return true;
    }
    if (sessionLifecycleMode && (value == "heartbeat" || value == "stop")) {
        if (fieldCount != xpcSessionControlRequestFieldCount)
            return fail(error, "xpc_control_request_fields_invalid");
        xpc_object_t version = xpc_dictionary_get_value(message, "protocol_version");
        if (!version)
            return fail(error, "xpc_control_request_fields_invalid");
        if (xpc_get_type(version) != XPC_TYPE_UINT64 ||
            xpc_uint64_get_value(version) != syntheticProtocolVersion)
            return fail(error, "xpc_control_request_version_invalid");
        xpc_object_t sessionId = xpc_dictionary_get_value(message, "session_id");
        if (!sessionId)
            return fail(error, "xpc_control_request_fields_invalid");
        if (xpc_get_type(sessionId) != XPC_TYPE_STRING)
            return fail(error, "xpc_control_request_session_id_invalid");
        const size_t sessionIdLength = xpc_string_get_length(sessionId);
        const char *sessionIdChars = xpc_string_get_string_ptr(sessionId);
        if (sessionIdLength == 0 || sessionIdLength > xpcSessionControlMaximumSessionIdBytes ||
            !sessionIdChars || !validSessionId(std::string_view(sessionIdChars, sessionIdLength)))
            return fail(error, "xpc_control_request_session_id_invalid");
        xpc_object_t capability = xpc_dictionary_get_value(message, "session_capability");
        if (!capability)
            return fail(error, "xpc_control_request_fields_invalid");
        if (xpc_get_type(capability) != XPC_TYPE_DATA ||
            xpc_data_get_length(capability) != xpcSessionControlCapabilityBytes)
            return fail(error, "xpc_control_request_session_capability_invalid");
        const auto *capabilityBytes =
            static_cast<const unsigned char *>(xpc_data_get_bytes_ptr(capability));
        if (!capabilityBytes)
            return fail(error, "xpc_control_request_session_capability_invalid");
        request->operation =
            value == "heartbeat" ? XpcControlOperation::Heartbeat : XpcControlOperation::Stop;
        request->sessionId.assign(sessionIdChars, sessionIdLength);
        request->sessionCapability.assign(capabilityBytes,
                                          capabilityBytes + xpcSessionControlCapabilityBytes);
        return true;
    }
    if (value == "start" && mode_ == Mode::SyntheticLifecycle) {
        xpc_object_t version = xpc_dictionary_get_value(message, "protocol_version");
        if (fieldCount != 2 || !version)
            return fail(error, "xpc_control_request_fields_invalid");
        if (xpc_get_type(version) != XPC_TYPE_UINT64 ||
            xpc_uint64_get_value(version) != syntheticProtocolVersion)
            return fail(error, "xpc_control_request_version_invalid");
        request->operation = XpcControlOperation::Start;
        return true;
    }
    if (fieldCount != 1)
        return fail(error, "xpc_control_request_fields_invalid");
    if (value == "probe")
        request->operation = XpcControlOperation::Probe;
    else if (value == "status")
        request->operation = XpcControlOperation::Status;
    else
        return fail(error, "xpc_control_request_operation_unsupported");

    return true;
}

} // namespace interceptor
