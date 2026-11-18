#include "XpcControlRequestGate.hpp"

#include <string_view>
#include <utility>

namespace interceptor {
namespace {
constexpr size_t maximumOperationLength = 16;
constexpr size_t maximumRequirementLength = 1024;
constexpr uint64_t syntheticProtocolVersion = 1;

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
    if (fieldCount != 1 && (mode_ != Mode::SyntheticLifecycle || fieldCount != 2))
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
