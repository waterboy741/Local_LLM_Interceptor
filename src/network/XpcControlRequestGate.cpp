#include "XpcControlRequestGate.hpp"

#include <cstring>
#include <utility>

namespace interceptor {
namespace {
constexpr size_t maximumOperationLength = 16;
constexpr qsizetype maximumRequirementLength = 1024;

bool fail(QString *error, const char *reason) {
    if (error)
        *error = QString::fromLatin1(reason);
    return false;
}

} // namespace

XpcControlRequestGate::XpcControlRequestGate(QByteArray trustedRequirement,
                                             XpcPeerCodeSignaturePolicy &policy)
    : trustedRequirement_(std::move(trustedRequirement)), policy_(policy) {}

bool XpcControlRequestGate::isConfigured() const {
    return !trustedRequirement_.isEmpty() &&
           trustedRequirement_.size() <= maximumRequirementLength &&
           !trustedRequirement_.contains('\0');
}

bool XpcControlRequestGate::parse(xpc_object_t message, XpcControlRequest *request,
                                  QString *error) const {
    if (error)
        error->clear();
    if (request)
        *request = XpcControlRequest{};
    if (!request)
        return fail(error, "xpc_control_request_output_invalid");

    if (!authenticateXpcPeerMessage(message, trustedRequirement_, policy_, error))
        return false;

    if (xpc_dictionary_get_count(message) != 1)
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

    if (std::strcmp(operation, "probe") == 0)
        request->operation = XpcControlOperation::Probe;
    else if (std::strcmp(operation, "status") == 0)
        request->operation = XpcControlOperation::Status;
    else
        return fail(error, "xpc_control_request_operation_unsupported");

    return true;
}

} // namespace interceptor
