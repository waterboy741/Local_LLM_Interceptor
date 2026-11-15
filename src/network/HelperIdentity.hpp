#pragma once

#include "XpcReadOnlyServiceClient.hpp"

#include <QByteArray>

#include <functional>

#include <sys/types.h>

namespace interceptor {

enum class HelperIdentityStatus { Loaded, Missing, Invalid };

struct HelperIdentity {
    HelperIdentityStatus status;
    QByteArray requirement;
};

HelperIdentity loadHelperIdentity();
// Allows offline tests to use a temporary path owned by the test process.
HelperIdentity loadHelperIdentity(const QByteArray &path, uid_t expectedOwner);

XpcReadOnlyClientResult queryTrustedHelperStatus(
    const HelperIdentity &identity,
    const std::function<XpcReadOnlyClientResult(const QByteArray &)> &trustedRequest);

} // namespace interceptor
