#pragma once

#include <string>
#include <sys/types.h>

namespace interceptor {

// Fails closed if the filesystem reports an extended ACL or cannot inspect it.
bool hasNoExtendedAcl(int fd);

// Returns a close-on-exec descriptor owned by the caller, or -1 on failure.
int openHelperStateDirectory(const char *absolutePath, uid_t expectedOwner,
                             std::string *error = nullptr);

} // namespace interceptor
