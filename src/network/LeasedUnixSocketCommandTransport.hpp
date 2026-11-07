#pragma once

#include "HelperDispatcher.hpp"
#include "HostSessionLease.hpp"

namespace interceptor {

// Dispatches one kernel-peer-credential-authenticated command only while the caller holds the
// host-wide session lease. The lease coordinates only helpers using the same canonical private
// directory inode. Call from the dispatcher's owner thread and keep the lease alive and unreleased
// for the whole call; concurrent release is unsupported. This wrapper does not bind the lock to a
// specific dispatcher identity. The caller retains ownership of the connected socket and must
// close it afterward.
bool dispatchOneLeasedUnixSocketCommand(int connectedSocketFd, const HostSessionLease &lease,
                                        HelperDispatcher &dispatcher, QString *error = nullptr);

} // namespace interceptor
