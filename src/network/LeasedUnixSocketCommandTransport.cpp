#include "LeasedUnixSocketCommandTransport.hpp"

#include "UnixSocketCommandTransport.hpp"

#include <QThread>

namespace interceptor {

bool dispatchOneLeasedUnixSocketCommand(int connectedSocketFd, const HostSessionLease &lease,
                                        HelperDispatcher &dispatcher, QString *error) {
    if (!lease.acquired()) {
        if (error)
            *error = QStringLiteral("host_session_lease_required");
        return false;
    }
    if (QThread::currentThread() != dispatcher.thread()) {
        if (error)
            *error = QStringLiteral("dispatcher_thread_required");
        return false;
    }
    return dispatchOneUnixSocketCommand(connectedSocketFd, dispatcher, error);
}

} // namespace interceptor
