#include "network/InstalledHelperBootstrap.hpp"

#include <QCoreApplication>
#include <QTextStream>

#include <limits>
#include <unistd.h>

namespace {
bool processArguments(const QStringList &args, QString *statePath, int *bootstrapFd) {
    if (args.size() != 6 || args.at(1) != QStringLiteral("--process") ||
        args.at(2) != QStringLiteral("--state-dir") ||
        args.at(4) != QStringLiteral("--bootstrap-fd"))
        return false;
    bool validFd = false;
    const qulonglong parsedFd = args.at(5).toULongLong(&validFd, 10);
    if (!validFd || parsedFd > static_cast<qulonglong>(std::numeric_limits<int>::max()))
        return false;
    *statePath = args.at(3);
    *bootstrapFd = static_cast<int>(parsedFd);
    return true;
}
} // namespace

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    QTextStream err(stderr);
    const QStringList args = app.arguments();
    const bool checkingStateDirectory =
        args.size() == 3 && args.at(1) == QStringLiteral("--check-state-dir");
    QString statePath;
    int bootstrapFd = -1;
    const bool requestingProcess = processArguments(args, &statePath, &bootstrapFd);
    if (!checkingStateDirectory && !requestingProcess) {
        err << "usage: llm_interceptor_helper --check-state-dir ABSOLUTE_PATH\n"
               "       llm_interceptor_helper --process --state-dir ABSOLUTE_PATH "
               "--bootstrap-fd FD\n";
        return 2;
    }
    if (::geteuid() != 0) {
        err << "effective_root_required\n";
        return 3;
    }
    if (checkingStateDirectory)
        statePath = args.at(2);

    QString failure;
    auto directory = interceptor::InstalledHelperStateDirectory::open(statePath, 0, &failure);
    if (!directory) {
        err << failure << '\n';
        return 4;
    }
    if (requestingProcess) {
        Q_UNUSED(bootstrapFd);
        err << "production_peer_authenticator_unavailable\n";
        return 5;
    }
    QTextStream(stdout) << "state_directory_ready\n";
    return 0;
}
