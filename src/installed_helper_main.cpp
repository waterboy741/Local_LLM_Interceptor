#include "network/InstalledHelperBootstrap.hpp"
#include "network/LaunchdMachServiceBootstrap.hpp"
#include "network/MachServicePeerAuthenticator.hpp"
#include "network/XpcControlRequestGate.hpp"
#include "network/XpcReadOnlyServiceListener.hpp"

#include <QCoreApplication>
#include <QTextStream>

#include <limits>
#include <memory>
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
    const bool requestingMachService = args.size() == 4 &&
                                       args.at(1) == QStringLiteral("--mach-service") &&
                                       args.at(2) == QStringLiteral("--state-dir");
    QString statePath;
    int bootstrapFd = -1;
    const bool requestingProcess = processArguments(args, &statePath, &bootstrapFd);
    if (!checkingStateDirectory && !requestingProcess && !requestingMachService) {
        err << "usage: llm_interceptor_helper --check-state-dir ABSOLUTE_PATH\n"
               "       llm_interceptor_helper --process --state-dir ABSOLUTE_PATH "
               "--bootstrap-fd FD\n"
               "       llm_interceptor_helper --mach-service --state-dir PATH\n";
        return 2;
    }
    if (::geteuid() != 0) {
        err << "effective_root_required\n";
        return 3;
    }
    if (checkingStateDirectory)
        statePath = args.at(2);
    else if (requestingMachService)
        statePath = args.at(3);

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
    if (requestingMachService) {
        interceptor::LaunchdMachServiceConfig config;
        if (!interceptor::loadLaunchdMachServiceConfig(directory->descriptor(), &config,
                                                       &failure)) {
            err << failure << '\n';
            return 6;
        }

        interceptor::MacXpcPeerCodeSignaturePolicy peerPolicy;
        std::unique_ptr<interceptor::XpcControlRequestGate> gate;
        std::unique_ptr<interceptor::XpcReadOnlyControlAdapter> adapter;
        std::unique_ptr<interceptor::XpcReadOnlyServiceListener> listener;
        const bool started = interceptor::startConfiguredLaunchdMachService(
            config,
            [&](const QByteArray &serviceName, const QByteArray &trustedRequirement,
                QString *startError) {
                gate = std::make_unique<interceptor::XpcControlRequestGate>(trustedRequirement,
                                                                            peerPolicy);
                adapter = std::make_unique<interceptor::XpcReadOnlyControlAdapter>(*gate);
                listener = std::make_unique<interceptor::XpcReadOnlyServiceListener>(serviceName,
                                                                                     *adapter);
                return listener->start(startError);
            },
            &failure);
        if (!started) {
            err << failure << '\n';
            return 7;
        }
        return app.exec();
    }
    QTextStream(stdout) << "state_directory_ready\n";
    return 0;
}
