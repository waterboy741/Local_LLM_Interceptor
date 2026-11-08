#include "network/InstalledHelperBootstrap.hpp"

#include <QCoreApplication>
#include <QTextStream>

#include <unistd.h>

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    QTextStream err(stderr);
    const QStringList args = app.arguments();
    if (args.size() != 3 || args.at(1) != QStringLiteral("--check-state-dir")) {
        err << "usage: llm_interceptor_helper --check-state-dir ABSOLUTE_PATH\n";
        return 2;
    }
    if (::geteuid() != 0) {
        err << "effective_root_required\n";
        return 3;
    }
    QString failure;
    auto directory = interceptor::InstalledHelperStateDirectory::open(args.at(2), 0, &failure);
    if (!directory) {
        err << failure << '\n';
        return 4;
    }
    QTextStream(stdout) << "state_directory_ready\n";
    return 0;
}
