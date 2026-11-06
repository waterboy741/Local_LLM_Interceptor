#include "network/ArpBpfReadinessCli.hpp"

#include <QCoreApplication>
#include <QTextStream>

using namespace interceptor;

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName("arp_bpf_readiness");
    QCoreApplication::setApplicationVersion("0.1.0");

    const auto result = ArpBpfReadinessCli::run(app.arguments());
    if (!result.standardOutput.isEmpty())
        QTextStream(stdout) << result.standardOutput;
    if (!result.standardError.isEmpty())
        QTextStream(stderr) << result.standardError;
    return result.exitCode;
}
