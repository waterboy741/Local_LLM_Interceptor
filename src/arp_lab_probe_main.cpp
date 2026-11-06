#include "network/ArpLabProbeCli.hpp"

#include <QCoreApplication>
#include <QTextStream>

using namespace interceptor;

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName("arp_lab_probe");
    QCoreApplication::setApplicationVersion("0.1.0");

    const auto result = ArpLabProbeCli::run(app.arguments());
    if (!result.standardOutput.isEmpty())
        QTextStream(stdout) << result.standardOutput;
    if (!result.standardError.isEmpty())
        QTextStream(stderr) << result.standardError;
    return result.exitCode;
}
