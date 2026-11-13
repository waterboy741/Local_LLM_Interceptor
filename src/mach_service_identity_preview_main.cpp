#include "network/MachServiceIdentityPreviewCli.hpp"

#include <QCoreApplication>
#include <QTextStream>

using namespace interceptor;

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName("mach_service_identity_preview");
    QCoreApplication::setApplicationVersion("0.1.0");

    const auto result = MachServiceIdentityPreviewCli::run(app.arguments());
    if (!result.standardOutput.isEmpty())
        QTextStream(stdout) << QString::fromUtf8(result.standardOutput);
    if (!result.standardError.isEmpty())
        QTextStream(stderr) << QString::fromUtf8(result.standardError);
    return result.exitCode;
}
