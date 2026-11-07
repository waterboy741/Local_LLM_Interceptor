#include "network/PfAttachmentMergeCli.hpp"

#include <QCoreApplication>
#include <QTextStream>

using namespace interceptor;

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName("pf_attachment_merge");
    QCoreApplication::setApplicationVersion("0.1.0");

    const auto result = PfAttachmentMergeCli::run(app.arguments());
    if (!result.standardOutput.isEmpty())
        QTextStream(stdout) << result.standardOutput;
    if (!result.standardError.isEmpty())
        QTextStream(stderr) << result.standardError;
    return result.exitCode;
}
