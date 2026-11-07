#pragma once

#include "PfDiagnostics.hpp"

#include <QStringList>

namespace interceptor {

struct PfReadinessCliResult {
    int exitCode = 2;
    QString standardOutput;
    QString standardError;
};

class PfReadinessCli {
  public:
    // Arguments include argv[0], as with QCommandLineParser::parse.
    static PfReadinessCliResult run(const QStringList &arguments);
    static PfReadinessCliResult run(const QStringList &arguments, PfCommandRunner &runner);
};

} // namespace interceptor
