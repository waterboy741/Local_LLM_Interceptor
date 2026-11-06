#pragma once

#include "MacBpfArpPacketIo.hpp"

#include <QString>
#include <QStringList>

namespace interceptor {

struct ArpBpfReadinessCliResult {
    int exitCode = 2;
    QString standardOutput;
    QString standardError;
};

class ArpBpfReadinessCli {
  public:
    // Arguments include argv[0], as with QCommandLineParser::parse.
    static ArpBpfReadinessCliResult run(const QStringList &arguments);
    static ArpBpfReadinessCliResult run(const QStringList &arguments, BpfSystemCalls &systemCalls);
};

} // namespace interceptor
