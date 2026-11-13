#pragma once

#include <QByteArray>
#include <QStringList>

namespace interceptor {

struct CodesignCommandResult {
    bool started = false;
    bool normalExit = false;
    bool timedOut = false;
    int exitCode = -1;
    QByteArray standardOutput;
    QByteArray standardError;
};

class CodesignCommandRunner {
  public:
    virtual ~CodesignCommandRunner() = default;
    virtual CodesignCommandResult run(const QStringList &arguments, int timeoutMs,
                                      qsizetype outputLimitBytes) = 0;
};

class MachServiceIdentityPreviewCli {
  public:
    // Arguments include argv[0], as with QCommandLineParser::parse.
    static CodesignCommandResult run(const QStringList &arguments);
    static CodesignCommandResult run(const QStringList &arguments, CodesignCommandRunner &runner);
};

} // namespace interceptor
