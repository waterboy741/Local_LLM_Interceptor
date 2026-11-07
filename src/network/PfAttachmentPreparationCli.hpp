#pragma once

#include <QByteArray>
#include <QString>
#include <QStringList>

namespace interceptor {

enum class PfSyntaxCheckStatus {
    Valid,
    Rejected,
    Failed,
    TimedOut,
    OutputLimitExceeded,
    UnsupportedPlatform
};

class PfSyntaxCheckRunner {
  public:
    virtual ~PfSyntaxCheckRunner() = default;
    // Implementations must parse only; they must never load or enable PF.
    virtual PfSyntaxCheckStatus check(const QByteArray &rules) = 0;
};

struct PfAttachmentPreparationResult {
    int exitCode = 2;
    QString standardOutput;
    QString standardError;
};

class PfAttachmentPreparationCli {
  public:
    static QByteArray attachmentRules();
    // Arguments include argv[0], as with QCommandLineParser::parse.
    static PfAttachmentPreparationResult run(const QStringList &arguments);
    static PfAttachmentPreparationResult run(const QStringList &arguments,
                                             PfSyntaxCheckRunner &runner);
};

} // namespace interceptor
