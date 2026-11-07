#pragma once

#include "PfAttachmentPreparationCli.hpp"

#include <QByteArray>
#include <QIODevice>
#include <QString>
#include <QStringList>

namespace interceptor {

enum class PfConfigMergeStatus {
    Merged,
    InvalidEncoding,
    InvalidLineEndings,
    MissingTranslationMarker,
    DuplicateTranslationMarker,
    MissingFilterMarker,
    DuplicateFilterMarker,
    InvalidSectionOrder,
    UnsupportedContinuation,
    ExistingApplicationReference
};

struct PfConfigMergeResult {
    PfConfigMergeStatus status = PfConfigMergeStatus::InvalidEncoding;
    QByteArray candidate;
};

class PfConfigAttachmentMerger {
  public:
    static PfConfigMergeResult merge(const QByteArray &existingConfig);
};

class PfAttachmentMergeCli {
  public:
    static constexpr qsizetype maximumInputBytes = 1024 * 1024;
    enum class InputStatus { Complete, ReadFailed, LimitExceeded };
    static InputStatus readBoundedInput(QIODevice &input, QByteArray *contents);
    // Arguments include argv[0], as with QCommandLineParser::parse.
    static PfAttachmentPreparationResult run(const QStringList &arguments);
    static PfAttachmentPreparationResult run(const QStringList &arguments,
                                             const QByteArray &existingConfig,
                                             PfSyntaxCheckRunner &runner);
};

} // namespace interceptor
