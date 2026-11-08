#pragma once

#include "PfAttachmentPreparationCli.hpp"

namespace interceptor {
class PfSessionPreviewCli {
  public:
    static PfAttachmentPreparationResult run(const QStringList &arguments);
    static PfAttachmentPreparationResult run(const QStringList &arguments,
                                             PfSyntaxCheckRunner &runner);
};
} // namespace interceptor
