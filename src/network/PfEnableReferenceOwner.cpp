#include "PfEnableReferenceOwner.hpp"

#include <QRegularExpression>

namespace interceptor {
namespace {
const QString pfctlPath = QStringLiteral("/sbin/pfctl");

QString commandStatus(PfEnableReferenceCommandStatus status) {
    switch (status) {
    case PfEnableReferenceCommandStatus::Completed:
        return QStringLiteral("command_completed");
    case PfEnableReferenceCommandStatus::PermissionDenied:
        return QStringLiteral("permission_denied");
    case PfEnableReferenceCommandStatus::TimedOut:
        return QStringLiteral("timed_out");
    case PfEnableReferenceCommandStatus::OutputLimitExceeded:
        return QStringLiteral("output_limit_exceeded");
    case PfEnableReferenceCommandStatus::Failed:
        return QStringLiteral("command_failed");
    }
    return QStringLiteral("command_failed");
}

bool completed(const PfEnableReferenceCommandResult &result) {
    return result.status == PfEnableReferenceCommandStatus::Completed && result.started &&
           result.processReaped && result.exitCode == 0;
}
} // namespace

QString PfEnableReferenceCommand::program() const { return pfctlPath; }

QStringList PfEnableReferenceCommand::arguments() const {
    if (operation_ == PfEnableReferenceOperation::Acquire)
        return {"-E"};
    return {"-X", QString::number(token_)};
}

std::optional<quint64> PfEnableReferenceOwner::parseTokenOutput(const QByteArray &output) {
    if (output.size() > maximumOutputBytes || QString::fromUtf8(output).toUtf8() != output)
        return std::nullopt;
    static const QRegularExpression tokenLine(R"(^[\t ]*Token[\t ]*:[\t ]*([0-9]{1,20})[\t ]*$)");
    std::optional<quint64> token;
    const auto lines = QString::fromUtf8(output).split('\n');
    for (auto line : lines) {
        if (line.endsWith('\r'))
            line.chop(1);
        if (line.trimmed().isEmpty())
            continue;
        const auto match = tokenLine.match(line);
        if (!match.hasMatch() || token)
            return std::nullopt;
        bool valid = false;
        const auto parsed = match.captured(1).toULongLong(&valid, 10);
        if (!valid || parsed == 0)
            return std::nullopt;
        token = parsed;
    }
    return token;
}

PfEnableReferenceResult PfEnableReferenceOwner::acquire() {
    if (state_ != PfEnableReferenceState::Unacquired)
        return {false,
                state_ == PfEnableReferenceState::AcquireUncertain ||
                    state_ == PfEnableReferenceState::Acquiring ||
                    state_ == PfEnableReferenceState::Owned ||
                    state_ == PfEnableReferenceState::ReleaseUncertain,
                state_ == PfEnableReferenceState::Acquiring
                    ? QStringLiteral("acquisition_in_progress")
                : state_ == PfEnableReferenceState::AcquireUncertain
                    ? QStringLiteral("acquisition_uncertain")
                    : QStringLiteral("acquisition_not_available"),
                token_, std::nullopt};

    state_ = PfEnableReferenceState::Acquiring;
    PfEnableReferenceCommandResult result;
    try {
        result = runner_.execute(PfEnableReferenceCommand(PfEnableReferenceOperation::Acquire),
                                 commandTimeoutMs, maximumOutputBytes);
    } catch (...) {
        state_ = PfEnableReferenceState::AcquireUncertain;
        return {false, true, QStringLiteral("acquisition_uncertain"), std::nullopt, std::nullopt};
    }

    if (!result.started) {
        state_ = PfEnableReferenceState::Unacquired;
        return {false,
                false,
                commandStatus(result.status),
                std::nullopt,
                PfEnableReferenceAcquireNotStartedReceipt{},
                std::nullopt};
    }
    const auto parsedToken = parseTokenOutput(result.standardOutput);
    if (parsedToken) {
        token_ = parsedToken;
        if (!result.processReaped) {
            state_ = PfEnableReferenceState::AcquireUncertain;
            return {false, true, QStringLiteral("acquisition_uncertain_token_captured"), token_,
                    std::nullopt};
        }
        state_ = PfEnableReferenceState::Owned;
        if (completed(result))
            return {true, false, QStringLiteral("acquired"), token_, std::nullopt};
        return {false, true, QStringLiteral("acquisition_uncertain_token_captured"), token_,
                std::nullopt};
    }
    state_ = PfEnableReferenceState::AcquireUncertain;
    return {false, true, QStringLiteral("acquisition_uncertain_token_unknown"), std::nullopt,
            std::nullopt};
}

PfEnableReferenceResult PfEnableReferenceOwner::release() {
    if (state_ == PfEnableReferenceState::Released)
        return {false, false, QStringLiteral("already_released"), std::nullopt, std::nullopt};
    if (state_ == PfEnableReferenceState::Acquiring)
        return {false, true, QStringLiteral("acquisition_in_progress"), std::nullopt, std::nullopt};
    if (state_ == PfEnableReferenceState::AcquireUncertain)
        return {false, true,
                token_ ? QStringLiteral("acquisition_uncertain_token_captured")
                       : QStringLiteral("acquisition_uncertain_token_unknown"),
                token_, std::nullopt};
    if (state_ == PfEnableReferenceState::ReleaseUncertain)
        return {false, true, QStringLiteral("release_already_attempted"), token_, std::nullopt};
    if (state_ != PfEnableReferenceState::Owned || !token_)
        return {false, false, QStringLiteral("no_owned_reference"), std::nullopt, std::nullopt};

    const auto token = token_;
    // Mark before calling the injected runner so exceptions and reentrant calls cannot release
    // twice.
    state_ = PfEnableReferenceState::ReleaseUncertain;
    PfEnableReferenceCommandResult result;
    try {
        result =
            runner_.execute(PfEnableReferenceCommand(PfEnableReferenceOperation::Release, *token),
                            commandTimeoutMs, maximumOutputBytes);
    } catch (...) {
        return {false, true, QStringLiteral("release_uncertain"), token_, std::nullopt};
    }
    if (completed(result)) {
        state_ = PfEnableReferenceState::Released;
        token_.reset();
        return {true,         false,        QStringLiteral("released"),
                std::nullopt, std::nullopt, PfEnableReferenceReleaseReceipt(*token)};
    }
    return {false, true,
            QStringLiteral("release_uncertain") + QStringLiteral("_") +
                commandStatus(result.status),
            token_, std::nullopt};
}

} // namespace interceptor
