#include "ArpLabProbeRunner.hpp"

namespace interceptor {

ArpLabProbeResult ArpLabProbeRunner::run(const ArpLabProbePlan &plan, ArpPacketIo &packetIo,
                                         ArpProbeWaiter &waiter, int durationMs) {
    ArpLabProbeResult result;
    if (durationMs < 1 || durationMs > maximumDurationMs) {
        result.status = ArpLabProbeStatus::InvalidDuration;
        return result;
    }
    try {
        if (waiter.interrupted()) {
            result.status = ArpLabProbeStatus::InterruptedBeforeRedirect;
            result.interrupted = true;
            return result;
        }
    } catch (...) {
        result.status = ArpLabProbeStatus::CleanupUncertain;
        return result;
    }

    result.redirectAttempted = true;
    try {
        result.redirectWriteAccepted =
            packetIo.sendFrame(plan.interfaceName(), plan.redirectionFrame());
    } catch (...) {
        result.redirectWriteAccepted = false;
    }

    bool waitFailed = false;
    if (result.redirectWriteAccepted) {
        try {
            const auto waitResult = waiter.waitFor(durationMs);
            result.interrupted =
                waitResult == ArpProbeWaitOutcome::Interrupted || waiter.interrupted();
        } catch (...) {
            waitFailed = true;
        }
    } else {
        // A failed packet write may have been partially accepted. Correct immediately and
        // report the original write as uncertain; never retry the redirect frame.
        try {
            result.interrupted = waiter.interrupted();
        } catch (...) {
            waitFailed = true;
        }
    }

    result.restorationAttempted = true;
    try {
        result.restorationWriteAccepted =
            packetIo.sendFrame(plan.interfaceName(), plan.restorationFrame());
    } catch (...) {
        result.restorationWriteAccepted = false;
    }
    if (!result.restorationWriteAccepted) {
        result.status = ArpLabProbeStatus::CleanupUncertain;
    } else if (waitFailed) {
        result.status = ArpLabProbeStatus::CleanupUncertain;
    } else if (!result.redirectWriteAccepted) {
        result.status = ArpLabProbeStatus::RedirectWriteUncertainCorrectionAccepted;
    } else if (result.interrupted) {
        result.status = ArpLabProbeStatus::CorrectionWriteAcceptedAfterSignal;
    } else {
        result.status = ArpLabProbeStatus::CorrectionWriteAcceptedAfterTimeout;
    }
    return result;
}

} // namespace interceptor
