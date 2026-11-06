#pragma once

#include "ArpLabProbePlan.hpp"
#include "ArpNeighborAdapter.hpp"

namespace interceptor {

enum class ArpProbeWaitOutcome { Elapsed, Interrupted };

class ArpProbeWaiter {
  public:
    virtual ~ArpProbeWaiter() = default;
    virtual bool interrupted() const = 0;
    virtual ArpProbeWaitOutcome waitFor(int durationMs) = 0;
};

enum class ArpLabProbeStatus {
    CorrectionWriteAcceptedAfterTimeout,
    CorrectionWriteAcceptedAfterSignal,
    RedirectWriteUncertainCorrectionAccepted,
    CleanupUncertain,
    InterruptedBeforeRedirect,
    InvalidDuration
};

struct ArpLabProbeResult {
    ArpLabProbeStatus status = ArpLabProbeStatus::CleanupUncertain;
    bool redirectAttempted = false;
    bool redirectWriteAccepted = false;
    bool restorationAttempted = false;
    bool restorationWriteAccepted = false;
    bool interrupted = false;

    // True means the redirect/correction write sequence completed locally. It does not
    // establish that either ARP update reached or changed the client's neighbor cache.
    bool writeSequenceComplete() const {
        return restorationWriteAccepted && status != ArpLabProbeStatus::CleanupUncertain &&
               status != ArpLabProbeStatus::InvalidDuration &&
               status != ArpLabProbeStatus::InterruptedBeforeRedirect;
    }
};

class ArpLabProbeRunner {
  public:
    static constexpr int maximumDurationMs = 5000;

    static ArpLabProbeResult run(const ArpLabProbePlan &plan, ArpPacketIo &packetIo,
                                 ArpProbeWaiter &waiter, int durationMs);
};

} // namespace interceptor
