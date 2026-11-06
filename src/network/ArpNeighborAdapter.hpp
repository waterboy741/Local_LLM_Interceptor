#pragma once

#include "NetworkSession.hpp"

#include <QByteArray>
#include <QString>

namespace interceptor {

// Packet writers are supplied by the caller. This repository deliberately has no live
// implementation; tests and offline callers can inject a deterministic fake.
class ArpPacketIo {
  public:
    virtual ~ArpPacketIo() = default;

    // Return true only when the complete Ethernet frame was accepted. A false result may
    // still follow a partial write, so callers must treat it as potentially applied.
    virtual bool sendFrame(const QString &interfaceName, const QByteArray &frame) = 0;
};

enum class ArpSendStatus { Completed, InvalidPlan, WriteFailed };

struct ArpSendResult {
    ArpSendStatus status = ArpSendStatus::InvalidPlan;
    int attemptedFrames = 0;
    int completedFrames = 0;

    bool success() const { return status == ArpSendStatus::Completed; }
    bool mayHaveApplied() const {
        return completedFrames > 0 ||
               (status == ArpSendStatus::WriteFailed && attemptedFrames > completedFrames);
    }
};

// Executes only the immutable pairwise ARP plans already held by SessionSnapshot.
// Calls are synchronous on the caller's thread and stop at the first writer failure.
class ArpNeighborAdapter {
  public:
    explicit ArpNeighborAdapter(ArpPacketIo &packetIo) : packetIo_(packetIo) {}

    ArpSendResult sendRedirection(const SessionSnapshot &snapshot);
    ArpSendResult sendRestoration(const SessionSnapshot &snapshot);

  private:
    ArpSendResult sendPlan(const SessionSnapshot &snapshot, const QList<QByteArray> &frames);
    ArpPacketIo &packetIo_;
};

} // namespace interceptor
