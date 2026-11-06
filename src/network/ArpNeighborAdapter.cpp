#include "ArpNeighborAdapter.hpp"

#include "ArpCodec.hpp"

namespace interceptor {

ArpSendResult ArpNeighborAdapter::sendRedirection(const SessionSnapshot &snapshot) {
    return sendPlan(snapshot, snapshot.redirectionFrames());
}

ArpSendResult ArpNeighborAdapter::sendRestoration(const SessionSnapshot &snapshot) {
    return sendPlan(snapshot, snapshot.restorationFrames());
}

ArpSendResult ArpNeighborAdapter::sendPlan(const SessionSnapshot &snapshot,
                                           const QList<QByteArray> &frames) {
    if (frames.size() != 2)
        return {ArpSendStatus::InvalidPlan, 0, 0};

    // Validate the full batch before the first I/O call so malformed plans cannot send only
    // one peer update. These are fixed Ethernet/IPv4 ARP replies padded to the minimum size.
    for (const auto &frame : frames) {
        const auto packet = ArpCodec::parse(frame);
        if (frame.size() != 60 || !packet || packet->operation != 2)
            return {ArpSendStatus::InvalidPlan, 0, 0};
    }

    ArpSendResult result{ArpSendStatus::Completed, 0, 0};
    for (const auto &frame : frames) {
        ++result.attemptedFrames;
        if (!packetIo_.sendFrame(snapshot.config().interfaceName, frame)) {
            result.status = ArpSendStatus::WriteFailed;
            return result;
        }
        ++result.completedFrames;
    }
    return result;
}

} // namespace interceptor
