#include "ArpRedirectRefresher.hpp"

#include <QTimer>

namespace interceptor {
namespace {

class QtArpRefreshTimer final : public QObject, public ArpRefreshTimer {
  public:
    QtArpRefreshTimer() {
        QObject::connect(&timer_, &QTimer::timeout, this, [this]() {
            if (timeoutHandler_)
                timeoutHandler_();
        });
    }

    void setTimeoutHandler(std::function<void()> handler) override {
        timeoutHandler_ = std::move(handler);
    }
    void start(int intervalMs) override { timer_.start(intervalMs); }
    void stop() override { timer_.stop(); }
    bool isActive() const override { return timer_.isActive(); }

  private:
    QTimer timer_;
    std::function<void()> timeoutHandler_;
};

bool sendAll(ArpPacketIo &packetIo, const QString &interfaceName, const QList<QByteArray> &frames) {
    bool accepted = true;
    for (const auto &frame : frames) {
        if (!packetIo.sendFrame(interfaceName, frame))
            accepted = false;
    }
    return accepted;
}

} // namespace

ArpRedirectRefresher::ArpRedirectRefresher(ArpPacketIo &packetIo,
                                           std::unique_ptr<ArpRefreshTimer> timer, int intervalMs)
    : packetIo_(packetIo),
      timer_(timer ? std::move(timer) : std::make_unique<QtArpRefreshTimer>()) {
    if (intervalMs >= minimumIntervalMs && intervalMs <= maximumIntervalMs)
        intervalMs_ = intervalMs;
    timer_->setTimeoutHandler([this] { tick(); });
}

ArpRedirectRefresher::~ArpRedirectRefresher() {
    // Destruction never sends frames; a session destroyed with a live or failed refresh keeps
    // its cleanup obligation with the session's own endArp/restoreNeighbors path.
    if (timer_)
        timer_->stop();
}

bool ArpRedirectRefresher::start(const SessionSnapshot &snapshot) {
    if (status_ == ArpRedirectRefresherStatus::Refreshing ||
        status_ == ArpRedirectRefresherStatus::CorrectionAttempted)
        return false;
    redirectFrames_ = snapshot.redirectionFrames();
    correctiveFrames_ = snapshot.restorationFrames();
    interfaceName_ = snapshot.facts().interfaceName;
    if (redirectFrames_.isEmpty() || correctiveFrames_.isEmpty())
        return false;

    // Initial pairwise redirection; the refresh loop then re-announces only the client mapping.
    if (sendAll(packetIo_, interfaceName_, redirectFrames_)) {
        status_ = ArpRedirectRefresherStatus::Refreshing;
        timer_->start(intervalMs_);
        return true;
    }
    // Failed or uncertain initial redirect: correct immediately, keep every obligation.
    status_ = sendAll(packetIo_, interfaceName_, correctiveFrames_)
                  ? ArpRedirectRefresherStatus::CorrectionAttempted
                  : ArpRedirectRefresherStatus::CorrectionUncertain;
    return false;
}

void ArpRedirectRefresher::tick() {
    if (status_ != ArpRedirectRefresherStatus::Refreshing)
        return;
    if (!redirectFrames_.isEmpty() && packetIo_.sendFrame(interfaceName_, redirectFrames_.first()))
        return;
    // A failed or uncertain refresh tick: cease refreshing and correct immediately.
    timer_->stop();
    status_ = sendAll(packetIo_, interfaceName_, correctiveFrames_)
                  ? ArpRedirectRefresherStatus::CorrectionAttempted
                  : ArpRedirectRefresherStatus::CorrectionUncertain;
}

bool ArpRedirectRefresher::stop() {
    if (status_ == ArpRedirectRefresherStatus::Refreshing)
        timer_->stop();
    if (status_ == ArpRedirectRefresherStatus::Inactive)
        return true; // nothing to cease; the session's restoration path still re-corrects
    status_ = sendAll(packetIo_, interfaceName_, correctiveFrames_)
                  ? ArpRedirectRefresherStatus::CorrectionAttempted
                  : ArpRedirectRefresherStatus::CorrectionUncertain;
    return status_ == ArpRedirectRefresherStatus::CorrectionAttempted;
}

bool ArpRedirectRefresher::redirectHealthy() const {
    // A correction after a failed refresh means the redirect loop is no longer running: the
    // session must stop and keep its cleanup obligations (a corrective attempt may have failed).
    return status_ == ArpRedirectRefresherStatus::Refreshing ||
           status_ == ArpRedirectRefresherStatus::Inactive;
}

} // namespace interceptor
