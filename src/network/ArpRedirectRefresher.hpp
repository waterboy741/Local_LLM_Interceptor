#pragma once

#include "ArpNeighborAdapter.hpp"
#include "NetworkSession.hpp"

#include <QString>

#include <functional>
#include <memory>

namespace interceptor {

// Injectable repeating-timer seam for the ARP redirect refresher. Production uses the Qt timer
// implementation defined in the source file; tests inject a deterministic fake.
class ArpRefreshTimer {
  public:
    virtual ~ArpRefreshTimer() = default;
    virtual void setTimeoutHandler(std::function<void()> handler) = 0;
    virtual void start(int intervalMs) = 0;
    virtual void stop() = 0;
    virtual bool isActive() const = 0;
};

enum class ArpRedirectRefresherStatus {
    Inactive,
    Refreshing,
    CorrectionAttempted,
    CorrectionUncertain
};

// Session-long bounded ARP redirect refresh loop for backlog package C. While active it
// re-announces only the client mapping for the server IP on a bounded interval; Stop and every
// failed or uncertain redirect immediately cease refreshing and send the full pairwise
// corrective frames. All methods must run on one thread (the session owner thread); the timer
// seam must dispatch its handler on that same thread. An accepted write is only BPF's local
// acceptance of one frame; it is not proof that the client's neighbor cache changed.
class ArpRedirectRefresher final {
  public:
    static constexpr int minimumIntervalMs = 250;
    static constexpr int maximumIntervalMs = 2000;
    static constexpr int defaultIntervalMs = 500;

    ArpRedirectRefresher(ArpPacketIo &packetIo, std::unique_ptr<ArpRefreshTimer> timer = nullptr,
                         int intervalMs = defaultIntervalMs);
    ~ArpRedirectRefresher();

    ArpRedirectRefresher(const ArpRedirectRefresher &) = delete;
    ArpRedirectRefresher &operator=(const ArpRedirectRefresher &) = delete;
    ArpRedirectRefresher(ArpRedirectRefresher &&) = delete;
    ArpRedirectRefresher &operator=(ArpRedirectRefresher &&) = delete;

    // Sends the pairwise redirection frames once and starts the bounded client-mapping refresh.
    // A failed or uncertain initial redirection attempts the corrective frames immediately and
    // returns false; the session must then treat its cleanup obligations as retained.
    bool start(const SessionSnapshot &snapshot);

    // Stops refreshing and sends the pairwise corrective frames once. Idempotent: it also
    // corrects after a failed refresh tick. Returns true only when every corrective frame was
    // accepted by the writer.
    bool stop();

    // Session health signal: true while the refresh loop is running or has never begun cleanly.
    bool redirectHealthy() const;
    ArpRedirectRefresherStatus status() const noexcept { return status_; }
    bool isActive() const noexcept { return status_ == ArpRedirectRefresherStatus::Refreshing; }

  private:
    void tick();

    ArpPacketIo &packetIo_;
    std::unique_ptr<ArpRefreshTimer> timer_;
    QList<QByteArray> redirectFrames_;
    QList<QByteArray> correctiveFrames_;
    QString interfaceName_;
    int intervalMs_ = defaultIntervalMs;
    ArpRedirectRefresherStatus status_ = ArpRedirectRefresherStatus::Inactive;
};

} // namespace interceptor
