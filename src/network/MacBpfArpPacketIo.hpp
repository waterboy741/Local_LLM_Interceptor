#pragma once

#include "ArpLabProbePlan.hpp"
#include "ArpNeighborAdapter.hpp"

#include <QString>

namespace interceptor {

enum class BpfArpWriterStatus {
    Ready,
    InvalidInterface,
    UnsupportedPlatform,
    OpenFailed,
    AttachFailed,
    UnsupportedLinkType,
    HeaderCompleteFailed,
    InvalidFrame,
    InterfaceMismatch,
    WriteFailed,
    CloseFailed,
    NotReady
};

struct BpfReadinessResult {
    BpfArpWriterStatus status = BpfArpWriterStatus::NotReady;
    bool deviceOpened = false;
    bool interfaceBound = false;
    bool ethernetLink = false;
    bool headerComplete = false;
    bool closeConfirmed = false;

    bool ready() const {
        return status == BpfArpWriterStatus::Ready && deviceOpened && interfaceBound &&
               ethernetLink && headerComplete && closeConfirmed;
    }
};

// Narrow seam around the system calls used by the macOS BPF writer. The overload accepting
// this interface is intended for deterministic tests; production uses the native calls.
class BpfSystemCalls {
  public:
    virtual ~BpfSystemCalls() = default;
    virtual int openDevice(const QString &path, int flags, int &errorNumber) = 0;
    virtual int ioctlDevice(int descriptor, unsigned long request, void *argument) = 0;
    virtual qint64 writeDevice(int descriptor, const char *data, qsizetype size) = 0;
    virtual int closeDevice(int descriptor) = 0;
};

// Opens and binds one BPF descriptor at construction. It has no refresh loop and is not
// connected to session startup or cleanup. A successful write only means BPF accepted the
// complete frame; it is not evidence that a peer received or accepted the ARP update.
class MacBpfArpPacketIo final : public ArpPacketIo {
  public:
    static constexpr int maximumDeviceIndex = 255;
    static constexpr qsizetype arpFrameSize = 60;

    explicit MacBpfArpPacketIo(const SessionSnapshot &snapshot);
    MacBpfArpPacketIo(const SessionSnapshot &snapshot, BpfSystemCalls &systemCalls);
    explicit MacBpfArpPacketIo(const ArpLabProbePlan &plan);
    MacBpfArpPacketIo(const ArpLabProbePlan &plan, BpfSystemCalls &systemCalls);
    ~MacBpfArpPacketIo() override;

    MacBpfArpPacketIo(const MacBpfArpPacketIo &) = delete;
    MacBpfArpPacketIo &operator=(const MacBpfArpPacketIo &) = delete;
    MacBpfArpPacketIo(MacBpfArpPacketIo &&) = delete;
    MacBpfArpPacketIo &operator=(MacBpfArpPacketIo &&) = delete;

    bool isReady() const { return descriptor_ >= 0; }
    BpfArpWriterStatus status() const { return status_; }
    const QString &interfaceName() const { return interfaceName_; }
    bool lastWriteMayHaveApplied() const { return lastWriteMayHaveApplied_; }

    static BpfReadinessResult probeReadiness(const QString &interfaceName);
    static BpfReadinessResult probeReadiness(const QString &interfaceName,
                                             BpfSystemCalls &systemCalls);

    bool sendFrame(const QString &interfaceName, const QByteArray &frame) override;
    bool close();

  private:
    void initialize();
    bool validFrame(const QByteArray &frame) const;
    void failAndClose(BpfArpWriterStatus status);
    MacBpfArpPacketIo(const QString &interfaceName, QList<QByteArray> allowedFrames,
                      BpfSystemCalls &systemCalls);

    QString interfaceName_;
    QList<QByteArray> allowedFrames_;
    BpfSystemCalls &systemCalls_;
    int descriptor_ = -1;
    BpfArpWriterStatus status_ = BpfArpWriterStatus::NotReady;
    bool lastWriteMayHaveApplied_ = false;
    bool deviceOpened_ = false;
    bool interfaceBound_ = false;
    bool ethernetLink_ = false;
    bool headerComplete_ = false;
    bool closeAttempted_ = false;
    bool closeConfirmed_ = false;
};

} // namespace interceptor
