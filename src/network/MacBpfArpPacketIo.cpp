#include "MacBpfArpPacketIo.hpp"

#include "ArpCodec.hpp"

#include <QRegularExpression>

#include <cerrno>
#include <cstring>

#ifdef __APPLE__
#include <fcntl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace interceptor {
namespace {
class NativeBpfSystemCalls final : public BpfSystemCalls {
  public:
    int openDevice(const QString &path, int flags, int &errorNumber) override {
#ifdef __APPLE__
        const auto encodedPath = path.toLocal8Bit();
        const int descriptor = ::open(encodedPath.constData(), flags);
        errorNumber = descriptor < 0 ? errno : 0;
        return descriptor;
#else
        Q_UNUSED(path)
        Q_UNUSED(flags)
        errorNumber = ENOTSUP;
        return -1;
#endif
    }

    int ioctlDevice(int descriptor, unsigned long request, void *argument) override {
#ifdef __APPLE__
        return ::ioctl(descriptor, request, argument);
#else
        Q_UNUSED(descriptor)
        Q_UNUSED(request)
        Q_UNUSED(argument)
        errno = ENOTSUP;
        return -1;
#endif
    }

    qint64 writeDevice(int descriptor, const char *data, qsizetype size) override {
#ifdef __APPLE__
        return static_cast<qint64>(::write(descriptor, data, static_cast<size_t>(size)));
#else
        Q_UNUSED(descriptor)
        Q_UNUSED(data)
        Q_UNUSED(size)
        errno = ENOTSUP;
        return -1;
#endif
    }

    int closeDevice(int descriptor) override {
#ifdef __APPLE__
        return ::close(descriptor);
#else
        Q_UNUSED(descriptor)
        errno = ENOTSUP;
        return -1;
#endif
    }
};

BpfSystemCalls &nativeBpfSystemCalls() {
    static NativeBpfSystemCalls calls;
    return calls;
}

bool validInterface(const QString &name) {
    static const QRegularExpression pattern("^[A-Za-z][A-Za-z0-9_.:-]{0,63}$");
    if (!pattern.match(name).hasMatch())
        return false;
#ifdef __APPLE__
    const auto encoded = name.toLocal8Bit();
    return !encoded.isEmpty() && encoded.size() < IFNAMSIZ;
#else
    return false;
#endif
}
} // namespace

MacBpfArpPacketIo::MacBpfArpPacketIo(const SessionSnapshot &snapshot)
    : MacBpfArpPacketIo(snapshot, nativeBpfSystemCalls()) {}

MacBpfArpPacketIo::MacBpfArpPacketIo(const SessionSnapshot &snapshot, BpfSystemCalls &systemCalls)
    : interfaceName_(snapshot.config().interfaceName), allowedFrames_(snapshot.redirectionFrames()),
      systemCalls_(systemCalls) {
    const auto restorations = snapshot.restorationFrames();
    allowedFrames_.append(restorations);
    initialize();
}

MacBpfArpPacketIo::~MacBpfArpPacketIo() { close(); }

void MacBpfArpPacketIo::initialize() {
    if (!validInterface(interfaceName_)) {
#ifdef __APPLE__
        status_ = BpfArpWriterStatus::InvalidInterface;
#else
        status_ = BpfArpWriterStatus::UnsupportedPlatform;
#endif
        return;
    }

#ifndef __APPLE__
    status_ = BpfArpWriterStatus::UnsupportedPlatform;
    return;
#else
    const int flags = O_RDWR | O_CLOEXEC | O_NONBLOCK;
    for (int index = 0; index <= maximumDeviceIndex; ++index) {
        int openError = 0;
        const QString path = QStringLiteral("/dev/bpf%1").arg(index);
        descriptor_ = systemCalls_.openDevice(path, flags, openError);
        if (descriptor_ >= 0)
            break;
        if (openError != EBUSY && openError != ENOENT) {
            status_ = BpfArpWriterStatus::OpenFailed;
            return;
        }
    }
    if (descriptor_ < 0) {
        status_ = BpfArpWriterStatus::OpenFailed;
        return;
    }

    struct ifreq interfaceRequest{};
    const auto encodedName = interfaceName_.toLocal8Bit();
    std::memcpy(interfaceRequest.ifr_name, encodedName.constData(),
                static_cast<size_t>(encodedName.size()));
    if (systemCalls_.ioctlDevice(descriptor_, BIOCSETIF, &interfaceRequest) < 0) {
        failAndClose(BpfArpWriterStatus::AttachFailed);
        return;
    }

    u_int linkType = 0;
    if (systemCalls_.ioctlDevice(descriptor_, BIOCGDLT, &linkType) < 0 || linkType != DLT_EN10MB) {
        failAndClose(BpfArpWriterStatus::UnsupportedLinkType);
        return;
    }

    u_int headerComplete = 1;
    if (systemCalls_.ioctlDevice(descriptor_, BIOCSHDRCMPLT, &headerComplete) < 0) {
        failAndClose(BpfArpWriterStatus::HeaderCompleteFailed);
        return;
    }
    headerComplete = 0;
    if (systemCalls_.ioctlDevice(descriptor_, BIOCGHDRCMPLT, &headerComplete) < 0 ||
        headerComplete != 1) {
        failAndClose(BpfArpWriterStatus::HeaderCompleteFailed);
        return;
    }
    status_ = BpfArpWriterStatus::Ready;
#endif
}

bool MacBpfArpPacketIo::validFrame(const QByteArray &frame) const {
    if (frame.size() != arpFrameSize || !allowedFrames_.contains(frame))
        return false;
    const auto packet = ArpCodec::parse(frame);
    return packet && packet->operation == 2;
}

bool MacBpfArpPacketIo::sendFrame(const QString &interfaceName, const QByteArray &frame) {
    lastWriteMayHaveApplied_ = false;
    if (!isReady()) {
        status_ = BpfArpWriterStatus::NotReady;
        return false;
    }
    if (interfaceName != interfaceName_) {
        status_ = BpfArpWriterStatus::InterfaceMismatch;
        return false;
    }
    if (!validFrame(frame)) {
        status_ = BpfArpWriterStatus::InvalidFrame;
        return false;
    }

    // BPF treats each write as one packet. Never retry a short/error result: the frame may
    // already have been partially or fully handed to the interface.
    lastWriteMayHaveApplied_ = true;
    const qint64 written = systemCalls_.writeDevice(descriptor_, frame.constData(), frame.size());
    if (written != frame.size()) {
        status_ = BpfArpWriterStatus::WriteFailed;
        return false;
    }
    status_ = BpfArpWriterStatus::Ready;
    return true;
}

bool MacBpfArpPacketIo::close() {
    if (descriptor_ < 0) {
        if (status_ == BpfArpWriterStatus::CloseFailed)
            return false;
        if (status_ == BpfArpWriterStatus::Ready)
            status_ = BpfArpWriterStatus::NotReady;
        return true;
    }
    const int descriptor = descriptor_;
    descriptor_ = -1;
    const bool succeeded = systemCalls_.closeDevice(descriptor) == 0;
    status_ = succeeded ? BpfArpWriterStatus::NotReady : BpfArpWriterStatus::CloseFailed;
    return succeeded;
}

void MacBpfArpPacketIo::failAndClose(BpfArpWriterStatus status) {
    if (close())
        status_ = status;
}

} // namespace interceptor
