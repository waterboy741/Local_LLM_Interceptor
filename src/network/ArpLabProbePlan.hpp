#pragma once

#include <QByteArray>
#include <QList>
#include <QString>

#include <optional>
#include <utility>

namespace interceptor {

// Facts needed for a single-client ARP probe. The observed interface name is supplied
// separately so creation can reject a stale or mismatched interface selection.
struct ArpLabProbeInputs {
    QString selectedInterfaceName;
    QString observedInterfaceName;
    QString researchIp;
    QString clientIp;
    QString serverIp;
    QString researchMac;
    QString clientMac;
    QString serverMac;
    int prefixLength = 24;
};

// Immutable, one-client probe plan independent of PF/proxy readiness. It contains only one
// redirect frame and one corrective frame, both targeted at the client.
class ArpLabProbePlan {
  public:
    static std::optional<ArpLabProbePlan> create(const ArpLabProbeInputs &inputs,
                                                 QString *error = nullptr);

    const QString &interfaceName() const { return interfaceName_; }
    const QByteArray &redirectionFrame() const { return redirectionFrame_; }
    const QByteArray &restorationFrame() const { return restorationFrame_; }
    QList<QByteArray> allowedFrames() const { return {redirectionFrame_, restorationFrame_}; }

  private:
    ArpLabProbePlan(QString interfaceName, QByteArray redirectionFrame, QByteArray restorationFrame)
        : interfaceName_(std::move(interfaceName)), redirectionFrame_(std::move(redirectionFrame)),
          restorationFrame_(std::move(restorationFrame)) {}

    QString interfaceName_;
    QByteArray redirectionFrame_;
    QByteArray restorationFrame_;
};

} // namespace interceptor
