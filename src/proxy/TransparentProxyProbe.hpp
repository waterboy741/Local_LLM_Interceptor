#pragma once

#include <QByteArray>
#include <QString>

namespace interceptor {

struct TransparentProxyProbeTarget {
    QString interfaceName;
    QString clientIp;
    QString upstreamIp;
    int upstreamPort = 0;
    int listenerPort = 0;
    QString listenAddress;
};

// The secret and target must arrive through a separately authenticated bootstrap channel.
// A successful probe is point-in-time listener possession, not PF or traffic readiness.
bool verifyTransparentProxyProbe(const TransparentProxyProbeTarget &target,
                                 const QByteArray &secret, int timeoutMs, QString *error = nullptr);

} // namespace interceptor
