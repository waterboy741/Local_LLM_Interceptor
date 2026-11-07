#pragma once
#include <QString>
#include <QStringList>
#include <functional>
#include <utility>
namespace interceptor {
struct SessionConfig {
    QString interfaceName;
    QString clientIp;
    QString serverIp;
    int serverPort = 11434;
    QStringList apiPaths{"/api/generate", "/api/chat", "/v1/chat/completions"};
    bool explicitProxy = false;
    QStringList validate() const;
};

// Evidence that ProxyServer successfully bound its transparent loopback listener. It reports
// configuration and bind readiness only; it does not establish upstream reachability or packet
// delivery. It is point-in-time evidence; callers must revalidate it with ProxyServer immediately
// before session activation. Instances can only be created by ProxyServer.
class TransparentProxyReadiness {
  public:
    const QString &interfaceName() const { return interfaceName_; }
    const QString &listenAddress() const { return listenAddress_; }
    const QString &allowedClientIp() const { return allowedClientIp_; }
    const QString &upstreamServerIp() const { return upstreamServerIp_; }
    int listenerPort() const { return listenerPort_; }
    int upstreamServerPort() const { return upstreamServerPort_; }
    bool isCurrent() const {
        try {
            return currentCheck_ && currentCheck_();
        } catch (...) {
            return false;
        }
    }

  private:
    TransparentProxyReadiness(QString interfaceName, QString listenAddress, QString allowedClientIp,
                              QString upstreamServerIp, int listenerPort, int upstreamServerPort)
        : interfaceName_(std::move(interfaceName)), listenAddress_(std::move(listenAddress)),
          allowedClientIp_(std::move(allowedClientIp)),
          upstreamServerIp_(std::move(upstreamServerIp)), listenerPort_(listenerPort),
          upstreamServerPort_(upstreamServerPort) {}

    QString interfaceName_;
    QString listenAddress_;
    QString allowedClientIp_;
    QString upstreamServerIp_;
    int listenerPort_ = 0;
    int upstreamServerPort_ = 0;
    std::function<bool()> currentCheck_;
    friend class ProxyServer;
    friend class M6LeasedHelperHostTests;
};
} // namespace interceptor
