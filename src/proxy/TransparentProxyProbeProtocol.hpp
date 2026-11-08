#pragma once

#include "TransparentProxyProbe.hpp"

#include <QByteArray>
#include <QCryptographicHash>
#include <QMessageAuthenticationCode>

namespace interceptor {

inline constexpr auto transparentProbePrefix = "/.llm-interceptor/readiness/v1/";

inline QByteArray transparentProbeMessage(const TransparentProxyProbeTarget &target,
                                          const QByteArray &nonce) {
    return QByteArray("llm-interceptor-probe-v1\n") + nonce.toHex() + '\n' +
           target.interfaceName.toUtf8() + '\n' + target.clientIp.toUtf8() + '\n' +
           target.upstreamIp.toUtf8() + '\n' + QByteArray::number(target.upstreamPort) + '\n' +
           QByteArray::number(target.listenerPort) + '\n';
}

inline QByteArray transparentProbeMac(const TransparentProxyProbeTarget &target,
                                      const QByteArray &nonce, const QByteArray &secret) {
    return QMessageAuthenticationCode::hash(transparentProbeMessage(target, nonce), secret,
                                            QCryptographicHash::Sha256)
        .toHex();
}

} // namespace interceptor
