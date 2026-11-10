#pragma once

#include <QByteArray>
#include <QString>

#include <functional>

namespace interceptor {

inline constexpr char launchdMachServiceName[] = "org.local-llm-interceptor.helper";

struct LaunchdMachServiceConfig {
    bool enabled = false;
    QByteArray trustedPeerRequirement;
};

// The config is deliberately strict so a typo or partial edit cannot enable
// the listener. The requirement is compiled by Security.framework here.
bool parseLaunchdMachServiceConfig(const QByteArray &contents, LaunchdMachServiceConfig *config,
                                   QString *error = nullptr);

// Reads `mach-service.conf` relative to a previously validated root-owned
// state directory descriptor. The file must be root-owned mode 0600.
bool loadLaunchdMachServiceConfig(int stateDirectoryFd, LaunchdMachServiceConfig *config,
                                  QString *error = nullptr);

using LaunchdMachServiceStart = std::function<bool(
    const QByteArray &serviceName, const QByteArray &trustedRequirement, QString *error)>;

// Validates the explicit config before handing the fixed service name and
// trusted local requirement to the listener factory.
bool startConfiguredLaunchdMachService(const LaunchdMachServiceConfig &config,
                                       const LaunchdMachServiceStart &start,
                                       QString *error = nullptr);

} // namespace interceptor
