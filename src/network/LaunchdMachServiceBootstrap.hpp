#pragma once

#include <functional>
#include <string>
#include <string_view>

namespace interceptor {

inline constexpr char launchdMachServiceName[] = "org.local-llm-interceptor.helper";

struct LaunchdMachServiceConfig {
    bool enabled = false;
    std::string trustedPeerRequirement;
    // Session-control gate. Absent (two-line config) means false: the service stays the
    // read-only probe/status responder and never constructs the session-control listener.
    bool sessionControl = false;
};

// Checks the literal cdhash syntax and compiles it with local Security.framework.
bool exactRequirementCompiles(std::string_view requirement);

// The config is deliberately strict so a typo or partial edit cannot enable
// the listener. The requirement is compiled by Security.framework here.
bool parseLaunchdMachServiceConfig(std::string_view contents, LaunchdMachServiceConfig *config,
                                   std::string *error = nullptr);

// Reads `mach-service.conf` relative to a previously validated root-owned
// state directory descriptor. The file must be root-owned mode 0600.
bool loadLaunchdMachServiceConfig(int stateDirectoryFd, LaunchdMachServiceConfig *config,
                                  std::string *error = nullptr);

using LaunchdMachServiceStart = std::function<bool(
    std::string_view serviceName, std::string_view trustedRequirement, std::string *error)>;

// Validates the explicit config before handing the fixed service name and
// trusted local requirement to the listener factory.
bool startConfiguredLaunchdMachService(const LaunchdMachServiceConfig &config,
                                       const LaunchdMachServiceStart &start,
                                       std::string *error = nullptr);

} // namespace interceptor
