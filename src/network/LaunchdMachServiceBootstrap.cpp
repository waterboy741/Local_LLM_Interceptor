#include "LaunchdMachServiceBootstrap.hpp"

#include "HelperStateDirectory.hpp"

#include <Security/SecRequirement.h>

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace interceptor {
namespace {
constexpr size_t maximumConfigLength = 4096;
constexpr size_t maximumRequirementLength = 1024;

bool fail(std::string *error, const char *reason) {
    if (error)
        *error = reason;
    return false;
}

bool validRequirement(std::string_view requirement) {
    if (requirement.empty() || requirement.size() > maximumRequirementLength ||
        requirement.find('\0') != std::string_view::npos)
        return false;
    for (const unsigned char value : requirement) {
        if (value < 0x20 || value == 0x7f)
            return false;
    }
    return true;
}

bool requirementCompiles(std::string_view requirement) {
    CFStringRef requirementText = CFStringCreateWithBytes(
        kCFAllocatorDefault, reinterpret_cast<const UInt8 *>(requirement.data()),
        static_cast<CFIndex>(requirement.size()), kCFStringEncodingUTF8, false);
    if (!requirementText)
        return false;
    SecRequirementRef compiled = nullptr;
    const OSStatus status =
        SecRequirementCreateWithString(requirementText, kSecCSDefaultFlags, &compiled);
    CFRelease(requirementText);
    if (!compiled)
        return false;
    CFRelease(compiled);
    return status == errSecSuccess;
}

} // namespace

bool exactRequirementCompiles(std::string_view requirement) {
    constexpr std::string_view prefix = "cdhash H\"";
    constexpr size_t overhead = prefix.size() + 1;
    if ((requirement.size() != overhead + 40 && requirement.size() != overhead + 64) ||
        !requirement.starts_with(prefix) || !requirement.ends_with('"'))
        return false;
    const auto hash = requirement.substr(prefix.size(), requirement.size() - overhead);
    return std::ranges::all_of(hash,
                               [](char value) {
                                   return (value >= '0' && value <= '9') ||
                                          (value >= 'a' && value <= 'f') ||
                                          (value >= 'A' && value <= 'F');
                               }) &&
           requirementCompiles(requirement);
}

bool parseLaunchdMachServiceConfig(std::string_view contents, LaunchdMachServiceConfig *config,
                                   std::string *error) {
    if (error)
        error->clear();
    if (!config)
        return fail(error, "launchd_mach_service_config_output_invalid");
    *config = LaunchdMachServiceConfig{};
    if (contents.empty() || contents.size() > maximumConfigLength ||
        contents.find('\0') != std::string_view::npos ||
        contents.find('\r') != std::string_view::npos)
        return fail(error, "launchd_mach_service_config_format_invalid");

    if (contents.ends_with('\n'))
        contents.remove_suffix(1);
    const auto newline = contents.find('\n');
    if (newline == std::string_view::npos)
        return fail(error, "launchd_mach_service_config_format_invalid");
    const auto setting = contents.substr(0, newline);
    auto requirement = contents.substr(newline + 1);
    constexpr std::string_view key = "peer-code-requirement=";
    if ((setting != "enabled=true" && setting != "enabled=false") || !requirement.starts_with(key))
        return fail(error, "launchd_mach_service_config_format_invalid");
    requirement.remove_prefix(key.size());
    const bool enabled = setting == "enabled=true";
    const bool valid = enabled ? exactRequirementCompiles(requirement)
                               : validRequirement(requirement) && requirementCompiles(requirement);
    if (!valid)
        return fail(error, "launchd_mach_service_peer_requirement_invalid");

    if (!enabled)
        return fail(error, "launchd_mach_service_disabled");

    // Optional, explicitly named third line. Anything else in the third line is invalid so a
    // stray edit can never silently enable privileged session control.
    std::string_view sessionControlLine;
    const auto requirementEnd = requirement.find('\n');
    if (requirementEnd != std::string_view::npos) {
        sessionControlLine = requirement.substr(requirementEnd + 1);
        if (sessionControlLine.find('\n') != std::string_view::npos)
            return fail(error, "launchd_mach_service_config_format_invalid");
        requirement.remove_suffix(sessionControlLine.size() + 1);
        const bool validEnabled = enabled && exactRequirementCompiles(requirement);
        if (!validEnabled)
            return fail(error, "launchd_mach_service_peer_requirement_invalid");
        if (sessionControlLine == "session-control=true")
            config->sessionControl = true;
        else if (sessionControlLine == "session-control=false")
            config->sessionControl = false;
        else
            return fail(error, "launchd_mach_service_session_control_line_invalid");
    }
    if (!enabled)
        return fail(error, "launchd_mach_service_disabled");
    config->enabled = true;
    config->trustedPeerRequirement = requirement;
    return true;
}

bool loadLaunchdMachServiceConfig(int stateDirectoryFd, LaunchdMachServiceConfig *config,
                                  std::string *error) {
    if (error)
        error->clear();
    if (!config)
        return fail(error, "launchd_mach_service_config_output_invalid");
    *config = LaunchdMachServiceConfig{};
    if (stateDirectoryFd < 0)
        return fail(error, "launchd_mach_service_state_directory_invalid");

    const int fd = ::openat(stateDirectoryFd, "mach-service.conf",
                            O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0)
        return fail(error, "launchd_mach_service_config_open_failed");
    struct stat info{};
    const int descriptorFlags = ::fcntl(fd, F_GETFD);
    const bool safe = ::fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && info.st_uid == 0 &&
                      (info.st_mode & 07777) == 0600 && info.st_nlink == 1 && info.st_size > 0 &&
                      info.st_size <= static_cast<off_t>(maximumConfigLength) &&
                      descriptorFlags >= 0 && (descriptorFlags & FD_CLOEXEC) != 0 &&
                      hasNoExtendedAcl(fd);
    if (!safe) {
        ::close(fd);
        return fail(error, "launchd_mach_service_config_file_unsafe");
    }

    std::string contents;
    contents.reserve(static_cast<size_t>(info.st_size));
    char buffer[512];
    bool readOk = true;
    while (true) {
        const ssize_t count = ::read(fd, buffer, sizeof(buffer));
        if (count == 0)
            break;
        if (count < 0) {
            if (errno == EINTR)
                continue;
            readOk = false;
            break;
        }
        if (contents.size() + static_cast<size_t>(count) > maximumConfigLength) {
            readOk = false;
            break;
        }
        contents.append(buffer, static_cast<size_t>(count));
    }
    ::close(fd);
    if (!readOk || contents.size() != static_cast<size_t>(info.st_size))
        return fail(error, "launchd_mach_service_config_read_failed");
    return parseLaunchdMachServiceConfig(contents, config, error);
}

bool startConfiguredLaunchdMachService(const LaunchdMachServiceConfig &config,
                                       const LaunchdMachServiceStart &start, std::string *error) {
    if (error)
        error->clear();
    if (!config.enabled)
        return fail(error, "launchd_mach_service_disabled");
    if (!exactRequirementCompiles(config.trustedPeerRequirement))
        return fail(error, "launchd_mach_service_peer_requirement_invalid");
    if (!start)
        return fail(error, "launchd_mach_service_start_unavailable");
    try {
        if (start(launchdMachServiceName, config.trustedPeerRequirement, error))
            return true;
    } catch (...) {
    }
    if (error && error->empty())
        *error = "launchd_mach_service_start_failed";
    return false;
}

} // namespace interceptor
