#include "LaunchdMachServiceBootstrap.hpp"

#include <Security/SecRequirement.h>

#include <QList>

#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace interceptor {
namespace {
constexpr qsizetype maximumConfigLength = 4096;
constexpr qsizetype maximumRequirementLength = 1024;

bool fail(QString *error, const char *reason) {
    if (error)
        *error = QString::fromLatin1(reason);
    return false;
}

bool validRequirement(const QByteArray &requirement) {
    if (requirement.isEmpty() || requirement.size() > maximumRequirementLength ||
        requirement.contains('\0'))
        return false;
    for (const unsigned char value : requirement) {
        if (value < 0x20 || value == 0x7f)
            return false;
    }
    return QString::fromUtf8(requirement).toUtf8() == requirement;
}

bool requirementCompiles(const QByteArray &requirement) {
    const QString text = QString::fromUtf8(requirement);
    const QByteArray utf8 = text.toUtf8();
    CFStringRef requirementText = CFStringCreateWithBytes(
        kCFAllocatorDefault, reinterpret_cast<const UInt8 *>(utf8.constData()),
        static_cast<CFIndex>(utf8.size()), kCFStringEncodingUTF8, false);
    if (!requirementText)
        return false;
    SecRequirementRef compiled = nullptr;
    const OSStatus status =
        SecRequirementCreateWithString(requirementText, kSecCSDefaultFlags, &compiled);
    CFRelease(requirementText);
    if (compiled)
        CFRelease(compiled);
    return status == errSecSuccess;
}

} // namespace

bool parseLaunchdMachServiceConfig(const QByteArray &contents, LaunchdMachServiceConfig *config,
                                   QString *error) {
    if (error)
        error->clear();
    if (!config)
        return fail(error, "launchd_mach_service_config_output_invalid");
    *config = LaunchdMachServiceConfig{};
    if (contents.isEmpty() || contents.size() > maximumConfigLength || contents.contains('\0') ||
        contents.contains('\r'))
        return fail(error, "launchd_mach_service_config_format_invalid");

    QByteArray normalized = contents;
    if (normalized.endsWith('\n'))
        normalized.chop(1);
    const QList<QByteArray> lines = normalized.split('\n');
    if (lines.size() != 2 || !lines.at(0).startsWith("enabled=") ||
        !lines.at(1).startsWith("peer-code-requirement=") ||
        (lines.at(0) != "enabled=true" && lines.at(0) != "enabled=false"))
        return fail(error, "launchd_mach_service_config_format_invalid");

    const QByteArray requirement = lines.at(1).mid(sizeof("peer-code-requirement=") - 1);
    if (!validRequirement(requirement) || !requirementCompiles(requirement))
        return fail(error, "launchd_mach_service_peer_requirement_invalid");

    config->enabled = lines.at(0) == "enabled=true";
    config->trustedPeerRequirement = requirement;
    if (!config->enabled) {
        *config = LaunchdMachServiceConfig{};
        return fail(error, "launchd_mach_service_disabled");
    }
    return true;
}

bool loadLaunchdMachServiceConfig(int stateDirectoryFd, LaunchdMachServiceConfig *config,
                                  QString *error) {
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
                      info.st_size <= maximumConfigLength && descriptorFlags >= 0 &&
                      (descriptorFlags & FD_CLOEXEC) != 0;
    if (!safe) {
        ::close(fd);
        return fail(error, "launchd_mach_service_config_file_unsafe");
    }

    QByteArray contents;
    contents.reserve(static_cast<qsizetype>(info.st_size));
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
        if (contents.size() + count > maximumConfigLength) {
            readOk = false;
            break;
        }
        contents.append(buffer, static_cast<qsizetype>(count));
    }
    ::close(fd);
    if (!readOk || contents.size() != info.st_size)
        return fail(error, "launchd_mach_service_config_read_failed");
    return parseLaunchdMachServiceConfig(contents, config, error);
}

bool startConfiguredLaunchdMachService(const LaunchdMachServiceConfig &config,
                                       const LaunchdMachServiceStart &start, QString *error) {
    if (error)
        error->clear();
    if (!config.enabled)
        return fail(error, "launchd_mach_service_disabled");
    if (!validRequirement(config.trustedPeerRequirement) ||
        !requirementCompiles(config.trustedPeerRequirement))
        return fail(error, "launchd_mach_service_peer_requirement_invalid");
    if (!start)
        return fail(error, "launchd_mach_service_start_unavailable");
    try {
        if (start(QByteArray(launchdMachServiceName), config.trustedPeerRequirement, error))
            return true;
    } catch (...) {
    }
    if (error && error->isEmpty())
        *error = QStringLiteral("launchd_mach_service_start_failed");
    return false;
}

} // namespace interceptor
