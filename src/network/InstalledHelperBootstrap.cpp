#include "InstalledHelperBootstrap.hpp"

#include <QFile>
#include <QFileInfo>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace interceptor {

std::optional<InstalledHelperStateDirectory>
InstalledHelperStateDirectory::open(const QString &absolutePath, uid_t expectedOwner,
                                    QString *error) {
    if (error)
        error->clear();
    const auto fail =
        [error](const QString &reason) -> std::optional<InstalledHelperStateDirectory> {
        if (error)
            *error = reason;
        return std::nullopt;
    };
    const QFileInfo requested(absolutePath);
    if (!requested.isAbsolute() || absolutePath.isEmpty() || absolutePath.endsWith('/') ||
        absolutePath.contains(QChar::Null))
        return fail(QStringLiteral("absolute_state_directory_required"));
    const QByteArray pathBytes = QFile::encodeName(absolutePath);
    struct stat pathInfo{};
    if (::lstat(pathBytes.constData(), &pathInfo) != 0 || !S_ISDIR(pathInfo.st_mode))
        return fail(QStringLiteral("state_directory_missing_or_symlink"));
    const QString canonical = requested.canonicalFilePath();
    if (canonical.isEmpty() || canonical != absolutePath)
        return fail(QStringLiteral("canonical_state_directory_required"));
    const int fd = ::open(pathBytes.constData(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return fail(QStringLiteral("state_directory_open_failed"));
    struct stat descriptorInfo{};
    const int flags = ::fcntl(fd, F_GETFD);
    const bool safe =
        ::fstat(fd, &descriptorInfo) == 0 && S_ISDIR(descriptorInfo.st_mode) &&
        descriptorInfo.st_uid == expectedOwner && (descriptorInfo.st_mode & 07777) == 0700 &&
        descriptorInfo.st_dev == pathInfo.st_dev && descriptorInfo.st_ino == pathInfo.st_ino &&
        flags >= 0 && (flags & FD_CLOEXEC) != 0;
    if (!safe) {
        ::close(fd);
        return fail(QStringLiteral("unsafe_state_directory"));
    }
    return InstalledHelperStateDirectory(fd, canonical);
}

InstalledHelperStateDirectory::InstalledHelperStateDirectory(
    InstalledHelperStateDirectory &&other) noexcept
    : fd_(other.fd_), canonicalPath_(std::move(other.canonicalPath_)) {
    other.fd_ = -1;
}

InstalledHelperStateDirectory::~InstalledHelperStateDirectory() {
    if (fd_ >= 0)
        ::close(fd_);
}

} // namespace interceptor
