#include "InstalledHelperBootstrap.hpp"

#include "HelperStateDirectory.hpp"

#include <QFile>

#include <unistd.h>

namespace interceptor {

std::optional<InstalledHelperStateDirectory>
InstalledHelperStateDirectory::open(const QString &absolutePath, uid_t expectedOwner,
                                    QString *error) {
    if (absolutePath.contains(QChar::Null)) {
        if (error)
            *error = QStringLiteral("absolute_state_directory_required");
        return std::nullopt;
    }
    const QByteArray pathBytes = QFile::encodeName(absolutePath);
    std::string failure;
    const int fd = openHelperStateDirectory(pathBytes.constData(), expectedOwner, &failure);
    if (error)
        *error = QString::fromStdString(failure);
    if (fd < 0)
        return std::nullopt;
    return InstalledHelperStateDirectory(fd, absolutePath);
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
