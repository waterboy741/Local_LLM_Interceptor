#pragma once

#include <QString>

#include <optional>
#include <sys/types.h>

namespace interceptor {

// Owns the single trusted descriptor passed to the host lease and both PF journals.
// Installation must create this directory as root:wheel with mode 0700 first.
class InstalledHelperStateDirectory final {
  public:
    static std::optional<InstalledHelperStateDirectory>
    open(const QString &absolutePath, uid_t expectedOwner, QString *error = nullptr);

    InstalledHelperStateDirectory(const InstalledHelperStateDirectory &) = delete;
    InstalledHelperStateDirectory &operator=(const InstalledHelperStateDirectory &) = delete;
    InstalledHelperStateDirectory(InstalledHelperStateDirectory &&other) noexcept;
    InstalledHelperStateDirectory &operator=(InstalledHelperStateDirectory &&other) = delete;
    ~InstalledHelperStateDirectory();

    int descriptor() const noexcept { return fd_; }
    const QString &canonicalPath() const noexcept { return canonicalPath_; }

  private:
    InstalledHelperStateDirectory(int fd, QString path)
        : fd_(fd), canonicalPath_(std::move(path)) {}
    int fd_ = -1;
    QString canonicalPath_;
};

} // namespace interceptor
