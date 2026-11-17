#include "HelperStateDirectory.hpp"

#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <limits.h>
#include <string_view>
#include <sys/acl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace interceptor {

bool hasNoExtendedAcl(int fd) {
    const acl_t acl = ::acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
    if (!acl)
        return errno == ENOENT;
    ::acl_free(acl);
    return false;
}

int openHelperStateDirectory(const char *absolutePath, uid_t expectedOwner, std::string *error) {
    if (error)
        error->clear();
    const auto fail = [error](const char *reason) {
        if (error)
            *error = reason;
        return -1;
    };

    if (!absolutePath)
        return fail("absolute_state_directory_required");
    const std::string_view path(absolutePath);
    if (!path.starts_with('/') || path.ends_with('/'))
        return fail("absolute_state_directory_required");
    struct stat pathInfo{};
    if (::lstat(absolutePath, &pathInfo) != 0 || !S_ISDIR(pathInfo.st_mode))
        return fail("state_directory_missing_or_symlink");
    char canonical[PATH_MAX];
    if (!::realpath(absolutePath, canonical) || path != canonical)
        return fail("canonical_state_directory_required");
    const int fd = ::open(absolutePath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW_ANY | O_CLOEXEC);
    if (fd < 0)
        return fail("state_directory_open_failed");

    struct stat descriptorInfo{};
    const int flags = ::fcntl(fd, F_GETFD);
    const bool safe =
        ::fstat(fd, &descriptorInfo) == 0 && S_ISDIR(descriptorInfo.st_mode) &&
        descriptorInfo.st_uid == expectedOwner && (descriptorInfo.st_mode & 07777) == 0700 &&
        descriptorInfo.st_dev == pathInfo.st_dev && descriptorInfo.st_ino == pathInfo.st_ino &&
        flags >= 0 && (flags & FD_CLOEXEC) != 0 && hasNoExtendedAcl(fd);
    if (!safe) {
        ::close(fd);
        return fail("unsafe_state_directory");
    }
    return fd;
}

} // namespace interceptor
