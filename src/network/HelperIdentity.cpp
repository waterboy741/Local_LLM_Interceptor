#include "HelperIdentity.hpp"

#include "HelperStateDirectory.hpp"
#include "LaunchdMachServiceBootstrap.hpp"

#include <array>
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace interceptor {
namespace {

constexpr char identityFilename[] = "llm_interceptor_helper.identity";
constexpr int directoryFlags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
constexpr char requirementPrefix[] = "helper-code-requirement=";
constexpr qsizetype prefixLength = sizeof(requirementPrefix) - 1;
constexpr qsizetype maximumLength = prefixLength + sizeof("cdhash H\"\"") - 1 + 64 + 1;

class ScopedFd {
  public:
    explicit ScopedFd(int fd) : fd_{fd} {}
    ~ScopedFd() {
        if (fd_ >= 0)
            ::close(fd_);
    }

    ScopedFd(const ScopedFd &) = delete;
    ScopedFd &operator=(const ScopedFd &) = delete;

    int get() const { return fd_; }

  private:
    int fd_;
};

HelperIdentity openFailure(int error) {
    return {error == ENOENT ? HelperIdentityStatus::Missing : HelperIdentityStatus::Invalid, {}};
}

bool isTrustedDirectory(int fd, uid_t expectedOwner) {
    struct stat info{};
    return ::fstat(fd, &info) == 0 && S_ISDIR(info.st_mode) && info.st_uid == expectedOwner &&
           (info.st_mode & (S_IWGRP | S_IWOTH)) == 0 && hasNoExtendedAcl(fd);
}

HelperIdentity loadIdentityAt(int directoryFd, const char *filename, uid_t expectedOwner) {
    const HelperIdentity invalid{HelperIdentityStatus::Invalid, {}};
    const ScopedFd file(
        ::openat(directoryFd, filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK));
    if (file.get() < 0)
        return openFailure(errno);

    struct stat info{};
    if (::fstat(file.get(), &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != expectedOwner ||
        (info.st_mode & 07777) != 0644 || info.st_size <= 0 || info.st_size > maximumLength ||
        !hasNoExtendedAcl(file.get()))
        return invalid;

    std::array<char, maximumLength + 1> buffer{};
    qsizetype size = 0;
    while (size < static_cast<qsizetype>(buffer.size())) {
        const auto count = ::read(file.get(), buffer.data() + size, buffer.size() - size);
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0)
            return invalid;
        if (count == 0)
            break;
        size += count;
    }

    QByteArray contents(buffer.data(), size);
    if (size > maximumLength || !contents.startsWith(requirementPrefix))
        return invalid;
    if (contents.endsWith('\n'))
        contents.chop(1);
    contents.remove(0, prefixLength);
    if (!exactRequirementCompiles(std::string_view(contents)))
        return invalid;
    struct stat finalInfo{};
    if (::fstat(file.get(), &finalInfo) != 0 || size != info.st_size ||
        finalInfo.st_size != info.st_size || finalInfo.st_dev != info.st_dev ||
        finalInfo.st_ino != info.st_ino ||
        finalInfo.st_mtimespec.tv_sec != info.st_mtimespec.tv_sec ||
        finalInfo.st_mtimespec.tv_nsec != info.st_mtimespec.tv_nsec ||
        finalInfo.st_ctimespec.tv_sec != info.st_ctimespec.tv_sec ||
        finalInfo.st_ctimespec.tv_nsec != info.st_ctimespec.tv_nsec)
        return invalid;

    return {HelperIdentityStatus::Loaded, contents};
}

} // namespace

HelperIdentity loadHelperIdentity() {
    constexpr uid_t root = 0;
    const HelperIdentity invalid{HelperIdentityStatus::Invalid, {}};
    const ScopedFd systemRoot(::open("/", directoryFlags));
    if (!isTrustedDirectory(systemRoot.get(), root))
        return invalid;

    const ScopedFd library(::openat(systemRoot.get(), "Library", directoryFlags));
    if (library.get() < 0)
        return openFailure(errno);
    if (!isTrustedDirectory(library.get(), root))
        return invalid;

    const ScopedFd helpers(::openat(library.get(), "PrivilegedHelperTools", directoryFlags));
    if (helpers.get() < 0)
        return openFailure(errno);
    if (!isTrustedDirectory(helpers.get(), root))
        return invalid;

    return loadIdentityAt(helpers.get(), identityFilename, root);
}

HelperIdentity loadHelperIdentity(const QByteArray &path, uid_t expectedOwner) {
    const HelperIdentity invalid{HelperIdentityStatus::Invalid, {}};
    const auto separator = path.lastIndexOf('/');
    if (!path.startsWith('/') || path.contains('\0') || separator == path.size() - 1)
        return invalid;

    const auto directory = path.left(separator == 0 ? 1 : separator);
    const auto filename = path.mid(separator + 1);
    const ScopedFd parent(
        ::open(directory.constData(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW_ANY | O_CLOEXEC));
    if (parent.get() < 0)
        return openFailure(errno);
    if (!isTrustedDirectory(parent.get(), expectedOwner))
        return invalid;

    return loadIdentityAt(parent.get(), filename.constData(), expectedOwner);
}

XpcReadOnlyClientResult queryTrustedHelperStatus(
    const HelperIdentity &identity,
    const std::function<XpcReadOnlyClientResult(const QByteArray &)> &trustedRequest) {
    XpcReadOnlyClientResult result;
    switch (identity.status) {
    case HelperIdentityStatus::Loaded:
        return trustedRequest(identity.requirement);
    case HelperIdentityStatus::Missing:
        result.status = XpcReadOnlyClientStatus::HelperIdentityMissing;
        break;
    case HelperIdentityStatus::Invalid:
        result.status = XpcReadOnlyClientStatus::HelperIdentityInvalid;
        break;
    }
    return result;
}

} // namespace interceptor
