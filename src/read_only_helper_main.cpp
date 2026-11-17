#include "network/HelperStateDirectory.hpp"
#include "network/LaunchdMachServiceBootstrap.hpp"
#include "network/MachServicePeerAuthenticator.hpp"
#include "network/XpcControlRequestGate.hpp"
#include "network/XpcReadOnlyServiceListener.hpp"

#include <cstdio>
#include <dispatch/dispatch.h>
#include <string>
#include <string_view>
#include <unistd.h>
#include <utility>

namespace {

constexpr std::string_view stateDirectory = "/private/var/db/llm_interceptor";

int fail(int status, const char *reason) {
    std::fputs(reason, stderr);
    std::fputc('\n', stderr);
    return status;
}

} // namespace

int main(int argc, char *argv[]) {
    const bool checking = argc == 3 && std::string_view(argv[1]) == "--check-state-dir";
    const bool running = argc == 4 && std::string_view(argv[1]) == "--mach-service" &&
                         std::string_view(argv[2]) == "--state-dir" &&
                         std::string_view(argv[3]) == stateDirectory;
    if (!checking && !running)
        return fail(2, "usage: llm_interceptor_read_only_helper --check-state-dir ABSOLUTE_PATH\n"
                       "       llm_interceptor_read_only_helper --mach-service --state-dir "
                       "/private/var/db/llm_interceptor");
    if (::geteuid() != 0)
        return fail(3, "effective_root_required");

    std::string error;
    const int fd = interceptor::openHelperStateDirectory(checking ? argv[2] : argv[3], 0, &error);
    if (fd < 0)
        return fail(4, error.c_str());
    if (checking) {
        ::close(fd);
        std::puts("state_directory_ready");
        return 0;
    }

    interceptor::LaunchdMachServiceConfig config;
    const bool configured = interceptor::loadLaunchdMachServiceConfig(fd, &config, &error);
    ::close(fd);
    if (!configured)
        return fail(6, error.c_str());

    // The listener and its dependencies live beyond the calling thread.
    static interceptor::MacXpcPeerCodeSignaturePolicy policy;
    static interceptor::XpcControlRequestGate gate(std::move(config.trustedPeerRequirement),
                                                   policy);
    static interceptor::XpcReadOnlyControlAdapter adapter(gate);
    static interceptor::XpcReadOnlyServiceListener listener(interceptor::launchdMachServiceName,
                                                            adapter);
    if (!listener.start(&error))
        return fail(7, error.c_str());

    dispatch_main();
}
