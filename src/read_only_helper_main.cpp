#include "network/HelperStateDirectory.hpp"
#include "network/InstalledSessionControl.hpp"
#include "network/LaunchdMachServiceBootstrap.hpp"
#include "network/MachServicePeerAuthenticator.hpp"
#include "network/XpcControlRequestGate.hpp"
#include "network/XpcReadOnlyServiceListener.hpp"
#include "network/XpcSessionControlServiceAdapter.hpp"

#include <cstdio>
#include <ctime>
#include <dispatch/dispatch.h>
#include <string>
#include <string_view>
#include <unistd.h>
#include <utility>

namespace {

constexpr std::string_view stateDirectory = "/private/var/db/llm_interceptor";
constexpr int probeTimeoutMs = 2000;
constexpr uint64_t watchdogTickNanoseconds = 250 * NSEC_PER_MSEC;

int fail(int status, const char *reason) {
    std::fputs(reason, stderr);
    std::fputc('\n', stderr);
    return status;
}

int64_t monotonicNowMs() {
    struct timespec now{};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return static_cast<int64_t>(now.tv_sec) * 1000 + now.tv_nsec / 1000000;
}

// Production backend for the operator-gated installed service. Listener verification runs the
// real Qt-free transparent probe; owned scoped operations (PF enable reference, anchor rules,
// ARP redirect) are intentionally fail-closed until the Qt-side scoped session backend is ported
// behind this interface, so Start can never report Active today.
class HelperSessionControlBackend final : public interceptor::InstalledSessionControlBackend {
  public:
    bool effectiveRoot() override { return ::geteuid() == 0; }

    bool freshListenerVerification(const interceptor::InstalledSessionTuple &tuple,
                                   const std::vector<unsigned char> &secret) override {
        std::string error;
        return interceptor::verifyTransparentListenerProbe(tuple, secret, probeTimeoutMs, &error);
    }

    bool startOwnedOperations(const interceptor::InstalledSessionTuple &,
                              std::string *error) override {
        if (error)
            *error = "scoped_backend_unavailable";
        return false;
    }

    void heartbeatOwnedOperations() override {}

    bool stopOwnedOperations(bool *cleaned, std::string *error) override {
        // No owned operations can exist while startOwnedOperations is fail-closed.
        if (cleaned)
            *cleaned = true;
        if (error)
            error->clear();
        return true;
    }
};

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
    static interceptor::XpcControlRequestGate gate(
        std::move(config.trustedPeerRequirement), policy,
        config.sessionControl ? interceptor::XpcControlRequestGate::Mode::InstalledLifecycle
                              : interceptor::XpcControlRequestGate::Mode::ReadOnly);

    if (!config.sessionControl) {
        // Byte-identical read-only service: probe/status only, no session grammar.
        static interceptor::XpcReadOnlyControlAdapter readOnlyAdapter(gate);
        static interceptor::XpcReadOnlyServiceListener readOnlyListener(
            interceptor::launchdMachServiceName, readOnlyAdapter);
        if (!readOnlyListener.start(&error))
            return fail(7, error.c_str());
        dispatch_main();
    }

    static HelperSessionControlBackend backend;
    static interceptor::InstalledSessionControlCore core(backend, monotonicNowMs);
    static interceptor::XpcSessionControlServiceAdapter adapter(gate, core);
    static interceptor::XpcReadOnlyServiceListener listener(interceptor::launchdMachServiceName,
                                                            adapter);
    if (!listener.start(&error))
        return fail(7, error.c_str());

    // Owner-loop watchdog: heartbeats must keep arriving or the session is stopped with its
    // cleanup obligation retained.
    dispatch_source_t watchdog = dispatch_source_create(
        DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
        dispatch_queue_create("org.local-llm-interceptor.session-watchdog", DISPATCH_QUEUE_SERIAL));
    dispatch_source_set_timer(watchdog, dispatch_time(DISPATCH_TIME_NOW, watchdogTickNanoseconds),
                              watchdogTickNanoseconds, watchdogTickNanoseconds / 2);
    dispatch_source_set_event_handler(watchdog, ^{
      core.watchdogTick();
    });
    dispatch_resume(watchdog);

    dispatch_main();
}
