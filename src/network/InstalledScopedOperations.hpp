#pragma once

#include "InstalledSessionControl.hpp"

#include <dispatch/dispatch.h>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace interceptor {

// Bounded typed-command seam for the installed scoped backend. `run` executes one fixed program
// with an explicit argument vector, optionally feeding one bounded stdin payload, and reports
// exactly whether the child was reaped and what exit status it produced. The default
// implementation wraps the reviewed PosixSpawnChildProcess engine. Fake implementations keep
// tests offline and deterministic.
class InstalledScopedCommandIo {
  public:
    struct Result {
        bool started = false;
        bool reaped = false;
        bool normalExit = false;
        int exitCode = -1;
        std::string standardOutput;
        // Bounded stderr capture (same engine cap): the loop must drain BOTH channels or a
        // stderr-only child output tight-spins waitForReadable forever; keeping the bytes also
        // gives the lab pfctl stderr diagnostics.
        std::string standardError;
    };

    virtual ~InstalledScopedCommandIo() = default;
    virtual Result run(const std::string &program, const std::vector<std::string> &arguments,
                       const std::string *standardInput, int timeoutMs,
                       std::size_t maximumOutputBytes) = 0;
};

// Default spawn-backed typed-command seam. One process per call; every wait is bounded by
// `timeoutMs` and captured output by `maximumOutputBytes`.
class InstalledScopedSpawnCommandIo final : public InstalledScopedCommandIo {
  public:
    Result run(const std::string &program, const std::vector<std::string> &arguments,
               const std::string *standardInput, int timeoutMs,
               std::size_t maximumOutputBytes) override;
};

// Raw Ethernet frame seam (ARP redirect frames). One interface per instance.
class InstalledScopedArpIo {
  public:
    virtual ~InstalledScopedArpIo() = default;
    virtual bool open(const std::string &interfaceName, std::string *error) = 0;
    virtual bool sendFrame(const unsigned char *frame, std::size_t length) = 0;
    virtual void close() = 0;
};

// Default /dev/bpfN writer: O_RDWR, BIOCSETIF, EN10MB link type, source-MAC completion enabled
// and read back, then one ::write per frame. Mirrors the reviewed MacBpfArpPacketIo setup.
class InstalledScopedBpfArpIo final : public InstalledScopedArpIo {
  public:
    ~InstalledScopedBpfArpIo() override;
    bool open(const std::string &interfaceName, std::string *error) override;
    bool sendFrame(const unsigned char *frame, std::size_t length) override;
    void close() override;

  private:
    int descriptor_ = -1;
};

// Kernel-setting seam for the two session-owned sysctls. The default implementation is
// sysctlbyname on the fixed names; fakes keep every test and dry run offline.
class InstalledScopedSettingIo {
  public:
    virtual ~InstalledScopedSettingIo() = default;
    virtual bool read(const std::string &name, int *value) = 0;
    virtual bool write(const std::string &name, int value) = 0;
};

class InstalledScopedSysctlSettingIo final : public InstalledScopedSettingIo {
  public:
    bool read(const std::string &name, int *value) override;
    bool write(const std::string &name, int value) override;
};

// Durable cleanup-obligation journal for the installed scoped session. One file inside the
// trusted root-owned directory (openat, mode 0600, no symlink). Records are single lines,
// appended and fsynced; a non-empty file at start means unresolved obligations exist and a new
// session may not start until the explicit recovery path clears them. Only a fully verified
// teardown truncates it. Port of the PfRecoveryJournal discipline in minimal form; the Qt
// journals in interceptor_network remain the fixture/research-host implementation of the same
// semantics.
class InstalledScopedJournal {
  public:
    InstalledScopedJournal() = default;
    ~InstalledScopedJournal();

    InstalledScopedJournal(const InstalledScopedJournal &) = delete;
    InstalledScopedJournal &operator=(const InstalledScopedJournal &) = delete;

    // Opens (or notes the clean absence of) the obligations file. An absent file is the clean
    // state: it is created on demand by the first append, never pre-created.
    bool open(int trustedDirectoryFd);
    // Re-reads the durable state from the trusted directory; a Start re-checks the file so an
    // operator-side cleanup of a stranded record takes effect without a process restart.
    bool reopen();
    bool hasRecords() const { return !records_.empty(); }
    const std::vector<std::string> &records() const { return records_; }
    bool append(const std::string &record);
    bool clear();
    void close();

  private:
    bool flush();
    void closeDirectory();

    // Owned duplicate of the trusted directory descriptor: the caller stays free to close its
    // own fd right after construction; the journal keeps directory access for the whole process
    // lifetime (reopen and on-demand create both use it).
    int directoryFd_ = -1;
    int descriptor_ = -1;
    std::vector<std::string> records_;
};

// Production scoped PF/ARP backend for the installed session-control service. Composition of the
// ordering proven by the Qt scoped fixture (SCOPED_OPERATION_INTEGRATION.md): durable recovery
// clearance → neighbor/interface facts → PF enable token (journaled) → owned anchor install
// (journaled) → active-evaluation verification before any frame → kernel settings only where not
// already desired (previous values journaled) → redirect frames + bounded refresh loop. Teardown
// is exactly reverse, and `cleaned` is true only after verified removal of every owned effect.
// All entry points serialize on one private dispatch queue (the refresh timer ticks on the same
// queue), so heartbeat/stop/watchdog calls from the responder queue cannot interleave a
// mutation. Nothing here runs unless the operator gated the installed service into session
// control; tests can drive it entirely through the injected command and ARP seams.
class InstalledScopedOperations final : public InstalledSessionControlBackend {
  public:
    static constexpr int defaultCommandTimeoutMs = 2000;
    static constexpr int defaultRefreshIntervalMs = 500;
    static constexpr int minimumRefreshIntervalMs = 250;
    static constexpr int maximumRefreshIntervalMs = 2000;
    static constexpr std::size_t maximumOutputBytes = 64 * 1024;

    // borrowed seams and state-directory descriptor; the descriptor stays owned by the caller.
    InstalledScopedOperations(InstalledScopedCommandIo &commands, InstalledScopedArpIo &arp,
                              InstalledScopedSettingIo &settings, int trustedDirectoryFd,
                              int refreshIntervalMs = defaultRefreshIntervalMs,
                              std::function<std::string()> anchorIdFactory = {});
    ~InstalledScopedOperations() override;

    InstalledScopedOperations(const InstalledScopedOperations &) = delete;
    InstalledScopedOperations &operator=(const InstalledScopedOperations &) = delete;

    // SessionControlBackend surface.
    bool effectiveRoot() override;
    bool freshListenerVerification(const InstalledSessionTuple &tuple,
                                   const std::vector<unsigned char> &secret) override;
    bool startOwnedOperations(const InstalledSessionTuple &tuple, std::string *error) override;
    void heartbeatOwnedOperations() override; // refresh is timer-driven; heartbeats hold only.
    bool stopOwnedOperations(bool *cleaned, std::string *error) override;

  private:
    struct NeighborFacts {
        std::string researchMac, clientMac, serverMac;
    };

    bool startOnQueue(const InstalledSessionTuple &tuple, std::string *error);
    // Ordered reconciliation of durable obligations left by a previous start that died before
    // verified teardown (process restart with a non-empty journal). Only a fully verified
    // reconciliation clears the journal; any unknown record, uncertain token, or failed
    // verification stays `recovery_pending` truthfully.
    bool reconcileJournalOnQueue(std::string *error);
    void stopOnQueue(bool *cleaned, std::string *error);
    void refreshTickOnQueue();

    bool ruleActivelyLoaded(const std::string &anchor, std::string *error) const;
    bool removeAnchorVerified(const std::string &anchor, std::string *error);
    bool releaseTokenVerified(unsigned long long token, std::string *error);
    bool sendRestorationFrames();
    bool startRefreshTimer(std::string *error);
    void stopRefreshTimer();

    // Injected seams and configuration.
    InstalledScopedCommandIo &commands_;
    InstalledScopedArpIo &arp_;
    InstalledScopedSettingIo &settings_;
    int refreshIntervalMs_;
    const std::function<std::string()> anchorIdFactory_;
    InstalledScopedJournal journal_;

    // Owner state; must only be touched on queue_.
    dispatch_queue_t queue_ = nullptr;
    dispatch_source_t refreshTimer_ = nullptr;
    NeighborFacts facts_{};
    std::vector<std::vector<unsigned char>> redirectFrames_;
    std::vector<std::vector<unsigned char>> restorationFrames_;
    std::string anchor_;
    unsigned long long pfToken_ = 0;
    bool pfTokenUncertain_ = false;
    int previousForwarding_ = -1; // -1 = unchanged
    int previousSendRedirects_ = -1;
    bool arpActive_ = false;
    bool refreshUnhealthy_ = false;
};

} // namespace interceptor
