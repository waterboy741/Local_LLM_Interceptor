#include "InstalledScopedOperations.hpp"

#include "PosixSpawnChildProcess.hpp"

#include <Security/SecRandom.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/bpf.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <os/log.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <thread>

namespace interceptor {
namespace {

constexpr std::string_view pfctlPath = "/sbin/pfctl";
constexpr std::string_view arpPath = "/usr/sbin/arp";
constexpr std::string_view journalName = "scoped-session-obligations.journal";
constexpr std::size_t maximumJournalBytes = 16 * 1024;
constexpr std::size_t arpFrameSize = 60;
constexpr int maximumBpfDeviceIndex = 8;
constexpr int commandTimeoutMs = 2000;
constexpr std::string_view forwardingName = "net.inet.ip.forwarding";
constexpr std::string_view sendRedirectsName = "net.inet.ip.redirect";

// Trusted monotonic clock for phase timing only (never for security decisions).
std::int64_t monotonicMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

// One bounded, non-sensitive os_log line per startup/teardown phase: the fixed phase name and a
// clamped duration in milliseconds, nothing else. Durations are rounded to whole ms and clamped
// to [0, 600000] so no clock anomaly can produce an unbounded log value.
void logPhaseMs(const char *phase, std::int64_t elapsedMs) {
    std::int64_t clamped = elapsedMs < 0 ? 0 : (elapsedMs > 600000 ? 600000 : elapsedMs);
    os_log_error(OS_LOG_DEFAULT, "llm_interceptor.scoped-phase %{public}s duration_ms=%lld", phase,
                 static_cast<long long>(clamped));
}

// Logs its phase duration when the scope leaves, on both success and failure paths, so the last
// logged phase names exactly where a Start stopped making progress.
class ScopedPhaseLog final {
  public:
    explicit ScopedPhaseLog(const char *phase) : phase_(phase), startedMs_(monotonicMs()) {}
    ~ScopedPhaseLog() { logPhaseMs(phase_, monotonicMs() - startedMs_); }
    ScopedPhaseLog(const ScopedPhaseLog &) = delete;
    ScopedPhaseLog &operator=(const ScopedPhaseLog &) = delete;

  private:
    const char *phase_;
    std::int64_t startedMs_;
};

void fail(std::string *error, const char *reason) {
    if (error)
        *error = reason;
}

std::string trim(const std::string &value) {
    std::size_t begin = 0, end = value.size();
    while (begin < end && (value[begin] == ' ' || value[begin] == '\t' || value[begin] == '\r'))
        ++begin;
    while (end > begin &&
           (value[end - 1] == ' ' || value[end - 1] == '\t' || value[end - 1] == '\r'))
        --end;
    return value.substr(begin, end - begin);
}

std::string toLower(const std::string &value) {
    std::string lowered;
    lowered.reserve(value.size());
    for (const char character : value)
        lowered.push_back(character >= 'A' && character <= 'Z'
                              ? static_cast<char>(character - 'A' + 'a')
                              : character);
    return lowered;
}

bool asciiHex(const std::string &value) {
    bool anyDigit = false;
    for (const char character : value) {
        if (character == ':' || character == '-')
            continue; // MAC separators; decodeMac re-checks the exact digit count
        const bool digit = character >= '0' && character <= '9';
        const bool lower = character >= 'a' && character <= 'f';
        const bool upper = character >= 'A' && character <= 'F';
        if (!digit && !lower && !upper)
            return false;
        anyDigit = true;
    }
    return anyDigit;
}

std::vector<unsigned char> decodeMac(const std::string &hex) {
    std::vector<unsigned char> bytes;
    std::string digits;
    for (const char character : hex) {
        if (character == ':' || character == '-')
            continue;
        if (!asciiHex(std::string(1, character)))
            return {};
        digits.push_back(character);
    }
    if (digits.size() != 12)
        return {};
    for (std::size_t index = 0; index < digits.size(); index += 2)
        bytes.push_back(
            static_cast<unsigned char>(std::strtol(digits.substr(index, 2).c_str(), nullptr, 16)));
    return bytes;
}

std::string encodeMac(const unsigned char *raw, std::size_t length) {
    static const char digits[] = "0123456789abcdef";
    std::string mac;
    if (length != 6)
        return {};
    for (std::size_t index = 0; index < length; ++index) {
        if (index)
            mac.push_back(':');
        mac.push_back(digits[raw[index] >> 4]);
        mac.push_back(digits[raw[index] & 0xf]);
    }
    return mac;
}

std::string macAddressOfInterface(const std::string &interfaceName) {
    struct ifaddrs *addresses = nullptr;
    if (getifaddrs(&addresses) != 0)
        return {};
    std::string mac;
    for (struct ifaddrs *entry = addresses; entry; entry = entry->ifa_next) {
        if (!entry->ifa_addr || entry->ifa_addr->sa_family != AF_LINK ||
            interfaceName != entry->ifa_name)
            continue;
        const auto *socketAddress = reinterpret_cast<const struct sockaddr_dl *>(entry->ifa_addr);
        const auto *raw = reinterpret_cast<const unsigned char *>(socketAddress->sdl_data +
                                                                  socketAddress->sdl_nlen);
        if (socketAddress->sdl_alen != 6 || (entry->ifa_flags & IFF_UP) == 0 ||
            (entry->ifa_flags & IFF_RUNNING) == 0 || (entry->ifa_flags & IFF_LOOPBACK) != 0)
            break;
        mac = encodeMac(raw, socketAddress->sdl_alen);
        break;
    }
    freeifaddrs(addresses);
    return mac;
}

// Mirrors the reviewed neighbor-identity parse discipline: the entry must name exactly the
// address and resolve on exactly the session interface.
std::string neighborMacOnInterface(const std::string &arpOutput, const std::string &address,
                                   const std::string &interfaceName) {
    std::size_t position = 0;
    while (position < arpOutput.size()) {
        std::size_t end = arpOutput.find('\n', position);
        if (end == std::string::npos)
            end = arpOutput.size();
        const std::string line = arpOutput.substr(position, end - position);
        position = end + 1;
        const std::size_t addressAt = line.find('(' + address + ')');
        if (addressAt == std::string::npos)
            continue;
        const std::size_t at = line.find(" at ", addressAt);
        if (at == std::string::npos)
            continue;
        const std::size_t macBegin = at + 4;
        const std::size_t macEnd = line.find_first_of(" \t", macBegin);
        if (macEnd == std::string::npos)
            continue;
        const std::string mac = trim(line.substr(macBegin, macEnd - macBegin));
        const std::size_t on = line.find(" on ", macEnd);
        if (on == std::string::npos || !asciiHex(mac))
            continue;
        // Real `arp -n` output is `? (a.b.c.d) at MAC on en0 ifscope [ethernet]` (and
        // `permanent` variants); the interface is the single token after "on".
        const std::string remainder = line.substr(on + 4);
        const std::size_t interfaceEnd = remainder.find_first_of(" \t");
        const std::string interface =
            trim(interfaceEnd == std::string::npos ? remainder : remainder.substr(0, interfaceEnd));
        if (interface != interfaceName || decodeMac(mac).size() != 6)
            continue;
        return mac;
    }
    return {};
}

// Mirrors the reviewed enable-token parse: exactly one Token line carrying the decimal token,
// no other non-empty content, zero rejected.
bool parseEnableToken(const std::string &output, unsigned long long *token) {
    std::size_t position = 0;
    bool seen = false;
    while (position <= output.size()) {
        std::size_t end = output.find('\n', position);
        if (end == std::string::npos)
            end = output.size();
        std::string line = output.substr(position, end - position);
        position = end + 1;
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        line = trim(line);
        if (line.empty())
            continue;
        // Ground truth observed live on this macOS 26/27 build, in this order: `pfctl -E`
        // prefixes the Token line with the two ALTQ lines plus a `pf enabled` status line.
        // Tolerated only before the Token line; anything else keeps the uncertain/fail-closed
        // verdict.
        const std::string loweredLine = toLower(line);
        if (!seen &&
            (loweredLine == "no altq support in kernel" ||
             loweredLine == "altq related functions disabled" || loweredLine == "pf enabled"))
            continue;
        const std::size_t colon = line.find(':');
        if (colon == std::string::npos || seen || line.size() > 32 ||
            toLower(trim(line.substr(0, colon))) != "token")
            return false;
        const std::string digits = trim(line.substr(colon + 1));
        if (digits.empty() || digits.size() > 20 ||
            digits.find_first_not_of("0123456789") != std::string::npos)
            return false;
        errno = 0;
        char *stopped = nullptr;
        const unsigned long long parsed = std::strtoull(digits.c_str(), &stopped, 10);
        if (errno != 0 || !stopped || *stopped != '\0' || parsed == 0)
            return false;
        seen = true;
        *token = parsed;
    }
    return seen;
}

enum class ReferenceState { Active, Absent, Unknown };

// Mirrors the reviewed reference classifier: Active requires a token-naming line containing
// the exact decimal token; Absent requires a recognized fully empty table; anything else stays
// Unknown so a cleanup obligation is never cleared on hope.
ReferenceState classifyReferenceTable(const std::string &output, unsigned long long token) {
    bool recognizedEmpty = false;
    std::size_t position = 0;
    while (position < output.size()) {
        std::size_t end = output.find('\n', position);
        if (end == std::string::npos)
            end = output.size();
        const std::string trimmed = trim(output.substr(position, end - position));
        position = end + 1;
        if (trimmed.empty())
            continue;
        const std::string lowered = toLower(trimmed);
        if (lowered.find("token") != std::string::npos) {
            std::size_t index = 0;
            while (index < lowered.size()) {
                if (lowered[index] >= '0' && lowered[index] <= '9') {
                    std::size_t digitsEnd = index;
                    while (digitsEnd < lowered.size() && lowered[digitsEnd] >= '0' &&
                           lowered[digitsEnd] <= '9')
                        ++digitsEnd;
                    errno = 0;
                    const unsigned long long parsed = std::strtoull(
                        lowered.substr(index, digitsEnd - index).c_str(), nullptr, 10);
                    if (errno == 0 && parsed == token)
                        return ReferenceState::Active;
                    index = digitsEnd;
                } else {
                    ++index;
                }
            }
            continue;
        }
        if (lowered == "no references" || lowered == "references: 0" || lowered == "refs: 0" ||
            // Ground truth observed live on this macOS 26/27 build: the empty-state reference
            // query answers with exactly this line.
            lowered == "no pf starter references held") {
            recognizedEmpty = true;
            continue;
        }
        // Ground-truth ALTQ preamble observed live on this build, preceding both the empty-state
        // line and the TOKENS table; tolerated exactly in this bounded two-line form, and
        // anything else keeps the Unknown verdict.
        if (lowered == "no altq support in kernel" || lowered == "altq related functions disabled")
            continue;
        return ReferenceState::Unknown;
    }
    return recognizedEmpty ? ReferenceState::Absent : ReferenceState::Unknown;
}

// Verified-empty anchor listing: exit 0 plus a listing whose every non-empty line is the
// bounded pfctl status preamble this build prefixes to every invocation (`No ALTQ support in
// kernel`, `ALTQ related functions disabled`); any other non-empty content keeps the obligation
// (fail-closed).
bool listingVerifiedEmpty(const std::string &listing) {
    std::size_t position = 0;
    while (position < listing.size()) {
        std::size_t end = listing.find('\n', position);
        if (end == std::string::npos)
            end = listing.size();
        const std::string trimmed = trim(listing.substr(position, end - position));
        position = end + 1;
        if (trimmed.empty())
            continue;
        const std::string lowered = toLower(trimmed);
        if (lowered != "no altq support in kernel" && lowered != "altq related functions disabled")
            return false;
    }
    return true;
}

void putWord(std::vector<unsigned char> &frame, unsigned short value) {
    frame.push_back(static_cast<unsigned char>(value >> 8));
    frame.push_back(static_cast<unsigned char>(value & 0xff));
}

bool putIpv4(const std::string &text, std::vector<unsigned char> &frame) {
    struct in_addr parsed{};
    if (inet_pton(AF_INET, text.c_str(), &parsed) != 1)
        return false;
    for (std::size_t index = 0; index < 4; ++index)
        frame.push_back(reinterpret_cast<const unsigned char *>(&parsed.s_addr)[index]);
    return true;
}

// Port of the reviewed 60-byte ARP-reply encoding: the Ethernet source and the ARP sender
// hardware address are separate inputs, matching ArpCodec (restoration frames send the real
// peer MAC as the ARP sender while the frame still originates from this host).
std::vector<unsigned char> encodeArpReply(const std::vector<unsigned char> &ethernetDestination,
                                          const std::vector<unsigned char> &ethernetSource,
                                          const std::vector<unsigned char> &senderHardwareAddress,
                                          const std::string &senderIp,
                                          const std::vector<unsigned char> &targetHardwareAddress,
                                          const std::string &targetIp) {
    if (ethernetDestination.size() != 6 || ethernetSource.size() != 6 ||
        senderHardwareAddress.size() != 6 || targetHardwareAddress.size() != 6)
        return {};
    std::vector<unsigned char> frame;
    frame.reserve(arpFrameSize);
    frame.insert(frame.end(), ethernetDestination.begin(), ethernetDestination.end());
    frame.insert(frame.end(), ethernetSource.begin(), ethernetSource.end());
    putWord(frame, 0x0806);
    putWord(frame, 1);
    putWord(frame, 0x0800);
    frame.push_back(6);
    frame.push_back(4);
    putWord(frame, 2); // reply
    frame.insert(frame.end(), senderHardwareAddress.begin(), senderHardwareAddress.end());
    if (!putIpv4(senderIp, frame))
        return {};
    frame.insert(frame.end(), targetHardwareAddress.begin(), targetHardwareAddress.end());
    if (!putIpv4(targetIp, frame))
        return {};
    frame.resize(arpFrameSize, 0);
    return frame;
}

// Scoped rules, mirroring the reviewed snapshot generation: one rdr to the bound listener plus
// the paired pass rules; the inbound rdr matches only the client IP, so the research host's own
// upstream traffic never loops.
std::string sessionPfRules(const InstalledSessionTuple &tuple, const std::string &sessionKey) {
    const std::string interface = "\"" + tuple.interfaceName + "\"";
    const std::string label = "\"llm_" + sessionKey + "\"";
    std::string rules;
    rules += "rdr on " + interface + " inet proto tcp from " + tuple.clientIpv4 + " to " +
             tuple.upstreamIpv4 + " port " + std::to_string(tuple.upstreamPort) + " -> " +
             tuple.listenAddress + " port " + std::to_string(tuple.listenerPort) + "\n" +
             "pass in quick on " + interface + " inet proto tcp from " + tuple.clientIpv4 + " to " +
             tuple.listenAddress + " port " + std::to_string(tuple.listenerPort) +
             " flags S/SA keep state label " + label + "\n" + "pass out quick on " + interface +
             " inet proto tcp from " + tuple.listenAddress + " to " + tuple.upstreamIpv4 +
             " port " + std::to_string(tuple.upstreamPort) + " flags S/SA keep state label " +
             label + "\n";
    return rules;
}

bool commandCompleted(const InstalledScopedCommandIo::Result &result) {
    return result.started && result.reaped && result.normalExit && result.exitCode == 0;
}

bool writeAll(int descriptor, const char *data, std::size_t length) {
    std::size_t written = 0;
    while (written < length) {
        const ssize_t result = ::write(descriptor, data + written, length - written);
        if (result < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        written += static_cast<std::size_t>(result);
    }
    return true;
}

} // namespace

bool InstalledScopedSysctlSettingIo::read(const std::string &name, int *value) {
    int parsed = 0;
    std::size_t size = sizeof(parsed);
    if (::sysctlbyname(name.c_str(), &parsed, &size, nullptr, 0) != 0 || size != sizeof(parsed))
        return false;
    *value = parsed;
    return true;
}

bool InstalledScopedSysctlSettingIo::write(const std::string &name, int value) {
    return ::sysctlbyname(name.c_str(), nullptr, nullptr, &value, sizeof(value)) == 0;
}

InstalledScopedCommandIo::Result InstalledScopedSpawnCommandIo::run(
    const std::string &program, const std::vector<std::string> &arguments,
    const std::string *standardInput, int timeoutMs, std::size_t maximumOutputBytes) {
    Result result;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    const auto remainingMs = [&]() {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                                   deadline - std::chrono::steady_clock::now())
                                   .count();
        return remaining < 0 ? 0 : static_cast<int>(remaining);
    };

    PosixSpawnChildProcess engine;
    if (!engine.start(program, arguments))
        return result;
    result.started = true;
    if (standardInput) {
        if (engine.write(standardInput->data(), standardInput->size()) != standardInput->size())
            return result;
        if (!engine.waitForBytesFlushed(remainingMs()))
            return result;
    }
    engine.closeWrite();
    while (engine.waitForReadable(remainingMs())) {
        const std::size_t remainingBytes = result.standardOutput.size() >= maximumOutputBytes
                                               ? 0
                                               : maximumOutputBytes - result.standardOutput.size();
        // Both channels must be drained: waitForReadable reports a pending child as readable when
        // EITHER stream holds bytes (pfctl legitimately writes warnings to stderr), and a stdout
        // read that drains nothing would re-enter the loop immediately and spin without ever
        // reaping. stderr is captured bounded alongside stdout.
        if (remainingBytes == 0 && result.standardError.size() >= maximumOutputBytes)
            break;
        result.standardOutput += engine.readStandardOutput(remainingBytes);
        const std::size_t remainingErrorBytes =
            result.standardError.size() >= maximumOutputBytes
                ? 0
                : maximumOutputBytes - result.standardError.size();
        result.standardError += engine.readStandardError(remainingErrorBytes);
    }
    if (!engine.waitForFinished(remainingMs()))
        return result; // not reaped: the engine keeps and reaps the child
    result.reaped = true;
    result.normalExit = engine.normalExit();
    result.exitCode = engine.exitCode();
    return result;
}

InstalledScopedBpfArpIo::~InstalledScopedBpfArpIo() { close(); }

bool InstalledScopedBpfArpIo::open(const std::string &interfaceName, std::string *error) {
    if (error)
        error->clear();
    close();
    if (interfaceName.empty() || interfaceName.size() >= IFNAMSIZ)
        return fail(error, "arb_interface_invalid"), false;
    const int flags = O_RDWR | O_CLOEXEC | O_NONBLOCK;
    for (int index = 0; index <= maximumBpfDeviceIndex; ++index) {
        const std::string path = "/dev/bpf" + std::to_string(index);
        const int descriptor = ::open(path.c_str(), flags);
        if (descriptor >= 0) {
            descriptor_ = descriptor;
            break;
        }
        if (errno != EBUSY && errno != ENOENT)
            return fail(error, "arp_writer_open_failed"), false;
    }
    if (descriptor_ < 0)
        return fail(error, "arp_writer_open_failed"), false;

    struct ifreq interfaceRequest{};
    std::memcpy(interfaceRequest.ifr_name, interfaceName.c_str(), interfaceName.size() + 1);
    if (::ioctl(descriptor_, BIOCSETIF, &interfaceRequest) < 0) {
        close();
        return fail(error, "arp_writer_attach_failed"), false;
    }
    u_int linkType = 0;
    if (::ioctl(descriptor_, BIOCGDLT, &linkType) < 0 || linkType != DLT_EN10MB) {
        close();
        return fail(error, "arp_writer_link_type_unsupported"), false;
    }
    u_int headerComplete = 1;
    if (::ioctl(descriptor_, BIOCSHDRCMPLT, &headerComplete) < 0) {
        close();
        return fail(error, "arp_writer_header_completion_failed"), false;
    }
    headerComplete = 0;
    if (::ioctl(descriptor_, BIOCGHDRCMPLT, &headerComplete) < 0 || headerComplete != 1) {
        close();
        return fail(error, "arp_writer_header_completion_failed"), false;
    }
    return true;
}

bool InstalledScopedBpfArpIo::sendFrame(const unsigned char *frame, std::size_t length) {
    if (descriptor_ < 0 || !frame || length == 0 || length > arpFrameSize)
        return false;
    ssize_t written = 0;
    do {
        written = ::write(descriptor_, frame, length);
    } while (written < 0 && errno == EINTR);
    // A BPF write below the frame length means the redirect mapping may not have applied; the
    // caller records it as an uncertain write, never as success.
    return written == static_cast<ssize_t>(length);
}

void InstalledScopedBpfArpIo::close() {
    if (descriptor_ >= 0) {
        ::close(descriptor_);
        descriptor_ = -1;
    }
}

InstalledScopedJournal::~InstalledScopedJournal() { close(); }

bool InstalledScopedJournal::open(int trustedDirectoryFd) {
    close();
    if (trustedDirectoryFd < 0)
        return false;
    directoryFd_ = trustedDirectoryFd;
    // No O_CREAT: an absent file is the CLEAN state (no obligations), not an error; the file is
    // created on demand by the first append, never pre-created. Every other open failure stays
    // an error so an unreadable existing journal never silently becomes clean.
    descriptor_ = ::openat(trustedDirectoryFd, std::string(journalName).c_str(),
                           O_RDWR | O_CLOEXEC | O_APPEND);
    if (descriptor_ < 0) {
        if (errno == ENOENT)
            return true; // clean: no obligation file exists
        descriptor_ = -1;
        return false;
    }
    std::string content;
    char buffer[4096];
    ssize_t received = 0;
    // O_APPEND bounds reads to the start; use pread until EOF for the recovery view.
    std::size_t offset = 0;
    while ((received = ::pread(descriptor_, buffer, sizeof(buffer), static_cast<off_t>(offset))) >
           0) {
        content.append(buffer, static_cast<std::size_t>(received));
        offset += static_cast<std::size_t>(received);
        if (content.size() > maximumJournalBytes) {
            close();
            return false;
        }
    }
    if (received < 0) {
        close();
        return false;
    }
    std::size_t position = 0;
    while (position < content.size()) {
        std::size_t end = content.find('\n', position);
        if (end == std::string::npos)
            end = content.size();
        if (end > position)
            records_.push_back(content.substr(position, end - position));
        position = end + 1;
    }
    return true;
}

bool InstalledScopedJournal::reopen() { return open(directoryFd_); }

bool InstalledScopedJournal::append(const std::string &record) {
    if (directoryFd_ < 0 || record.empty() || record.size() > 256 ||
        record.find('\n') != std::string::npos)
        return false;
    if (descriptor_ < 0) {
        // Create on demand: the first obligation ever written is what creates the file.
        descriptor_ = ::openat(directoryFd_, std::string(journalName).c_str(),
                               O_WRONLY | O_CREAT | O_CLOEXEC | O_APPEND, 0600);
        if (descriptor_ < 0)
            return false;
    }
    std::string line = record;
    line.push_back('\n');
    if (!writeAll(descriptor_, line.data(), line.size()) || ::fsync(descriptor_) != 0)
        return false;
    records_.push_back(record);
    return true;
}

bool InstalledScopedJournal::clear() {
    if (descriptor_ < 0)
        return false;
    if (::ftruncate(descriptor_, 0) != 0 || ::fsync(descriptor_) != 0)
        return false;
    records_.clear();
    return true;
}

void InstalledScopedJournal::close() {
    if (descriptor_ >= 0) {
        ::close(descriptor_);
        descriptor_ = -1;
    }
    records_.clear();
}

InstalledScopedOperations::InstalledScopedOperations(InstalledScopedCommandIo &commands,
                                                     InstalledScopedArpIo &arp,
                                                     InstalledScopedSettingIo &settings,
                                                     int trustedDirectoryFd, int refreshIntervalMs,
                                                     std::function<std::string()> anchorIdFactory)
    : commands_(commands), arp_(arp), settings_(settings), refreshIntervalMs_(refreshIntervalMs),
      anchorIdFactory_(anchorIdFactory ? std::move(anchorIdFactory) : [] {
          unsigned char identifier[8];
          static const char digits[] = "0123456789abcdef";
          if (SecRandomCopyBytes(kSecRandomDefault, sizeof(identifier), identifier) !=
              errSecSuccess)
              return std::string();
          std::string key;
          key.reserve(16);
          for (const unsigned char byte : identifier) {
              key.push_back(digits[byte >> 4]);
              key.push_back(digits[byte & 0xf]);
          }
          return key;
      }) {
    queue_ =
        dispatch_queue_create("org.local-llm-interceptor.scoped-operations", DISPATCH_QUEUE_SERIAL);
    journal_.open(trustedDirectoryFd);
    if (refreshIntervalMs_ < minimumRefreshIntervalMs ||
        refreshIntervalMs_ > maximumRefreshIntervalMs)
        refreshIntervalMs_ = defaultRefreshIntervalMs;
}

InstalledScopedOperations::~InstalledScopedOperations() {
    if (arpActive_ || !anchor_.empty() || pfToken_ != 0 || pfTokenUncertain_ ||
        previousForwarding_ >= 0 || previousSendRedirects_ >= 0) {
        bool cleaned = false;
        (void)stopOwnedOperations(&cleaned, nullptr);
    }
    stopRefreshTimer();
    if (queue_)
        dispatch_release(queue_);
}

bool InstalledScopedOperations::effectiveRoot() { return ::geteuid() == 0; }

bool InstalledScopedOperations::freshListenerVerification(
    const InstalledSessionTuple &tuple, const std::vector<unsigned char> &secret) {
    return verifyTransparentListenerProbe(tuple, secret, 2000);
}

bool InstalledScopedOperations::startOwnedOperations(const InstalledSessionTuple &tuple,
                                                     std::string *error) {
    if (error)
        error->clear();
    if (!queue_) {
        fail(error, "internal_queue_unavailable");
        return false;
    }
    __block std::string startError;
    __block bool started = false;
    dispatch_sync(queue_, ^{
      started = startOnQueue(tuple, &startError);
    });
    if (error)
        *error = std::move(startError);
    return started;
}

void InstalledScopedOperations::heartbeatOwnedOperations() {
    // The bounded refresh loop is timer-driven on the backend queue; a GUI heartbeat holds the
    // core watchdog but does not need to touch owned state.
}

bool InstalledScopedOperations::stopOwnedOperations(bool *cleaned, std::string *error) {
    if (error)
        error->clear();
    if (cleaned)
        *cleaned = false;
    if (!queue_)
        return false;
    __block std::string stopError;
    __block bool localCleaned = false;
    dispatch_sync(queue_, ^{
      stopOnQueue(&localCleaned, &stopError);
    });
    if (error)
        *error = std::move(stopError);
    if (cleaned)
        *cleaned = localCleaned;
    return localCleaned;
}

bool InstalledScopedOperations::startOnQueue(const InstalledSessionTuple &tuple,
                                             std::string *error) {
    const auto failStart = [this, error](const char *reason) {
        bool cleaned = false;
        std::string rollbackError;
        stopOnQueue(&cleaned, &rollbackError);
        if (error)
            *error = reason;
        return false;
    };

    if (arpActive_ || !anchor_.empty() || pfToken_ != 0 || pfTokenUncertain_) {
        fail(error, "session_already_owned");
        return false;
    }
    ScopedPhaseLog totalPhase("start_total");
    // Always logged, including the empty-journal no-op, so an absent line is unambiguous.
    {
        ScopedPhaseLog reconcilePhase("journal_reconcile");
        // Re-read the durable state before deciding: an absent file is clean (create-on-demand
        // handled by the journal itself), and an operator-side cleanup of a stranded record by
        // the documented path takes effect on the next Start without a process restart.
        if (!journal_.reopen())
            return failStart("journal_unavailable");
        if (journal_.hasRecords()) {
            // A previous start died with obligations outstanding (process restart with a
            // journaled enable token, anchor, or settings restore). Attempt the ordered
            // reconciliation before deciding: fully verified recovery clears the journal and the
            // fresh start proceeds, and any uncertain or failed step stays recovery_pending so
            // the operator is never told a lie.
            std::string recoveryError;
            if (!reconcileJournalOnQueue(&recoveryError)) {
                if (error)
                    *error = recoveryError.empty() ? "recovery_pending" : recoveryError;
                return false;
            }
        }
    }

    // Neighbor and interface facts (fresh, never cached): the interface MAC must be live, and
    // both the client and upstream must resolve on exactly this interface right now.
    const std::int64_t neighborStartedMs = monotonicMs();
    NeighborFacts facts;
    facts.researchMac = macAddressOfInterface(tuple.interfaceName);
    if (facts.researchMac.empty()) {
        fail(error, "interface_mac_unavailable");
        return false;
    }
    std::string *const clientMacOut = &facts.clientMac;
    std::string *const serverMacOut = &facts.serverMac;
    for (const auto &lookup : {std::make_pair(std::cref(tuple.clientIpv4), clientMacOut),
                               std::make_pair(std::cref(tuple.upstreamIpv4), serverMacOut)}) {
        const auto result = commands_.run(std::string(arpPath), {"-n", lookup.first}, nullptr,
                                          commandTimeoutMs, maximumOutputBytes);
        *lookup.second =
            neighborMacOnInterface(result.standardOutput, lookup.first, tuple.interfaceName);
        if (lookup.second->empty()) {
            fail(error, "neighbor_identity_unavailable");
            return false;
        }
    }
    logPhaseMs("neighbor_facts", monotonicMs() - neighborStartedMs);

    const std::int64_t settingsSnapshotStartedMs = monotonicMs();
    int forwarding = 0, sendRedirects = 0;
    if (!settings_.read(std::string(forwardingName), &forwarding) ||
        !settings_.read(std::string(sendRedirectsName), &sendRedirects)) {
        return failStart("settings_unavailable");
    }
    logPhaseMs("settings_snapshot", monotonicMs() - settingsSnapshotStartedMs);

    // PF enable reference: capture the exact token and journal the obligation durably. The
    // command itself gets its own preflight line so an absent pfctl_enable_token line localizes
    // the failure to the token parse instead of to the spawned command.
    const std::int64_t enableStartedMs = monotonicMs();
    const auto enabled = commands_.run(std::string(pfctlPath), {"-E"}, nullptr, commandTimeoutMs,
                                       maximumOutputBytes);
    logPhaseMs("pf_reference_preflight", monotonicMs() - enableStartedMs);
    unsigned long long token = 0;
    if (commandCompleted(enabled) && parseEnableToken(enabled.standardOutput, &token)) {
        pfToken_ = token;
        if (!journal_.append("pf-token " + std::to_string(token)))
            return failStart("journal_unavailable");
    } else if (enabled.started) {
        // Started but unreaped/unparsable: the command may have run, so the obligation stands.
        pfTokenUncertain_ = true;
        (void)journal_.append("pf-token-uncertain");
        return failStart("pf_reference_uncertain");
    } else {
        return failStart("pf_reference_unavailable");
    }
    logPhaseMs("pfctl_enable_token", monotonicMs() - enableStartedMs);

    // Owned anchor: scoped rules, then install through the one typed command path.
    const std::string sessionKey = anchorIdFactory_();
    if (sessionKey.empty())
        return failStart("session_key_unavailable");
    anchor_ = "llm_interceptor/" + sessionKey;
    const std::int64_t anchorStartedMs = monotonicMs();
    const std::string rules = sessionPfRules(tuple, sessionKey);
    const auto installed = commands_.run(std::string(pfctlPath), {"-a", anchor_, "-f", "-"}, &rules,
                                         commandTimeoutMs, maximumOutputBytes);
    if (!commandCompleted(installed)) {
        (void)journal_.append("anchor " + anchor_); // obligation stands until verified removed
        return failStart("anchor_install_uncertain");
    }
    if (!journal_.append("anchor " + anchor_))
        return failStart("journal_unavailable");
    logPhaseMs("anchor_install", monotonicMs() - anchorStartedMs);

    // Active-evaluation verification before any frame: the anchor must actually hold both owned
    // rule types. Success is never inferred from an empty response.
    const std::int64_t evaluationStartedMs = monotonicMs();
    std::string verificationError;
    if (!ruleActivelyLoaded(anchor_, &verificationError))
        return failStart("anchor_verification_failed");
    logPhaseMs("active_evaluation", monotonicMs() - evaluationStartedMs);

    // Kernel settings only where not already at the desired values; the previous value is
    // journaled before the write so an uncertain crash restores it.
    const std::int64_t settingsStartedMs = monotonicMs();
    if (forwarding != 1) {
        if (!journal_.append("forwarding-restore " + std::to_string(forwarding)))
            return failStart("journal_unavailable");
        if (!settings_.write(std::string(forwardingName), 1))
            return failStart("forwarding_setup_failed");
        previousForwarding_ = forwarding;
    }
    if (sendRedirects != 0) {
        if (!journal_.append("redirects-restore " + std::to_string(sendRedirects)))
            return failStart("journal_unavailable");
        if (!settings_.write(std::string(sendRedirectsName), 0))
            return failStart("redirects_setup_failed");
        previousSendRedirects_ = sendRedirects;
    }
    logPhaseMs("settings", monotonicMs() - settingsStartedMs);

    // ARP redirect frames (pairwise) and bounded refresh (client mapping only).
    const auto research = decodeMac(facts.researchMac), client = decodeMac(facts.clientMac),
               server = decodeMac(facts.serverMac);
    const auto toClientRedirect =
        encodeArpReply(client, research, research, tuple.upstreamIpv4, client, tuple.clientIpv4);
    const auto toServerRedirect =
        encodeArpReply(server, research, research, tuple.clientIpv4, server, tuple.upstreamIpv4);
    const auto toClientRestore =
        encodeArpReply(client, research, server, tuple.upstreamIpv4, client, tuple.clientIpv4);
    const auto toServerRestore =
        encodeArpReply(server, research, client, tuple.clientIpv4, server, tuple.upstreamIpv4);
    if (toClientRedirect.empty() || toServerRedirect.empty() || toClientRestore.empty() ||
        toServerRestore.empty())
        return failStart("arp_frame_unavailable");
    redirectFrames_ = {toClientRedirect, toServerRedirect};
    restorationFrames_ = {toClientRestore, toServerRestore};

    const std::int64_t arpStartedMs = monotonicMs();
    std::string arpError;
    if (!arp_.open(tuple.interfaceName, &arpError))
        return failStart("arp_writer_unavailable");
    arpActive_ = true;
    logPhaseMs("arp_open", monotonicMs() - arpStartedMs);
    const std::int64_t framesStartedMs = monotonicMs();
    for (const auto &frame : redirectFrames_) {
        if (!arp_.sendFrame(frame.data(), frame.size())) {
            (void)sendRestorationFrames();
            return failStart("arp_write_failed");
        }
    }
    logPhaseMs("arp_first_frames", monotonicMs() - framesStartedMs);
    if (!startRefreshTimer(&arpError))
        return failStart("arp_refresh_timer_unavailable");
    facts_ = facts;
    refreshUnhealthy_ = false;
    return true;
}

bool InstalledScopedOperations::reconcileJournalOnQueue(std::string *error) {
    // Parse the durable records exactly as startOnQueue writes them; anything unrecognized or
    // unparsable keeps the journal and the recovery_pending verdict.
    std::string anchor;
    unsigned long long token = 0;
    bool tokenUncertain = false;
    int previousForwarding = -1, previousSendRedirects = -1;
    const auto recoverFailure = [error] {
        // Every reconciliation failure keeps the single bounded verdict from the contract
        // vocabulary; the specific failed step stays visible through the helper-side reject log.
        if (error)
            *error = "recovery_pending";
        return false;
    };
    for (const std::string &record : journal_.records()) {
        const auto prefixMatch = [&record](const char *prefix) {
            const std::size_t length = std::strlen(prefix);
            return record.size() > length && record.compare(0, length, prefix) == 0
                       ? record.substr(length)
                       : std::string();
        };
        if (record == "pf-token-uncertain") {
            // An unnamed token cannot be released with reference verification; recovery stays
            // pending and the operator-facing verdict names it truthfully.
            tokenUncertain = true;
            continue;
        }
        if (std::string value = prefixMatch("pf-token "); !value.empty()) {
            char *end = nullptr;
            token = std::strtoull(value.c_str(), &end, 10);
            if (!end || *end != '\0' || token == 0)
                return recoverFailure();
            continue;
        }
        if (std::string value = prefixMatch("anchor "); !value.empty()) {
            anchor = value;
            continue;
        }
        if (std::string value = prefixMatch("forwarding-restore "); !value.empty()) {
            previousForwarding = std::atoi(value.c_str());
            if (previousForwarding < 0)
                return recoverFailure();
            continue;
        }
        if (std::string value = prefixMatch("redirects-restore "); !value.empty()) {
            previousSendRedirects = std::atoi(value.c_str());
            if (previousSendRedirects < 0)
                return recoverFailure();
            continue;
        }
        return recoverFailure();
    }
    if (tokenUncertain)
        return recoverFailure();
    // Journal-order integrity: startOnQueue always appends the enable reference before any
    // anchor or settings record, so a journal without a token record is corrupt or synthetic and
    // stays recovery_pending without a single command. Only a named token reconciles.
    if (token == 0)
        return recoverFailure();

    // Reconcile in exactly the teardown order: owned anchor first (verified removal), then the
    // journaled previous kernel settings, then the exact enable reference (verified absence).
    // A failed or uncertain step keeps the record; only full verified recovery truncates.
    if (!anchor.empty() && !removeAnchorVerified(anchor, error))
        return recoverFailure();
    if (previousForwarding >= 0 &&
        !settings_.write(std::string(forwardingName), previousForwarding))
        return recoverFailure();
    if (previousSendRedirects >= 0 &&
        !settings_.write(std::string(sendRedirectsName), previousSendRedirects))
        return recoverFailure();
    if (token != 0 && !releaseTokenVerified(token, error))
        return recoverFailure();
    if (!journal_.clear())
        return recoverFailure();
    return true;
}

void InstalledScopedOperations::stopOnQueue(bool *cleaned, std::string *error) {
    ScopedPhaseLog totalPhase("stop_total");
    if (cleaned)
        *cleaned = false;
    stopRefreshTimer();
    bool ok = true;

    // 1: cease ARP and restore the pairwise mappings (best effort; an uncertain send keeps the
    // obligation and is surfaced, never guessed).
    if (arpActive_) {
        if (!sendRestorationFrames()) {
            ok = false;
            fail(error, "neighbor_restoration_uncertain");
        }
        arp_.close();
        arpActive_ = false;
    }

    // 2: remove the owned anchor and verify it empty (both listings, exit 0, empty only).
    if (!anchor_.empty()) {
        if (!removeAnchorVerified(anchor_, error))
            ok = false;
    }

    // 3: restore the kernel settings to the previously recorded values.
    if (previousForwarding_ >= 0) {
        if (!settings_.write(std::string(forwardingName), previousForwarding_)) {
            ok = false;
            fail(error, "forwarding_restore_failed");
        } else {
            previousForwarding_ = -1;
        }
    }
    if (previousSendRedirects_ >= 0) {
        if (!settings_.write(std::string(sendRedirectsName), previousSendRedirects_)) {
            ok = false;
            fail(error, "redirects_restore_failed");
        } else {
            previousSendRedirects_ = -1;
        }
    }

    // 4: release the exact enable token and verify its absence with the reference query.
    if (pfToken_ != 0) {
        if (!releaseTokenVerified(pfToken_, error))
            ok = false;
    }
    if (pfTokenUncertain_) {
        ok = false; // an unrecoverable token cannot be named for verified release
        fail(error, "pf_token_unrecoverable");
    }

    // Only a fully verified teardown drops the in-memory obligations and the durable journal, so
    // a Stop retry re-drives exactly the steps that failed.
    if (!ok)
        return;
    if (!journal_.clear()) {
        fail(error, "journal_clear_failed");
        return;
    }
    anchor_.clear();
    pfToken_ = 0;
    pfTokenUncertain_ = false;
    redirectFrames_.clear();
    restorationFrames_.clear();
    if (cleaned)
        *cleaned = true;
}

void InstalledScopedOperations::refreshTickOnQueue() {
    if (!arpActive_ || refreshUnhealthy_ || redirectFrames_.empty())
        return;
    // Only the client mapping is re-announced during the session (bounded interval).
    const auto &frame = redirectFrames_[0];
    if (!arp_.sendFrame(frame.data(), frame.size())) {
        refreshUnhealthy_ = true;
        // Immediate pairwise correction after a failed or uncertain redirect.
        (void)sendRestorationFrames();
    }
}

bool InstalledScopedOperations::ruleActivelyLoaded(const std::string &anchor,
                                                   std::string *error) const {
    const auto natListing = commands_.run(std::string(pfctlPath), {"-s", "nat", "-a", anchor},
                                          nullptr, commandTimeoutMs, maximumOutputBytes);
    const auto ruleListing = commands_.run(std::string(pfctlPath), {"-s", "rules", "-a", anchor},
                                           nullptr, commandTimeoutMs, maximumOutputBytes);
    if (!commandCompleted(natListing) || !commandCompleted(ruleListing)) {
        fail(error, "anchor_listing_failed");
        return false;
    }
    const std::string nat = toLower(natListing.standardOutput);
    const std::string rules = toLower(ruleListing.standardOutput);
    if (nat.find("rdr") == std::string::npos || rules.find("pass") == std::string::npos) {
        fail(error, "anchor_rules_not_active");
        return false;
    }
    return true;
}

bool InstalledScopedOperations::removeAnchorVerified(const std::string &anchor,
                                                     std::string *error) {
    for (const std::string &flush : {std::string("nat"), std::string("rules")}) {
        const auto removed = commands_.run(std::string(pfctlPath), {"-a", anchor, "-F", flush},
                                           nullptr, commandTimeoutMs, maximumOutputBytes);
        if (!commandCompleted(removed)) {
            fail(error, "anchor_cleanup_failed");
            return false;
        }
    }
    const auto natListing = commands_.run(std::string(pfctlPath), {"-s", "nat", "-a", anchor},
                                          nullptr, commandTimeoutMs, maximumOutputBytes);
    const auto ruleListing = commands_.run(std::string(pfctlPath), {"-s", "rules", "-a", anchor},
                                           nullptr, commandTimeoutMs, maximumOutputBytes);
    if (!commandCompleted(natListing) || !commandCompleted(ruleListing)) {
        fail(error, "anchor_cleanup_verification_failed");
        return false;
    }
    if (!listingVerifiedEmpty(natListing.standardOutput) ||
        !listingVerifiedEmpty(ruleListing.standardOutput)) {
        fail(error, "anchor_cleanup_verification_not_empty");
        return false;
    }
    return true;
}

bool InstalledScopedOperations::releaseTokenVerified(unsigned long long token, std::string *error) {
    const auto released = commands_.run(std::string(pfctlPath), {"-X", std::to_string(token)},
                                        nullptr, commandTimeoutMs, maximumOutputBytes);
    if (!commandCompleted(released)) {
        fail(error, "pf_token_release_failed");
        return false;
    }
    const auto references = commands_.run(std::string(pfctlPath), {"-s", "References"}, nullptr,
                                          commandTimeoutMs, maximumOutputBytes);
    if (!commandCompleted(references)) {
        fail(error, "pf_token_absence_unverified");
        return false;
    }
    const auto state = classifyReferenceTable(references.standardOutput, token);
    if (state == ReferenceState::Active) {
        fail(error, "pf_token_still_active");
        return false;
    }
    if (state == ReferenceState::Unknown) {
        fail(error, "pf_token_absence_unknown");
        return false;
    }
    return true;
}

bool InstalledScopedOperations::sendRestorationFrames() {
    for (const auto &frame : restorationFrames_) {
        if (!frame.empty() && !arp_.sendFrame(frame.data(), frame.size()))
            return false;
    }
    return true;
}

bool InstalledScopedOperations::startRefreshTimer(std::string *error) {
    if (error)
        error->clear();
    if (refreshTimer_)
        return true;
    refreshTimer_ = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue_);
    if (!refreshTimer_)
        return false;
    const uint64_t interval = static_cast<uint64_t>(refreshIntervalMs_) * NSEC_PER_MSEC;
    dispatch_source_set_timer(refreshTimer_, dispatch_time(DISPATCH_TIME_NOW, interval), interval,
                              interval / 4);
    dispatch_source_set_event_handler(refreshTimer_, ^{
      refreshTickOnQueue();
    });
    dispatch_resume(refreshTimer_);
    return true;
}

void InstalledScopedOperations::stopRefreshTimer() {
    if (!refreshTimer_)
        return;
    dispatch_source_cancel(refreshTimer_);
    dispatch_release(refreshTimer_);
    refreshTimer_ = nullptr;
}

} // namespace interceptor
