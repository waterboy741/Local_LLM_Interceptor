#define __STDC_WANT_LIB_EXT1__ 1
#include "TrustedBootstrapHandoff.hpp"

#include <QElapsedTimer>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include <Security/SecRandom.h>
#include <cerrno>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace interceptor {
namespace {
constexpr int deadlineMs = 3000;
constexpr int maximumFrame = 4096;

void wipe(QByteArray &bytes) noexcept {
    if (!bytes.isEmpty())
        (void)memset_s(bytes.data(), static_cast<rsize_t>(bytes.size()), 0,
                       static_cast<rsize_t>(bytes.size()));
    bytes.clear();
}

bool fail(QString *error, const char *reason) {
    if (error)
        *error = QString::fromLatin1(reason);
    return false;
}

bool socketAndPeerValid(int fd) {
    int type = 0;
    socklen_t typeLength = sizeof(type);
    sockaddr_storage peer{};
    socklen_t peerLength = sizeof(peer);
    int noSigPipe = 1;
    return fd >= 0 && ::getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &typeLength) == 0 &&
           type == SOCK_STREAM &&
           ::getpeername(fd, reinterpret_cast<sockaddr *>(&peer), &peerLength) == 0 &&
           peer.ss_family == AF_UNIX &&
           ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, sizeof(noSigPipe)) == 0;
}

bool transfer(int fd, char *data, size_t size, bool sending, QElapsedTimer &elapsed) {
    size_t done = 0;
    while (done < size) {
        const int remaining = deadlineMs - static_cast<int>(elapsed.elapsed());
        if (remaining <= 0)
            return false;
        pollfd waitFor{fd, static_cast<short>(sending ? POLLOUT : POLLIN), 0};
        const int pollResult = ::poll(&waitFor, 1, remaining);
        if (pollResult < 0 && errno == EINTR)
            continue;
        if (pollResult <= 0 || (waitFor.revents & (POLLERR | POLLNVAL)) != 0 ||
            (waitFor.revents & (sending ? POLLOUT : POLLIN)) == 0)
            return false;
        const ssize_t count = sending ? ::send(fd, data + done, size - done, MSG_DONTWAIT)
                                      : ::recv(fd, data + done, size - done, MSG_DONTWAIT);
        if (count < 0 && (errno == EAGAIN || errno == EINTR))
            continue;
        if (count <= 0)
            return false;
        done += static_cast<size_t>(count);
    }
    return true;
}

QJsonObject snapshotObject(const SessionSnapshot &snapshot) {
    const auto &config = snapshot.config();
    const auto &facts = snapshot.facts();
    QJsonArray paths;
    for (const auto &path : config.apiPaths)
        paths.append(path);
    return {{"version", 1},
            {"sessionId", snapshot.sessionId()},
            {"proxyPort", snapshot.proxyPort()},
            {"config", QJsonObject{{"interfaceName", config.interfaceName},
                                   {"clientIp", config.clientIp},
                                   {"serverIp", config.serverIp},
                                   {"serverPort", config.serverPort},
                                   {"apiPaths", paths},
                                   {"explicitProxy", config.explicitProxy}}},
            {"facts", QJsonObject{{"interfaceName", facts.interfaceName},
                                  {"researchIp", facts.researchIp},
                                  {"researchMac", facts.researchMac},
                                  {"clientMac", facts.clientMac},
                                  {"serverMac", facts.serverMac},
                                  {"proxyServerIp", facts.proxyServerIp},
                                  {"proxyServerPort", facts.proxyServerPort},
                                  {"proxyListenPort", facts.proxyListenPort},
                                  {"prefixLength", facts.prefixLength},
                                  {"interfaceUp", facts.interfaceUp},
                                  {"sameLink", facts.sameLink},
                                  {"anchorAttached", facts.anchorAttached},
                                  {"proxyReady", facts.proxyReady},
                                  {"authorized", facts.authorized}}}};
}

std::optional<SessionSnapshot> parseSnapshot(const QJsonObject &root) {
    if (root.value("version").toInt(-1) != 1 || !root.value("config").isObject() ||
        !root.value("facts").isObject())
        return std::nullopt;
    const auto configJson = root.value("config").toObject();
    const auto factsJson = root.value("facts").toObject();
    if (!configJson.value("apiPaths").isArray() || !configJson.value("explicitProxy").isBool())
        return std::nullopt;
    SessionConfig config;
    config.interfaceName = configJson.value("interfaceName").toString();
    config.clientIp = configJson.value("clientIp").toString();
    config.serverIp = configJson.value("serverIp").toString();
    config.serverPort = configJson.value("serverPort").toInt(-1);
    config.explicitProxy = configJson.value("explicitProxy").toBool();
    config.apiPaths.clear();
    const auto paths = configJson.value("apiPaths").toArray();
    if (paths.size() > 16)
        return std::nullopt;
    for (const auto &path : paths) {
        if (!path.isString())
            return std::nullopt;
        config.apiPaths.append(path.toString());
    }
    NetworkFacts facts;
    facts.interfaceName = factsJson.value("interfaceName").toString();
    facts.researchIp = factsJson.value("researchIp").toString();
    facts.researchMac = factsJson.value("researchMac").toString();
    facts.clientMac = factsJson.value("clientMac").toString();
    facts.serverMac = factsJson.value("serverMac").toString();
    facts.proxyServerIp = factsJson.value("proxyServerIp").toString();
    facts.proxyServerPort = factsJson.value("proxyServerPort").toInt(-1);
    facts.proxyListenPort = factsJson.value("proxyListenPort").toInt(-1);
    facts.prefixLength = factsJson.value("prefixLength").toInt(-1);
    for (const char *name :
         {"interfaceUp", "sameLink", "anchorAttached", "proxyReady", "authorized"})
        if (!factsJson.value(QLatin1String(name)).isBool())
            return std::nullopt;
    facts.interfaceUp = factsJson.value("interfaceUp").toBool();
    facts.sameLink = factsJson.value("sameLink").toBool();
    facts.anchorAttached = factsJson.value("anchorAttached").toBool();
    facts.proxyReady = factsJson.value("proxyReady").toBool();
    facts.authorized = factsJson.value("authorized").toBool();
    return SessionSnapshot::create(config, facts, root.value("proxyPort").toInt(-1),
                                   root.value("sessionId").toString());
}

bool authorized(int fd, BootstrapPeerAuthenticator &authenticator,
                const QByteArray &expectedIdentity, QString *error) {
    if (!socketAndPeerValid(fd) || expectedIdentity.isEmpty() || expectedIdentity.size() > 256)
        return fail(error, "bootstrap_socket_or_identity_invalid");
    try {
        if (authenticator.authenticate(fd, expectedIdentity))
            return true;
    } catch (...) {
    }
    return fail(error, "bootstrap_peer_not_authenticated");
}
} // namespace

TrustedBootstrapHandoff::TrustedBootstrapHandoff(TrustedBootstrapHandoff &&other) noexcept
    : snapshot_(std::move(other.snapshot_)), probeSecret_(std::move(other.probeSecret_)) {}

TrustedBootstrapHandoff::~TrustedBootstrapHandoff() { wipe(probeSecret_); }

QByteArray TrustedBootstrapHandoff::takeProbeSecret() noexcept {
    QByteArray result = std::move(probeSecret_);
    probeSecret_.clear();
    return result;
}

bool writeBootstrapHandoff(int fd, BootstrapPeerAuthenticator &authenticator,
                           const QByteArray &expectedHelperCodeIdentity,
                           const SessionSnapshot &snapshot, const QByteArray &probeSecret,
                           QString *error) {
    if (error)
        error->clear();
    if (!authorized(fd, authenticator, expectedHelperCodeIdentity, error))
        return false;
    if (probeSecret.size() != 32)
        return fail(error, "bootstrap_secret_invalid");
    const auto &paths = snapshot.config().apiPaths;
    if (paths.isEmpty() || paths.size() > 16)
        return fail(error, "bootstrap_paths_invalid");
    qsizetype totalPathBytes = 0;
    for (const auto &path : paths) {
        if (path.size() < 1 || path.size() > 256)
            return fail(error, "bootstrap_paths_invalid");
        const qsizetype bytes = path.toUtf8().size();
        if (bytes > 256)
            return fail(error, "bootstrap_paths_invalid");
        totalPathBytes += bytes;
        if (totalPathBytes > 2048)
            return fail(error, "bootstrap_paths_invalid");
    }
    QElapsedTimer elapsed;
    elapsed.start();
    QByteArray challenge(32, Qt::Uninitialized);
    if (!transfer(fd, challenge.data(), 32, false, elapsed)) {
        wipe(challenge);
        return fail(error, "bootstrap_challenge_read_failed");
    }
    const QByteArray snapshotJson =
        QJsonDocument(snapshotObject(snapshot)).toJson(QJsonDocument::Compact);
    QByteArray payload;
    payload.reserve(64 + snapshotJson.size());
    payload.append(challenge);
    payload.append(probeSecret);
    payload.append(snapshotJson);
    wipe(challenge);
    if (payload.isEmpty() || payload.size() > maximumFrame) {
        wipe(payload);
        return fail(error, "bootstrap_payload_invalid");
    }
    char prefix[2] = {static_cast<char>((payload.size() >> 8) & 0xff),
                      static_cast<char>(payload.size() & 0xff)};
    const bool sent =
        transfer(fd, prefix, sizeof(prefix), true, elapsed) &&
        transfer(fd, payload.data(), static_cast<size_t>(payload.size()), true, elapsed);
    wipe(payload);
    return sent ? true : fail(error, "bootstrap_payload_write_failed");
}

std::optional<TrustedBootstrapHandoff>
receiveTrustedBootstrapHandoff(int fd, BootstrapPeerAuthenticator &authenticator,
                               const QByteArray &expectedGuiCodeIdentity, QString *error) {
    if (error)
        error->clear();
    if (!authorized(fd, authenticator, expectedGuiCodeIdentity, error))
        return std::nullopt;
    QElapsedTimer elapsed;
    elapsed.start();
    QByteArray challenge(32, Qt::Uninitialized);
    if (SecRandomCopyBytes(kSecRandomDefault, 32, challenge.data()) != errSecSuccess) {
        wipe(challenge);
        fail(error, "bootstrap_nonce_unavailable");
        return std::nullopt;
    }
    if (!transfer(fd, challenge.data(), 32, true, elapsed)) {
        wipe(challenge);
        fail(error, "bootstrap_challenge_write_failed");
        return std::nullopt;
    }
    char prefix[2]{};
    if (!transfer(fd, prefix, sizeof(prefix), false, elapsed)) {
        wipe(challenge);
        fail(error, "bootstrap_length_read_failed");
        return std::nullopt;
    }
    const int length =
        (static_cast<unsigned char>(prefix[0]) << 8) | static_cast<unsigned char>(prefix[1]);
    if (length < 65 || length > maximumFrame) {
        wipe(challenge);
        fail(error, "bootstrap_length_invalid");
        return std::nullopt;
    }
    QByteArray payload(length, Qt::Uninitialized);
    if (!transfer(fd, payload.data(), static_cast<size_t>(length), false, elapsed)) {
        wipe(challenge);
        wipe(payload);
        fail(error, "bootstrap_payload_read_failed");
        return std::nullopt;
    }
    const bool challengeMatches =
        timingsafe_bcmp(payload.constData(), challenge.constData(), 32) == 0;
    QByteArray secret(payload.constData() + 32, 32);
    const auto document = QJsonDocument::fromJson(payload.mid(64));
    wipe(payload);
    wipe(challenge);
    if (!document.isObject()) {
        wipe(secret);
        fail(error, "bootstrap_payload_invalid");
        return std::nullopt;
    }
    const auto root = document.object();
    auto snapshot = challengeMatches ? parseSnapshot(root) : std::nullopt;
    if (!snapshot) {
        wipe(secret);
        fail(error, "bootstrap_payload_not_trusted");
        return std::nullopt;
    }
    return TrustedBootstrapHandoff(*snapshot, std::move(secret));
}

} // namespace interceptor
