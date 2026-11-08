#include "MacNeighborIdentityVerifier.hpp"

#include <QHostAddress>
#include <QRegularExpression>

namespace interceptor {
namespace {
bool validInput(const QString &interfaceName, const QString &ipv4) {
    static const QRegularExpression interfacePattern("^[A-Za-z][A-Za-z0-9_.:-]{0,63}$");
    static const QRegularExpression ipv4Pattern(
        "^(?:0|[1-9][0-9]{0,2})(?:\\.(?:0|[1-9][0-9]{0,2})){3}$");
    QHostAddress address;
    const bool validAddress = address.setAddress(ipv4);
    const auto numeric = validAddress ? address.toIPv4Address() : 0U;
    const auto firstOctet = numeric >> 24;
    return interfacePattern.match(interfaceName).hasMatch() && ipv4Pattern.match(ipv4).hasMatch() &&
           validAddress && address.protocol() == QAbstractSocket::IPv4Protocol &&
           !address.isNull() && !address.isLoopback() && !address.isMulticast() &&
           address != QHostAddress::Broadcast && firstOctet >= 1 && firstOctet <= 223 &&
           (numeric & 0xffff0000U) != 0xa9fe0000U && address.toString() == ipv4;
}

std::optional<QString> canonicalMac(const QString &text) {
    const auto octets = text.split(':');
    if (octets.size() != 6)
        return std::nullopt;
    QStringList normalized;
    normalized.reserve(6);
    unsigned first = 0;
    bool anyNonzero = false;
    for (int i = 0; i < octets.size(); ++i) {
        const auto &part = octets.at(i);
        static const QRegularExpression octetPattern("^[0-9A-Fa-f]{1,2}$");
        if (!octetPattern.match(part).hasMatch())
            return std::nullopt;
        bool valid = false;
        const unsigned value = part.toUInt(&valid, 16);
        if (!valid || value > 255)
            return std::nullopt;
        if (i == 0)
            first = value;
        anyNonzero = anyNonzero || value != 0;
        normalized.append(QStringLiteral("%1").arg(value, 2, 16, QLatin1Char('0')));
    }
    if ((first & 1U) != 0 || !anyNonzero)
        return std::nullopt;
    return normalized.join(':');
}
} // namespace

std::optional<ObservedNeighborIdentity>
MacNeighborIdentityVerifier::observe(const QString &interfaceName, const QString &ipv4) {
    if (!validInput(interfaceName, ipv4))
        return std::nullopt;
    const auto output = runner_.query(NetworkQuery::ClientNeighbor, interfaceName, ipv4, timeoutMs,
                                      maximumOutputBytes);
    if (output.status != NetworkCommandStatus::Completed || output.exitCode != 0 ||
        !output.standardError.isEmpty() || output.standardOutput.isEmpty() ||
        output.standardOutput.size() > maximumOutputBytes)
        return std::nullopt;
    QByteArray line = output.standardOutput;
    if (line.endsWith('\n'))
        line.chop(1);
    if (line.endsWith('\r'))
        line.chop(1);
    if (line.isEmpty() || line.size() > 512)
        return std::nullopt;
    for (const char character : line)
        if (character < 0x20 || character > 0x7e)
            return std::nullopt;
    static const QRegularExpression linePattern(
        R"(^(?:\S+\s+)?\(([0-9.]+)\)\s+at\s+([0-9A-Fa-f:]+)\s+on\s+([A-Za-z][A-Za-z0-9_.:-]{0,63})(?:\s+ifscope\s+\[ethernet\])?$)");
    const auto match = linePattern.match(QString::fromLatin1(line));
    if (!match.hasMatch() || match.captured(1) != ipv4 || match.captured(3) != interfaceName)
        return std::nullopt;
    const auto mac = canonicalMac(match.captured(2));
    if (!mac)
        return std::nullopt;
    return ObservedNeighborIdentity{interfaceName, ipv4, *mac, true};
}

MacNeighborIdentityVerifier &systemMacNeighborIdentityVerifier() {
    static MacNeighborIdentityVerifier verifier(systemNetworkCommandRunner());
    return verifier;
}

} // namespace interceptor
