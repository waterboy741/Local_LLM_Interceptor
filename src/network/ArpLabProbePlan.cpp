#include "ArpLabProbePlan.hpp"

#include "ArpCodec.hpp"

#include <QAbstractSocket>
#include <QHostAddress>
#include <QRegularExpression>

namespace interceptor {
namespace {
bool parseUsableIpv4(const QString &text, quint32 &value) {
    QHostAddress address;
    if (!address.setAddress(text) || address.protocol() != QAbstractSocket::IPv4Protocol ||
        address.isLoopback() || address.isMulticast() || address.toString() != text)
        return false;
    value = address.toIPv4Address();
    const quint32 firstOctet = value >> 24;
    const bool linkLocal = (value & 0xffff0000U) == 0xa9fe0000U;
    return firstOctet > 0 && firstOctet < 224 && !linkLocal;
}

bool parseUnicastMac(const QString &text, QByteArray &value) {
    static const QRegularExpression pattern("^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$");
    if (!pattern.match(text).hasMatch())
        return false;
    value = QByteArray::fromHex(text.toLatin1());
    return value.size() == 6 && value != QByteArray(6, char(0)) &&
           (static_cast<unsigned char>(value[0]) & 1) == 0;
}

bool validInterface(const QString &name) {
    static const QRegularExpression pattern("^[A-Za-z][A-Za-z0-9_.:-]{0,63}$");
    return pattern.match(name).hasMatch();
}
} // namespace

std::optional<ArpLabProbePlan> ArpLabProbePlan::create(const ArpLabProbeInputs &inputs,
                                                       QString *error) {
    const auto fail = [error](const QString &message) -> std::optional<ArpLabProbePlan> {
        if (error)
            *error = message;
        return std::nullopt;
    };
    if (error)
        error->clear();

    if (!validInterface(inputs.selectedInterfaceName) ||
        inputs.selectedInterfaceName != inputs.observedInterfaceName)
        return fail("Selected interface does not exactly match the observed interface");
    if (inputs.prefixLength < 1 || inputs.prefixLength > 30)
        return fail("Probe subnet prefix must be between /1 and /30");

    quint32 researchIp = 0, clientIp = 0, serverIp = 0;
    if (!parseUsableIpv4(inputs.researchIp, researchIp) ||
        !parseUsableIpv4(inputs.clientIp, clientIp) ||
        !parseUsableIpv4(inputs.serverIp, serverIp) || researchIp == clientIp ||
        researchIp == serverIp || clientIp == serverIp)
        return fail(
            "Research, client, and server require distinct usable canonical IPv4 addresses");

    const quint32 mask = 0xffffffffU << (32 - inputs.prefixLength);
    const quint32 network = researchIp & mask;
    const quint32 broadcast = network | ~mask;
    for (const quint32 address : {researchIp, clientIp, serverIp}) {
        if ((address & mask) != network || address == network || address == broadcast)
            return fail("Research, client, and server must be usable hosts on the same subnet");
    }

    QByteArray researchMac, clientMac, serverMac;
    if (!parseUnicastMac(inputs.researchMac, researchMac) ||
        !parseUnicastMac(inputs.clientMac, clientMac) ||
        !parseUnicastMac(inputs.serverMac, serverMac) || researchMac == clientMac ||
        researchMac == serverMac || clientMac == serverMac)
        return fail("Research, client, and server require distinct nonzero unicast MAC addresses");

    const QByteArray redirection = ArpCodec::encode(
        {researchMac, clientMac, researchMac, clientMac, inputs.serverIp, inputs.clientIp, 2});
    const QByteArray restoration = ArpCodec::encode(
        {researchMac, clientMac, serverMac, clientMac, inputs.serverIp, inputs.clientIp, 2});
    if (redirection.size() != 60 || restoration.size() != 60)
        return fail("Could not encode the targeted Ethernet/IPv4 ARP probe frames");

    return ArpLabProbePlan(inputs.selectedInterfaceName, redirection, restoration);
}

} // namespace interceptor
