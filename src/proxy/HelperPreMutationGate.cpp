#include "HelperPreMutationGate.hpp"
#include "MacNeighborIdentityVerifier.hpp"

namespace interceptor {
namespace {
HelperPreMutationResult reject(const char *reason) { return {false, QString::fromLatin1(reason)}; }

bool exactNeighbor(NeighborIdentityVerifier &verifier, const QString &interfaceName,
                   const QString &ipv4, const QString &expectedMac) {
    const auto observed = verifier.observe(interfaceName, ipv4);
    return observed && observed->resolved && observed->interfaceName == interfaceName &&
           observed->ipv4 == ipv4 && observed->mac.compare(expectedMac, Qt::CaseInsensitive) == 0;
}
} // namespace

bool SystemTransparentListenerVerifier::verify(const TransparentProxyProbeTarget &target,
                                               const QByteArray &secret, int timeoutMs) {
    return verifyTransparentProxyProbe(target, secret, timeoutMs);
}

HelperPreMutationDependencies systemHelperPreMutationDependencies() {
    static SystemTransparentListenerVerifier listener;
    return {systemLabProbe(), systemNetworkCommandRunner(), systemPfCommandRunner(),
            systemMacNeighborIdentityVerifier(), listener};
}

HelperPreMutationResult HelperPreMutationGate::verify(const SessionSnapshot &snapshot,
                                                      const QByteArray &probeSecret,
                                                      HelperPreMutationDependencies dependencies) {
    return verify(snapshot, probeSecret, dependencies.labProbe, dependencies.networkRunner,
                  dependencies.pfRunner, dependencies.neighbors, dependencies.listener);
}

HelperPreMutationResult
HelperPreMutationGate::verify(const SessionSnapshot &snapshot, const QByteArray &probeSecret,
                              LabProbe &labProbe, NetworkCommandRunner &networkRunner,
                              PfCommandRunner &pfRunner, NeighborIdentityVerifier &neighbors,
                              TransparentListenerVerifier &listener) {
    try {
        const auto &config = snapshot.config();
        const auto &facts = snapshot.facts();
        if (probeSecret.size() != 32 ||
            !SessionSnapshot::create(config, facts, snapshot.proxyPort(), snapshot.sessionId()))
            return reject("snapshot_or_probe_secret_invalid");

        const auto interfaceFacts = labProbe.interfaceFacts(config.interfaceName);
        if (!interfaceFacts.found || !interfaceFacts.up ||
            interfaceFacts.macAddress.compare(facts.researchMac, Qt::CaseInsensitive) != 0)
            return reject("research_interface_identity_mismatch");
        bool addressMatches = false;
        for (const auto &address : interfaceFacts.ipv4Addresses)
            if (address.ipv4 == facts.researchIp && address.prefixLength == facts.prefixLength)
                addressMatches = true;
        if (!addressMatches)
            return reject("research_interface_address_mismatch");

        const auto routes = RouteNeighborDiagnostics::collect(config, networkRunner);
        if (!routes.complete || !routes.client.routeRecognized ||
            !routes.client.routeInterfaceMatches || !routes.client.routeDirectKnown ||
            !routes.client.routeDirect || !routes.server.routeRecognized ||
            !routes.server.routeInterfaceMatches || !routes.server.routeDirectKnown ||
            !routes.server.routeDirect || !routes.client.neighborRecognized ||
            !routes.client.neighborResolved || !routes.client.neighborInterfaceMatches ||
            !routes.server.neighborRecognized || !routes.server.neighborResolved ||
            !routes.server.neighborInterfaceMatches)
            return reject("route_or_neighbor_not_verified");

        if (!exactNeighbor(neighbors, config.interfaceName, config.clientIp, facts.clientMac) ||
            !exactNeighbor(neighbors, config.interfaceName, config.serverIp, facts.serverMac))
            return reject("neighbor_identity_mismatch");

        if (labProbe.connectTcp(config.interfaceName, facts.researchIp, config.serverIp,
                                config.serverPort,
                                LabPreflight::defaultTimeoutMs) != TcpProbeResult::Reachable)
            return reject("upstream_not_reachable");

        if (!PfDiagnostics::collectPreInstallReadiness(pfRunner).ready)
            return reject("pf_attachment_not_ready");

        const TransparentProxyProbeTarget target{config.interfaceName, config.clientIp,
                                                 config.serverIp,      config.serverPort,
                                                 snapshot.proxyPort(), facts.researchIp};
        if (!listener.verify(target, probeSecret, 1000))
            return reject("transparent_listener_not_verified");
        return {true, QStringLiteral("ready")};
    } catch (...) {
        return reject("revalidation_exception");
    }
}

} // namespace interceptor
