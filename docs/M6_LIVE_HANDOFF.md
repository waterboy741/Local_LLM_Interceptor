# M6 live transparent redirection handoff

This is the work queue for the next implementation and lab sessions. The application is **not** yet an installed privileged helper. A bounded manual end-to-end transparent request has been demonstrated; automated activation and recovery remain incomplete. Keep the existing explicit proxy usable while developing M6. The authorized lab topology last reported was research Mac `en0`, Ubuntu/OpenCode client `192.168.1.169`, and Ollama `192.168.1.141:11434` using `/v1/chat/completions`; recheck addresses before every live run.

**November 8 evidence:** manual client-neighbor override, scoped PF LAN redirection, and temporary `net.link.generic.system.hwcksum_rx=0` delivered an unchanged-URL OpenCode request visible in the GUI and a successful response to the client. Neighbor/checksum restoration, owned-rule cleanup, restored PF configuration, and disabled/no-reference PF status were reported. Disappearance of one earlier upstream PF state was not separately verified. Default-checksum operation, continuous ARP, installed-helper lifecycle, and automatic recovery remain unverified. See [the historical runbook](M6_LIVE_DEMO_RUNBOOK.md) for commands and full evidence; its former GUI controls are no longer present.

## Existing building blocks

- `ProxyServer` has a selected-interface LAN-bound transparent mode with an exact client allowlist. Its live readiness evidence feeds `SessionSnapshot` and must be rechecked immediately before activation.
- `LeasedHelperHost` composes a host lease, session identity, snapshot, recovery operations, dispatcher, and watchdog. `LeasedUnixHelperCommandListener` serves bounded Heartbeat/Stop requests on a private socket; Start is an in-process operation. Neither is an installed service or connected to the GUI startup path.
- `PfAnchorRecoverySystemOperations` and `PfEnableReferenceRecoveryCoordinator` enforce ordered, journaled PF anchor and exact-token reference operations through injected adapters. Startup blocks unresolved `release_needed` references until the corresponding anchor is independently cleaned. The typed native runners exist, but production authorization, attachment verification, and live wiring are incomplete.
- `ArpLabProbeRunner`/`MacBpfArpPacketIo` support a bounded one-client redirect/correction probe. This is not continuous, crash-safe ARP redirection.
- `pf_attachment_merge`, `pf_attachment_prepare`, `pf_readiness`, `lab_preflight`, and route/neighbor diagnostics prepare or observe lab state. A syntax-valid candidate is not an installed or active PF attachment.

## A. Installable privileged host

1. Choose an explicit, reviewable installation/launch mechanism for the lab Mac. A Developer ID Network Extension is unavailable in this project; the path must use a narrowly scoped privileged helper. Document the exact executable, owner/mode, private state directory, socket location, launch and uninstall steps. Do not make the GUI itself root.
2. Supply one trusted root-owned private directory descriptor to the host lease and both PF journals. Require the same canonical directory inode, one helper instance, and a running owner-thread event loop for watchdog and listener. Define how the GUI securely receives the one-time session capability; kernel UID/GID alone does not distinguish same-UID processes or prove app identity.
3. Wire the host factory to the concrete PF runners and read-only verifiers. Verify effective root, exact anchor ownership, enabled PF and both live attachment references before install. Preserve unknown/uncertain journal state for explicit recovery. No global `pfctl -d`; release only the captured `-E` token.
4. Add a helper process integration test with fake PF/BPF backends: Start, Heartbeat, Stop, lost GUI, helper interruption, restart with each journal phase, and failure at each mutation boundary. The host must not claim ready until the relay is listening and the PF reference/rules are durably owned. A failing cleanup must remain visible and retryable.

**Gate:** an installed test helper starts and stops with synthetic backends, survives GUI loss, and can be removed without altering unrelated PF state. This gate does not send lab traffic.

## B. Transparent traffic and ARP session

1. Prepare and review the dedicated `llm_interceptor/*` filter and translation references in the full PF configuration. Make a backup and rollback procedure before any write or reload. Confirm the active main rules contain exactly the expected references; syntax-only validation is insufficient.
2. Generate a single-client/single-server/single-port PF `rdr` to the **actual** transparent listener port on the research interface IPv4. Keep source, destination, protocol, interface, and owned anchor narrow. Confirm packet evaluation and return translation with an explicit lab probe before enabling ARP redirection. A Mac-local connection does not exercise the inbound `en0` path.
3. Implement a continuous, bounded ARP session that refreshes only the client mapping for the server IP while active, records exact original identities, and sends the corrective frame on Stop and all recoverable failures. Pair it with PF/relay ordering so traffic is never intentionally redirected to an absent listener. A process crash or power loss cannot guarantee corrective ARP; document and test the recovery procedure.
4. Integrate startup/stop order in one state machine: listener ready → lease and recovery clear → PF reference → owned PF rules → ARP redirect; on Stop cease ARP/restore mapping → remove owned rules and verify empty → release exact PF token → release host lease. Failed steps retain cleanup obligations and must not report success.

**Gate:** a one-client request to the unchanged Ollama address is observed by the proxy and Ollama, with an unmodified response and no unrelated traffic captured. Stop restores the client neighbor mapping and removes only owned PF state.

## C. Staged lab acceptance

Use a fresh observation of `en0`, client/server addresses and MACs, direct-route/neighbor state, Ollama reachability, and PF status. Record sanitized results only; do not commit prompts, credentials, packet captures, or machine-specific configuration.

1. Read-only preflight and backup: interface, neighbor, upstream HTTP, current PF references/rules, existing PF enable-reference state. Abort on mismatch or unknown ownership.
2. PF-only trial: activate dedicated attachments and one owned anchor without ARP; verify active evaluation, exact redirect destination, then remove and verify empty. Confirm unrelated PF rules and references remain intact.
3. One-client bounded ARP trial: observe the client's server-IP neighbor entry switch to the research Mac and return to the original server MAC after correction. The earlier one-frame probe proved a temporary switch on Ubuntu, not continuous session behavior.
4. End-to-end HTTP trial: OpenCode on the Ubuntu client sends `/v1/chat/completions` to the unchanged Ollama address; verify one request in GUI, upstream delivery, response body/stream completion, and no 502/504. Compare before/after behavior and test a second request.
5. Failure matrix: Stop, helper termination, GUI exit, relay loss, interface loss, timeout, uncertain PF command, failed correction, restart with pending journals, and repeated start/stop. Record cleanup outcome and manual recovery instructions for every unresolved state.

**Final acceptance:** live request and response succeed without client configuration changes, exact client-only capture/modification is visible, correction and PF cleanup are verified, unrelated traffic/PF state are unchanged, and failure recovery results are recorded. Until these observations exist, report the feature as unverified.

## Next narrow implementation slice

Start with the **installed helper process using synthetic backends** (section A), then wire concrete read-only PF verification. Keep the production, tests, and independent review roles separate per `AGENTS.md`, require three COMPLETE votes, run debug/release/sanitizer checks, and commit/push each accepted slice. Do not start live PF or ARP mutation merely because offline tests pass.
