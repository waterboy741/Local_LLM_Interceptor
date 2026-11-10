# llm_interceptor — Development Plan

Status: Revised October 18, 2026. M0 through M5 are complete under their offline acceptance criteria. M6 live lab validation remains deferred until the lab is available.

## Purpose

Build a standalone, macOS-first desktop application for controlled research on a local network. The application sits between an explicitly selected client and a locally hosted LLM service and provides three functions:

1. Redirect their traffic through the research machine using ARP spoofing.
2. Identify, filter, and display LLM JSON requests while forwarding traffic with minimal disruption.
3. Selectively intercept and modify JSON requests before forwarding them to the LLM.

Use is limited to devices and traffic authorized for the local research experiment. Target selection and session activation are explicit; launching the application must not change network state.

## Starting Point and Working Assumptions

The repository currently contains guidelines, ignore rules, and a license, but no application source, build configuration, or tests. Behaviors described in AGENTS.md are intended conventions, not verified existing capabilities.

- Stack: C++20, Qt 6 Widgets, CMake, Ninja, and Qt Test.
- Initial topology: one client, one local LLM server, and one research machine on the same IPv4 layer-2 network.
- Scope: HTTP traffic only. Initial protocol support is HTTP/1.1 with JSON request bodies; responses may be JSON or streamed newline-delimited JSON (NDJSON).
- Initial API: Ollama native HTTP with session-configured client IPv4, LLM server IPv4, server TCP port, and endpoint paths. Port 11434 is only Ollama's default/example, not a required runtime value. Start synthetic adapter coverage with POST /api/generate; confirm the actual client paths before adapter implementation.
- The client must retain its configured server address in ARP redirection mode. A separately configured explicit proxy mode will support early development and troubleshooting.
- IPv6, HTTP/2, HTTP/3, WebSockets, compressed request bodies, and multipart uploads are outside the initial inspection/editing scope. Define and test how unsupported traffic is forwarded or rejected before live use; never silently corrupt it.
- HTTPS/TLS interception, certificate authorities, and client certificate trust setup are out of scope. Encrypted traffic is never inspected or modified.

These assumptions guide offline implementation. Validate them against the actual lab in M6 before claiming live redirection support.

## User Workflow

1. Select the research interface and enter the client and LLM server addresses, server port, protocol, and API paths.
2. Run preflight checks and review the target pair, forwarding readiness, transport support, and required privileges.
3. Choose **Observe** or **Modify** and start a session. Observe is the default.
4. View a bounded request history with time, client, endpoint, model, method, status, latency, and modification state. Filter by these fields or request text.
5. Open a request to inspect headers, formatted JSON, original raw content, response metadata, and any applied changes.
6. In Modify mode, apply scoped rules or pause selected requests for manual editing and validation.
7. Stop the session, release held requests according to the configured policy, restore network configuration where possible, and display the cleanup result.

## Architecture

Keep packet handling, transport, JSON processing, persistence, and presentation separate.

| Component | Responsibility |
| --- | --- |
| Qt GUI (`src/gui/`) | Session setup, request list, filters, details, JSON editor, diff, and session health |
| Session controller (`src/session/`) | Explicit lifecycle, configuration, startup rollback, shutdown, and component coordination |
| Privileged network helper (`src/network/`) | Narrow operations for capture/injection, selected-pair ARP redirection, forwarding setup, and restoration |
| Transport proxy (`src/proxy/`) | Downstream/upstream connections, HTTP framing, streaming, backpressure, deadlines, and cancellation |
| Request pipeline (`src/interception/`) | Endpoint matching, bounded JSON parsing, Observe/Modify decisions, validation, and edit audit |
| Request history (`src/storage/`) | Bounded in-memory records, optional sanitized exports, retention, and replay metadata |
| Shared models (`src/core/`) | Typed configuration, immutable request events, errors, and metrics |

The GUI should not run with elevated privileges. Define a narrow authenticated local IPC boundary for privileged operations, with validation and session-scoped target restrictions. Document helper installation/signing options in M0. M4 implements the offline command/authorization model and injected orchestration; real IPC transport, signing, installation, and privilege verification belong to M6.

Use mature protocol and JSON libraries where appropriate. Select dependencies after a focused compatibility, maintenance, licensing, and macOS packaging review; do not implement a production HTTP parser from scratch.

### Data Path

```text
Selected client
    -> research machine (explicit proxy initially; ARP redirection later)
        -> selected LLM connection: transport proxy
            -> request match / JSON inspection / optional modification
            -> local LLM server
        -> other redirected traffic: forwarding path

LLM responses -> research machine -> client
Request metadata and bounded body copies -> GUI/history
```

ARP redirection and application interception are separate mechanisms. The implementation must prove how both traffic directions reach the research machine, how selected connections enter the proxy, and how the proxy reaches the original server without loops. Do not attempt JSON changes by rewriting individual TCP packets; terminate and relay selected connections at the transport layer.

## Functional Requirements

### 1. ARP Redirection and Session Recovery

- Restrict each session to an explicitly configured client/server pair on the selected interface.
- Check address/MAC resolution, interface availability, topology assumptions, and forwarding readiness before changing ARP state.
- Establish forwarding and proxy readiness before starting redirection. Handle partial startup with rollback.
- Maintain bidirectional connectivity and prevent the application's own upstream traffic from being intercepted recursively.
- Snapshot only the system settings the application changes and restore them carefully without overwriting unrelated concurrent changes.
- On normal stop, cease redirection, attempt neighbor-state restoration, restore owned system configuration, and report failures.
- Design a helper watchdog for GUI failure. Document that abrupt machine loss and stale neighbor caches can still interrupt connectivity; recovery cannot be guaranteed under every failure.
- Detect interface loss, target disappearance, and privilege failures and surface an actionable session state.

### 2. Observe and Forward

- Identify relevant requests by configured destination, port, method, path, and content type; avoid treating every JSON body as an LLM prompt.
- Retain original request bytes for comparison within configured size limits. Inspection must not rewrite an unmodified JSON body.
- Preserve request/response semantics, authentication forwarding, errors, keep-alive behavior, ordering, and streaming delivery. HTTP framing or hop-by-hop headers may need protocol-correct adjustment by the proxy.
- Stream responses incrementally; do not wait for an entire generated answer before forwarding it.
- Forward nonmatching traffic through the appropriate path without parsing or storing its content.
- Bound request sizes, history, connection counts, parser depth, inspection buffers, and queued GUI events. Define oversized-body behavior explicitly.
- Keep capture/proxy work off the GUI thread. Slow rendering or full history must not stall forwarding.
- Hide credentials in the GUI and exclude them from exports by default. Persistence is opt-in; raw captures can contain sensitive content even when displayed fields are redacted.

“Undisturbed” means preserved application behavior and measured, low added latency. A proxy necessarily changes transport characteristics and adds overhead; it cannot promise zero impact.

### 3. Modify JSON Requests

- Enable editing only for matching, supported JSON requests and only after explicit selection of Modify mode.
- Support manual hold/edit/forward and deterministic scoped rules, such as replacing a prompt field or changing a model parameter.
- Match rules by endpoint and optional model/JSON-field conditions. Define rule ordering and apply each rule once per request.
- Preserve unknown fields and validate JSON syntax plus adapter-specific constraints before forwarding.
- Show an original/modified diff and record the rule or manual action responsible for each edit.
- Recompute framing and content length when necessary. Handle encodings explicitly; do not mutate unsupported signed, compressed, or otherwise unverifiable bodies.
- Give held requests a visible deadline. Configure whether timeout forwards the original request or returns an explicit error; default to forwarding the original for continuity.
- Bound held requests and handle client cancellation. Invalid edits remain blocked from submission while the user can forward the original.
- Do not retry submitted generation requests automatically when delivery is uncertain; retries can duplicate work.

## Milestones and Acceptance Criteria

### M0 — Offline Definition and macOS Feasibility Design

See [HTTP Traffic Redirection: macOS Design Investigation](docs/TRAFFIC_REDIRECTION.md) for the proposed PF-to-local-proxy packet path, return translation, lifecycle constraints, and proof-of-concept test matrix. This is researched design, not completed live validation. See [M0 lab definition and evidence record](docs/M0_LAB.md) for the confirmed Ollama/Wi-Fi scope, supported traffic matrix, PF syntax check, and live checks reserved for M6.

Define the configurable client/server/interface inputs, selected synthetic Ollama API and HTTP/1.1 transport, proposed topology, and synthetic request/response samples. Investigate macOS capture, packet injection, forwarding, transparent proxy integration, privileges, helper lifecycle, and packaging using primary documentation and parse-only checks. Actual lab inventory and disposable network proof belong to M6.

Acceptance:
- A topology diagram and supported traffic matrix exist in `docs/`.
- The first API and transport are selected, with sanitized fixtures. The product design accepts configurable research interface, client IPv4, LLM server IPv4, server TCP port (1–65535), and API paths. Validate usable unicast IPv4 addresses and port range; freeze one immutable snapshot for the active session. Selected values consistently drive preflight, PF matching, upstream connections, and diagnostics; reject mismatches rather than routing from HTTP Host. Actual lab addresses are required for live validation, not for defining this configuration contract.
- A documented design covers both directions of traffic, configured original-destination routing, loop avoidance, startup rollback, cleanup, and unresolved platform questions; it identifies the M6 evidence needed to validate these claims.
- ARP-incompatible networks and unresolved platform limitations are documented. Offline development may proceed; live operation remains unproven until M6.

### M1 — Application Foundation

Create the CMake presets, Qt application shell, configuration models, session state machine, bounded event/history interfaces, and test infrastructure. Add README setup and permissions guidance.

Acceptance:
- Debug build and offscreen lifecycle tests pass; closing the window shuts down workers cleanly.
- Debug, release, and sanitizer presets exist; sanitizer support is checked.
- Starting the GUI performs no network mutation or privileged action.

### M2 — Explicit Proxy and Observe Mode

Build the HTTP relay against a deterministic local mock LLM before adding network redirection. Implement endpoint filtering, JSON inspection, history, details, and streaming response forwarding.

Completed October 9, 2026. The local Observe proxy is explicitly started, forwards to the configured HTTP endpoint, and displays matching JSON requests. Offline tests cover the acceptance cases below, including GUI visibility and shutdown. Production, testing, and independent review each returned COMPLETE after the final changes. Debug, release, and sanitizer suites each passed 3/3 registered tests. The repeatable measurements, provisional targets, and limits are in [docs/M2_BASELINE.md](docs/M2_BASELINE.md). Rich request-list filters and metadata remain in M5; Wi-Fi routing and target-device verification remain in M6.

Acceptance:
- Matching requests appear in the GUI; nonmatching content is not retained.
- Unmodified body bytes and response content match mock-server expectations.
- Tests cover concurrent connections, keep-alive, chunked framing, malformed/truncated messages, disconnects, cancellation, timeouts, and NDJSON streaming.
- A repeatable baseline reports latency, streaming time-to-first-byte, throughput, and memory under stated limits. Agree on numeric performance targets before live testing.

### M3 — Manual and Rule-Based Modification (Offline)

Add request holding, JSON editing, diffs, rule configuration, validation, deadlines, and modification audit records.

Completed October 9, 2026 under the offline acceptance criteria. Production, testing, and independent review each returned COMPLETE. Debug and sanitizer builds passed all 4 registered suites; an M3 release run was not performed. See [docs/M3_MODIFICATION.md](docs/M3_MODIFICATION.md) for behavior and limits and [docs/M3_STATE.md](docs/M3_STATE.md) for the saved milestone state. Live target-device behavior remains deferred to M6.

Acceptance:
- The mock LLM receives exactly the intended modified JSON; unmatched requests remain unchanged.
- Tests cover nested fields, Unicode, missing fields, invalid JSON, oversized bodies, rule ordering, concurrent held requests, deadlines, cancellation, and disconnects.
- Observe mode cannot apply modifications. Switching modes has explicit behavior for already held requests.

### M4 — Network Helper Integration (Offline)

Implement the scoped helper module, offline command/authorization boundary, preflight/session orchestration, PF rule generation, watchdog, rollback, and cleanup reporting behind an injectable system-operation boundary. Develop with synthetic Ethernet frames, fake neighbor/settings/PF state, and parse-only platform checks. Keep live activation opt-in and explicitly unvalidated.

Completed October 12, 2026 under the offline acceptance criteria. Production, testing, and independent review each returned COMPLETE after final fixes. Debug, release, and sanitizer suites each passed 5/5 registered tests; the standard debug preset independently passed 5/5. The generated documentation-address PF sample passed syntax-only validation. See [docs/M4_OFFLINE_HELPER.md](docs/M4_OFFLINE_HELPER.md). A real privileged backend, IPC transport, installation, active anchor verification, and network recovery remain M6 work.

Acceptance:
- Offline tests cover ARP parsing and generation, packet bounds, malformed/truncated frames, unsupported types, interface/target validation, and configurable nondefault ports.
- Generated PF rules and proxy routing derive from one validated session snapshot; tests prove client/interface/server/port scope and loop avoidance by rule construction.
- Mocked startup failures, watchdog expiry, interface loss, conditional setting restoration, PF token ownership, and owned-state cleanup produce correct rollback/status results.
- Available PF syntax-only checks pass without installing rules. Dedicated anchor attachment and privilege/packaging prerequisites are documented for M6.
- Offline dispatch rejects unverified/wrong transport peer credentials, wrong session capability/anchor, mismatched frozen snapshots, and unsupported/malformed commands before system operations. Real authenticated IPC transport and helper installation remain M6.
- Mocked results are labeled as such; active anchors, actual routing, neighbor changes, and recovery are not claimed as verified.

### M5 — Research Usability and Hardening

Add sanitized request export/import, bounded retention settings, session summaries, and reproducible offline replay into the inspection pipeline. Packet recording and CSV export mentioned in repository guidelines are secondary features; implement them after the core interceptor works, with explicit recording controls and bounded storage.

Completed October 18, 2026 under offline acceptance criteria. Production, testing, and independent review each returned COMPLETE after fixes. Socket-enabled debug, release, and sanitizer suites passed 7/7. The 300-request GUI load test and bounded-retention cases ran with synthetic loopback traffic. A local unsigned app package and M6 runbook are prepared; see [M5 inspection behavior](docs/M5_INSPECTION.md) and [package and lab runbook](docs/M5_PACKAGE_AND_LAB.md). No live lab validation or automatic redirection is claimed.

Acceptance:
- Long-running synthetic load stays within configured memory/storage limits and leaves the UI responsive.
- Exports omit credentials by default and round-trip supported research records. Offline replay cannot accidentally send requests to a live server.
- Relevant debug, release, and sanitizer checks pass. Packaging artifacts and the lab runbook are prepared; installation/privilege and device walkthrough verification are deferred to M6.

### M6 — Authorized Lab Validation

The remaining implementation order and live acceptance gates are tracked in [M6 live transparent redirection handoff](docs/M6_LIVE_HANDOFF.md).
For a bounded recording before full M6 completion, see [M6 minimal lab demo plan](docs/M6_MINIMAL_LAB_DEMO.md).

Read-only XPC listener foundation (November 2026): an authenticated adapter now supports only bounded `probe` and `status` replies, and a reusable native XPC service listener validates its configured service name and trusted code requirement. It caps concurrent peers at 16, accepted peers at 256, each peer at 128 messages, and each run at 4096 messages. It is not wired into the helper or GUI. No launchd installation or service configuration, production identity default, GUI/helper rendezvous, capability handoff, or privileged dispatcher is included. This foundation performs no Start, Heartbeat, Stop, PF, or ARP operation and does not satisfy installed-helper acceptance; see [XPC control request gate](docs/m6/XPC_CONTROL_REQUEST_GATE.md).

Perform every verification requiring the test Wi-Fi network or actual client/server assets here, after offline work is ready and lab access is available. Record the actual client/API paths, Ollama version/model, addresses, interface, subnet/L2 behavior, server LAN bind/firewall, OS versions, and applicable network policy.

Acceptance:
- Confirm peer reachability, selected endpoint/protocol, Wi-Fi ARP compatibility, and both-direction MAC/IP delivery using sanitized synthetic traffic first.
- Demonstrate that the dedicated PF anchor is actively evaluated, a fresh SYN reaches the proxy, and expected state/counters and reverse translation exist.
- The client keeps its configured server address; the proxy uses the selected server IP/port, including a nondefault-port test. No recursive upstream connections occur.
- Actual LLM requests are visible and native NDJSON responses stream; representative non-LLM bypass traffic works in both directions. Shorter and longer edited JSON bodies arrive intact and exactly once at the mock server in the real network path before testing edits against Ollama.
- Repeated start/stop, partial startup failure, interface loss, GUI/helper/proxy failure, existing connections, stale neighbors, and cleanup have measured outcomes. Unrelated PF rules/state/references remain intact.
- Helper packaging, installation, authentication, required privileges, watchdog behavior, and a multi-device walkthrough are verified with actual limitations.
- Compare live latency/streaming/throughput against stated targets. Resolve findings and obtain all three COMPLETE votes before claiming live support.

M6 preparation update (October 19, 2026): the opt-in, source-address-bound TCP preflight succeeded against the authorized lab endpoint, one ICMP echo to the client succeeded, both peers had local neighbor entries, and an Ollama version endpoint returned HTTP 200. A synthetic request to the client's OpenAI-compatible chat endpoint returned one completion. Sanitized observations are recorded locally; ignored raw lab artifacts are not committed. A separate read-only PF diagnostics mode is prepared and returned `permission_denied` on the first query without administrator privileges; no PF rules or state were read. No PF, ARP, forwarding, route, or interface settings were changed. These checks do not prove packet egress on the selected interface, Wi-Fi/L2 compatibility, ARP redirection, active PF evaluation, bidirectional delivery, reverse translation, helper lifecycle, device walkthrough, or live support. M6 remains incomplete.

M6 helper groundwork (October 19, 2026; bounded listener added November 7, 2026): a bounded one-request Unix-socket transport verifies kernel peer UID/GID, accepts only Heartbeat/Stop, and obtains time from the trusted monotonic clock owned by `HelperDispatcher`. The local listener requires an absolute fixed-basename path under the same private directory inode supplied by the caller, refuses existing paths, sets socket mode 0600, handles one accepted connection per bounded serve call, and removes only the socket inode it created. Listener creation failure immediately attempts local host cleanup; failed cleanup is reported and remains caller-owned for retry. The listener closes once its host reaches Idle and remains available for Stop retries while cleanup is pending. Its host must outlive it; listener lifecycle calls and destruction are confined to its creating thread. Processes under the same UID remain indistinguishable; this does not verify app identity or signing. This same-process listener is not an installed/surviving helper, has no Start-over-wire operation, and is not connected to application startup or live network mutation.

M6 watchdog scheduling groundwork (October 22, 2026): an offline `HelperWatchdog` owns a Qt timer, follows the helper session's Active state, and invokes a private dispatcher tick using the same injected monotonic clock callback supplied to socket transport. The timer carries no capability or peer data, is owner-thread and reentrancy guarded, and stops after cleanup or dispatcher destruction. It can check without GUI/IPC callbacks only while its host's Qt event loop is running; it is not an installed/surviving helper service, and no live watchdog behavior is claimed.

M6 route/neighbor inspection groundwork (October 22, 2026): an explicit read-only diagnostics mode queries the current OS route and selected-interface neighbor-cache row for the configured client and server using bounded fixed commands. The sanitized result reports interface matches, only explicit direct-route evidence, and whether a neighbor row has a valid MAC; it omits addresses, MACs, gateways, and raw command output. Incomplete or absent neighbor entries are reported as unresolved, and cached entries may be stale. These snapshots do not prove packet egress, layer-2 reachability, ARP acceptance, PF evaluation, or redirection, and the mode does not send traffic or change network state.

M6 scoped PF operation groundwork (October 22, 2026): an offline-only adapter builds fixed `pfctl` plans to load or remove rules in a single validated `llm_interceptor/<session-id>` anchor. Installation requires effective root, a current session lease, PF enabled, fresh active filter/translation attachment references, and lease-bound anchor ownership. Removal requires effective root, the current lease, and exact anchor ownership, while allowing cleanup after PF is disabled or the global attachment disappears. A macOS-only `QProcess` runner now accepts only the typed plans, verifies their exact fixed program/arguments and bounded stdin, enforces a 3-second command deadline and combined drained-output cap, and kills/reaps failed children with up to one additional second for cleanup without retaining or logging raw output. The drained-byte cap detects overflow promptly, but Qt may transiently buffer more internally between drain events; this is not a hard process-memory bound. The runner remains unwired from the GUI, CLI, and session backend; tests use a synthetic child-process boundary and never launch `pfctl`. If a command starts and then fails, times out, exceeds its output cap, or returns nonzero, the result marks it as possibly applied so the caller can retain cleanup ownership. This does not establish active packet evaluation or redirection; concrete authorization, attachment/ownership verification, integration, and recovery remain incomplete.

An authorized read-only run on October 22 recognized both peer routes on the selected interface and found no neighbor-cache entries for either peer. The report was observationally complete, but neither peer was resolved and directness remained unknown; this does not establish current connectivity. Its sanitized evidence remains in ignored local build output.

Remote-device explicit-proxy check (October 19, 2026): the user manually verified that a live request from another device reaches the proxy and upstream LLM after configuring that client to use the research Mac's displayed LAN listener URL. Debug, release, and sanitizer suites passed locally, and the push workflow for `ceb7030` succeeded. This confirms the reported explicit-proxy path only; unchanged-server-address transparent redirection and the remaining M6 acceptance checks are still open.

Read-only interface-facts preflight (October 22, 2026): the selected interface reported an active usable IPv4/prefix and unicast MAC, and both configured peers fell within one selected-interface subnet. A source-address-bound TCP connection to the configured Ollama endpoint timed out on this run, so current endpoint reachability was not established. The sanitized v2 record is retained only in ignored local build evidence. Subnet membership does not prove shared L2, Wi-Fi/ARP delivery, PF evaluation, or transparent redirection.

M6 pre-install PF readiness groundwork (October 25, 2026): an offline read-only probe runs only fixed PF status, main filter-rule, and main translation-rule queries. It requires enabled PF and a uniquely recognized `anchor "llm_interceptor/*"` plus `rdr-anchor "llm_interceptor/*"` reference, stops on the first failed or unrecognized query, and returns sanitized status without raw output or session details. It is not wired into the GUI, CLI, or mutation adapter; tests use a fake runner. These textual references do not prove active packet evaluation, a loaded session anchor, or redirection.

M6 host-lease groundwork (October 25, 2026): an offline move-only `HostSessionLease` opens a fixed lock file relative to a trusted directory descriptor, rejects non-private directories, symlinks, non-regular files, unsafe ownership/modes, and multiply linked lock files, then acquires a nonblocking exclusive `flock`. RAII release closes the descriptor and never unlinks the file. This coordinates cooperating processes only if all instances use the same canonical directory inode; the future privileged helper must supply the same root-owned private directory and prevent descriptor leakage. No token issuance, authorization, recovery, or live backend integration is provided, and no network state is changed.

M6 durable PF-recovery groundwork (October 25, 2026): an offline `PfRecoveryJournal` stores only a validated session ID, its derived owned anchor, and `cleanup_needed` phase. It uses a trusted private directory descriptor, a separate guard lock, strict file ownership/mode/link checks, file fsync, atomic rename, and parent-directory fsync. Any existing pending record, including the same session ID, blocks a new persist because there is no session-generation proof. Callers must persist before any PF command that may apply; uncertain durability blocks proceeding. Clear is an explicit matching-session operation intended only after independently verified cleanup. The journal is not connected to PF execution or GUI/session operations and covers no ARP, forwarding, or PF-reference recovery.

M6 PF recovery orchestration groundwork (October 25, 2026): an offline `PfAnchorRecoveryCoordinator` persists the cleanup obligation before invoking scoped install; install success and failure both retain it. Cleanup requires a matching journal record before calling the existing authorized remove adapter, then requires both successful removal and an injected independent read-only confirmation that the exact session anchor has no rules before attempting journal clear. Any failed or uncertain step retains the obligation. Its `cleanupPending` result is conservative and means cleanup may still be required or state is unknown; missing journal data does not prove the anchor empty. The coordinator is not instantiated by the live helper, GUI, or system operations, and it does not recover PF references, ARP, or forwarding state.

M6 PF anchor backend-composition groundwork (November 7, 2026): `PfAnchorRecoverySystemOperations` decorates an injected `SystemOperations` backend, requires the process host lease before backend calls, binds the delegated session token to the full immutable snapshot and construction thread, and routes anchor install/removal through `PfAnchorRecoveryCoordinator`. The delegated session token is passed unchanged to `PfAnchorOperations`, whose authorization checks effective root, session lease, and exact anchor ownership for both operations; installation additionally requires PF enabled and fresh active attachments, while removal remains available for cleanup if PF or the global attachment is unavailable. The coordinator attempts to persist cleanup obligation before install and preserves an existing obligation on uncertain command/verification outcomes; the decorator retains its delegated token after a failed release and reports cleanup uncertainty. A failed persistence does not guarantee a durable recovery record. This is offline composition only; no production backend or live PF command is wired or executed.

M6 PF enable-reference helper-lifecycle composition (November 7, 2026): when configured with a fresh active `PfEnableReferenceRecoveryCoordinator`, the same lease-gated decorator routes PF enable-reference acquisition and release through its durable ordering coordinator and returns the captured token only after it is journaled. Repeated acquisition is rejected, anchor installation requires the durably captured PF token, PF-reference release requires successful anchor removal plus empty-anchor verification, and delegated session-lease release is blocked while the PF reference remains active or uncertain. An optional distinct startup recovery coordinator reads the prior owner ID from the durable journal and reconciles only a proven absent/released token before the new helper session lease is acquired; missing journal is safe to proceed, while unknown or unresolved records block startup. Startup does not auto-release a `ReleaseNeeded` record because that phase does not prove anchor cleanup; it requires independent anchor recovery before retry. The active and startup coordinators must have distinct owners because restart recovery consumes the recovery owner, and the decorator enforces that both coordinators share the same journal object. The host lease, PF-reference journal, and anchor journal must also use the same canonical private directory inode so all helpers contend on one lock; the decorator does not introspect this invariant. Both remain injected/offline. The path uses only typed `-E`/token-bound `-X` plans, never global PF disable, and no live PF command was run.

M6 transparent relay-listener groundwork (November 7, 2026): `ProxyServer` has an explicit `transparentRedirect` mode that binds only `127.0.0.1`, filters accepted TCP peers to the configured client IPv4, and forwards using the fixed configured server IP/port. It returns non-forgeable `TransparentProxyReadiness` only after successful listener bind; the evidence includes selected interface, actual bound loopback address/port, client allowlist, and fixed upstream IP/port. `SessionSnapshot::create` can consume that evidence and derives the PF redirect port/upstream from it rather than accepting manually asserted proxy-ready facts, while the caller must revalidate that the listener is still active immediately before session activation. This establishes local listener/configuration readiness only; it does not prove upstream reachability, PF evaluation, ARP delivery, or client traffic. No PF/ARP operation was performed.

M6 leased helper-host bootstrap groundwork (November 7, 2026): `LeasedHelperHost` composes the host session lock, secure session/capability generation, a snapshot derived from the same current `TransparentProxyReadiness` token, a factory-created `PfAnchorRecoverySystemOperations`, `HelperDispatcher`, and `HelperWatchdog`. The host validates an already authenticated bootstrap peer from an outer authenticator, explicitly starts through the dispatcher, hands credentials out once only after Active, and routes Heartbeat/Stop through the lease-gated Unix transport. It installs no listener, grants no wire Start command, and does not verify app signing or distinguish same-UID processes. Methods and cleanup are thread-affine; cross-thread destruction is deferred to the owner event loop. No concrete privileged service or live PF/ARP operation was run.

M6 helper process-bootstrap slice (November 8, 2026): `InstalledHelperProcessBootstrap` now composes root-owned private-directory validation, trusted handoff reception, kernel UID/GID extraction from that same connected socket, and `LeasedHelperHost::createFromBootstrap` behind injected authentication and operations factories. The existing helper executable accepts a strict `--process --state-dir PATH --bootstrap-fd FD` form, validates its state directory, then exits fail-closed with `production_peer_authenticator_unavailable` (5); it does not read the fd, start a host, expose a socket, or run PF/ARP. No production code-signature authenticator, gated system backend, GUI/helper rendezvous, or service installer exists. A GUI process cannot traverse the intended `root:wheel` 0700 state directory, so a separate GUI-accessible authenticated rendezvous must be designed before adding the control listener. Synthetic tests cover only injected paths; this does not meet the installed-helper or live authorization gates.

M6 concrete PF-anchor cleanup-verifier groundwork (October 25, 2026): `PfCommandAnchorCleanupVerifier` uses fixed, typed session-filter and session-translation rule queries against the snapshot's exact owned anchor, with a 3-second default (5-second maximum) timeout and 64 KiB output cap per query. It reports empty only if both bounded commands complete successfully with exit code zero and ASCII-whitespace-only output; recognized rule/counter content is nonempty, while malformed output or command uncertainty is unknown. It remains unwired from the coordinator's live path, GUI, and helper service, and no PF command was run by its fake-runner tests. An empty listing is not evidence of packet evaluation or transparent redirection.

M6 helper-identity groundwork (October 25, 2026): an offline `HelperSessionIdentity` factory uses checked Apple Security entropy to produce a 16-byte-random lowercase-hex session ID and a 32-byte raw capability, failing closed without partial results. Its identity is move-only and wipes its owned capability bytes at destruction; dispatcher capability comparisons use equal-length validation followed by `timingsafe_bcmp`. This does not guarantee erasure of later copies and is unwired from helper startup/GUI/live operations. Deterministic entropy injection is private to the focused test fixture.

M6 ARP adapter groundwork (November 5, 2026): `ArpNeighborAdapter` accepts only the snapshot-generated two-frame redirection or restoration plan on the validated interface, checks both frames before sending either, and reports potentially applied partial writes for cleanup. It has only an injected packet writer and is not connected to a privileged helper or GUI. Deterministic tests cover exact pair scope, first/second-frame failure, and full restoration retry. Debug, release, and sanitizer suites each passed 19/19. Read-only lab preflight found the selected interface active, the configured server reachable by a bounded TCP probe, and both peer neighbor entries after the probe. That does not prove the peers will accept an injected ARP update or that restoration will work; no ARP packet was sent.

M6 macOS BPF writer groundwork (November 5, 2026): `MacBpfArpPacketIo` binds a bounded nonblocking BPF device to the snapshot interface, requires Ethernet link type and complete-header mode, and allowlists only the snapshot's four exact ARP frames. Fake-syscall tests cover setup, scope, short/error writes, and descriptor cleanup; debug, release, and sanitizer suites each passed 20/20. The writer has no production call site and tests opened no real BPF device. Effective privilege, live packet delivery, peer-cache acceptance, and verified restoration remain open lab gates.

M6 one-client ARP probe-plan groundwork (November 5, 2026): `ArpLabProbePlan` independently validates the selected/observed interface match, distinct usable same-subnet IPv4 identities (excluding link-local), and distinct unicast MAC identities without relying on PF or proxy readiness. It creates exactly one redirect frame and one corrective frame, both targeted to the client; the corrective frame advertises the configured server MAC while the Ethernet source remains the research MAC. The server MAC is operator-supplied and must be checked against a fresh observation of the client's neighbor mapping for the server IP before use; the client MAC must be checked against lab inventory. OS/AP acceptance must still be proven live. `MacBpfArpPacketIo` can be constructed from this plan and then accepts only those exact two frames; the normal session path retains its four-frame snapshot allowlist. Debug, release, and sanitizer suites each passed 21/21. This is offline plan generation only, not a CLI/live send or proof of peer-cache change/restoration.

M6 open-only BPF readiness groundwork (November 5, 2026): the opt-in `arp_bpf_readiness --interface NAME` executable opens a bounded nonblocking BPF device, binds the named interface, verifies Ethernet link type and complete-header mode, then closes the descriptor. Its CLI has no send call or packet writer construction; output is sanitized stage status with no interface name, IP, MAC, or raw system error. Strict argument handling rejects missing/duplicate/unknown options before any BPF call, and fake-syscall tests verify setup, close, and zero writes. An unprivileged live attempt on `en0` returned `device_open_failed` and `traffic_sent:false`.

M6 privileged BPF readiness observation (November 5, 2026): the user ran `sudo ./build/debug/arp_bpf_readiness --interface en0` on the research Mac and reported `status: ready` with device-open, interface-bind, Ethernet-link, header-complete, and close-confirmed flags all true, plus `traffic_sent: false`. This verifies privileged BPF setup on `en0` for the current machine and OS session. It does not demonstrate packet delivery, peer ARP-cache acceptance, restoration, forwarding, or transparent HTTP interception.

M6 one-client ARP probe CLI groundwork (November 5, 2026): `arp_lab_probe` requires explicit interface, research/client/server IPv4 and MAC identities, subnet prefix, a bounded 1–5000 ms duration, and an explicit one-client confirmation flag. Before opening BPF, it verifies the selected interface is up/running and matches the supplied research IPv4/prefix/MAC, then validates the same-subnet plan. Client/server MAC inputs are operator-supplied; verify the client MAC against lab inventory and the server MAC against a fresh observation of the client's neighbor mapping for the server IP. It sends exactly one client-targeted redirect frame and, after timeout or SIGINT/SIGTERM, one exact corrective frame; a failed/uncertain redirect write triggers immediate correction. Signal-triggered correction is best-effort and interrupted runs return exit code 130; SIGKILL, process crash, power loss, or failed correction cannot run/complete recovery. It performs no refresh or PF/forwarding/session integration. Output reports local write acceptance and cleanup uncertainty, never peer-cache change as proven. Fake-backed runner/CLI checks do not perform network writes; the later one-client live write observation is recorded below.

M6 one-client live write observation (November 5, 2026): the user ran the privileged one-second probe and reported `redirect_write_attempted: true`, `redirect_write_accepted: true`, `corrective_write_attempted: true`, `corrective_write_accepted: true`, `descriptor_close_confirmed: true`, `interrupted: false`, and `peer_cache_change_verified: false`, with status `corrective_frame_write_accepted_after_timeout`. This establishes local BPF write acceptance and descriptor cleanup for that run. The user subsequently confirmed that the client ARP entry changed after the probe, establishing client acceptance of a redirect update. The user subsequently checked the Ubuntu Linux client after the probe and confirmed its entry returned to the original server MAC. This verifies the observed final mapping for that run; the exact transition timing and which mechanism restored it were not independently captured. CI passed for commit `a83cf10` ([run 42149093558](https://github.com/waterboy741/Local_LLM_Interceptor/actions/runs/42149093558)).

M6 read-only PF pre-install readiness CLI groundwork (November 6, 2026): `pf_readiness` wraps the existing bounded, read-only PF status and main anchor-reference checks. It emits sanitized JSON and distinguishes PF enablement/reference readiness from actual packet evaluation; it does not query a configured session anchor, mutate PF, or verify proxy readiness or routing. Its timeout is bounded, argument failures make no query, and non-macOS invocation fails closed before accessing `/sbin/pfctl`. This adds a reusable operator check only; it does not activate interception.

M6 PF status format observation (November 6, 2026): the user ran `sudo pf_readiness` and reported the status line `Status: Disabled … Debug: Urgent`. The parser now accepts an optional `Debug:` suffix only for PF's recognized `none`, `urgent`, `misc`, and `loud` levels, using horizontal whitespace and preserving strict single-status-line and UTF-8 checks. This records PF as disabled for that observation, so pre-install readiness remains false; no PF setting was changed by the application.

M6 read-only PF pre-install rerun (November 6, 2026): the user reported `pf_known: true`, `pf_enabled: false`, `status: pf_disabled`, and only the status query completed. The filter/translation references remain unknown because the diagnostic intentionally stops at disabled PF. No enable, load, or other PF change was performed.

M6 dedicated PF attachment preparation (November 6, 2026): `pf_attachment_prepare` prints the exact two-reference candidate at `docs/m6/llm_interceptor_attachment.pf` only after a syntax-only `pfctl -n -f -` check on macOS. The fragment orders `rdr-anchor` before `anchor` for parser section order; its integration guidance places them separately in translation and filter sections, preserving stock rules and `com.apple/*` anchors. The command does not enable/load PF or write files; syntax acceptance does not prove correct placement or active evaluation.

M6 supplied PF configuration merge preparation (November 6, 2026): `pf_attachment_merge` accepts at most 1 MiB of supplied config on stdin, inserts only the `llm_interceptor/*` translation/filter references before the unique stock `com.apple/*` markers, syntax-checks with `pfctl -n -f -`, and emits a full review candidate to stdout only on success. It rejects missing/duplicate/reversed markers, mixed line endings, active continuations, and any active existing `llm_interceptor` namespace text. Original bytes outside the two insertions are preserved. The CLI does not write `/etc/pf.conf`, load/enable PF, or change host configuration.

M6 offline PF enable-reference owner (November 6, 2026): `PfEnableReferenceOwner` uses an injected runner and exposes only typed `pfctl -E` acquisition and `pfctl -X <captured-token>` release plans. It parses one nonzero decimal `Token : n` result from bounded output, marks state before runner calls to prevent reentrant duplicate operations, and retains uncertain tokens/acquisition state for recovery. Release is attempted at most once; no `pfctl -d`, native runner, CLI, or live PF invocation is implemented. Tests use injected runner responses only.

M6 durable PF enable-reference recovery journal (November 7, 2026): `PfEnableReferenceJournal` provides durable phase records for pre-acquire obligation, uncertain acquisition, captured token, and release-pending state using a trusted private directory fd and injected atomic-file operations. It can clear a matching token-bearing release record after an injected verifier reports that exact token absent. Unknown-token records remain blocking and cannot be cleared through this API. The journal is offline and only used by injected code; no PF operation or host setting was changed.

M6 lease-gated helper transport groundwork (November 7, 2026): `dispatchOneLeasedUnixSocketCommand` composes the existing host-wide lease with the bounded Unix command transport authenticated by kernel peer credentials. It rejects a missing/released lease before reading the socket and requires dispatch on the `HelperDispatcher` owner thread. The caller must retain and not concurrently release the lease through synchronous dispatch; coordination applies only when helpers use the same canonical private directory inode. Same-UID processes remain indistinguishable, and the seam does not bind a lease to a particular dispatcher or provide the installed helper lifecycle. It remains offline and unwired; no live helper or network operation was performed.

M6 PF enable-reference ordering coordinator (November 7, 2026): `PfEnableReferenceRecoveryCoordinator` composes the owner, journal, and injected verifier. Its same-process path persists acquire-pending before owner acquire, captures the token durably before reporting readiness, and persists release-pending before owner release. It clears only with the owner-issued successful release receipt plus verified token absence. A proven no-start acquire uses a dedicated receipt to clear only the untouched acquire-pending record. Durability-uncertain writes block PF operations, including retries of a visible release-pending record. Restart recovery is described in the following entry; all runner and verifier operations remain injected and unwired.

M6 typed native PF enable-reference runner (November 7, 2026): `QProcessPfEnableReferenceCommandRunner` implements the injected runner with a macOS-only factory and fixed `/sbin/pfctl -E` / `-X <canonical decimal token>` argument allowlist, a 3-second deadline, a 4096-byte combined drained-output cap plus overflow sentinel, permission classification, and kill/reap reporting. The cap bounds bytes consumed by the runner, not transient Qt internal buffering. It has no application call site; tests use a fake child-process factory, and no live PF command was run.

M6 offline PF enable-reference restart recovery (November 7, 2026): the injected `recoverRelease` path reconciles token-bearing `release_needed` and `release_pending` records using a supplied token-state verifier. Verified absence clears the exact matching journal record. Only `release_needed` plus verified active state may durably transition to `release_pending`, freshly recheck active state, adopt the token, and issue one typed `-X`; `release_pending` plus active or unknown state retains for manual recovery and issues no command because a prior child may still run. Unknown token/state and uncertain writes remain blocking. The verifier and runner are injected, the recovery path has no application call site, and no PF command was run.

M6 read-only lab route/neighbor observation (November 7, 2026): the user ran the privileged route/neighbor diagnostics on `en0` for the selected client and Ollama server. All four queries completed; both routes were recognized on the selected interface, and both neighbor entries were resolved on that interface. The report was complete but did not establish direct-route status, packet egress, layer-2 delivery, or current redirection. No network setting was changed.

The CLI was also run against this Mac's current on-disk `/etc/pf.conf`, with its candidate redirected to a temporary review file. It reported `syntax_validated`; the candidate contained exactly one dedicated translation reference and one dedicated filter reference, adding only their 58 bytes. The temporary files were removed. This validates the merger's proposed before-marker placement against the current file's syntax only; it does not activate PF or prove coexistence with dynamic rules.

M6 local PF merge syntax observation (November 6, 2026): a temporary copy of this Mac's `/etc/pf.conf` was made under `/private/tmp` with only the dedicated `rdr-anchor` inserted after the stock translation reference and the dedicated filter `anchor` inserted after the stock filter reference. `/sbin/pfctl -n -f` accepted that temporary complete candidate with exit code zero. The active ruleset and `/etc/pf.conf` were not changed. This checks syntax and placement against the current on-disk file only; it does not establish coexistence with dynamic rules, active evaluation, or safe enablement.

M6 active PF anchor observation (November 6, 2026): the user ran read-only privileged main filter and translation rule listings. They showed the stock `com.apple/*` scrub/filter and nat/rdr anchor references, with no `llm_interceptor/*` reference. The commands also printed the usual ALTQ unavailable notice. This is consistent with the earlier `pf_disabled` readiness result and confirms the dedicated attachment is absent from the observed active main rules. No PF setting or rule was changed.

PF journal slice validation: its focused test passed in debug, release, and sanitizer builds. Full local debug CTest runs were interrupted by macOS sleep on battery, producing timing failures in older M2/M5/Unix-socket tests; the previously failing M5 and Unix-socket tests passed when rerun in isolation while awake. GitHub Actions subsequently passed debug, release, and sanitizer for commit `a73cdb7` ([run 40242824300](https://github.com/waterboy741/Local_LLM_Inteceptor/actions/runs/40242824300)). No filesystem-sync failure injection or live PF test was performed.

PF recovery coordinator slice validation: focused `m6_pf_anchor_recovery_coordinator_tests` passed in separate debug, release, and sanitizer builds. No full preset/CI validation or PF command execution was performed for this coordinator increment.

PF anchor cleanup-verifier slice validation: focused `m6_pf_anchor_cleanup_verifier_tests` passed in separate debug, release, and sanitizer builds. No full preset/CI validation, PF command execution, or live-system verification was performed.

Helper identity slice validation: the focused `m4_network`, Unix-socket transport, and helper-identity CTests passed 3/3 in separate debug, release, and sanitizer builds. The identity test uses injected deterministic entropy and never calls the system entropy provider. No live helper identity generation or capability use was performed.

M6 availability does not gate completion of M0–M5. Live checks are separate opt-in work and must never be inferred from offline test success.

## Validation and Milestone Review

Prefer deterministic tests under `tests/` and small synthetic/sanitized data under `tests/fixtures/`. Keep live capture/redirection tests opt-in and separate from normal CTest runs.

For implementation milestones, follow AGENTS.md: assign production/build/docs, tests, and independent review to separate GPT-6.1 Sol agents using Light effort, with separate build directories. Review ownership, packet bounds, thread safety, cleanup, and milestone acceptance criteria. Require all three COMPLETE votes after findings are resolved and affected tests are rerun. This initial planning document does not claim those implementation votes.

Standard checks once build configuration exists:

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug --output-on-failure
git diff --check
```

Record actual results and coverage gaps for each milestone. Mocked restoration tests do not replace live recovery verification.

## Decisions and When to Resolve Them

1. Which LLM server and client applications will be used first, and which API paths do they call?
2. Do the selected client and server use HTTP/1.1, and which native Ollama endpoints does the client call? Preserve native NDJSON streaming; SSE is only a future generic transport option.
3. Are all three machines on the same IPv4 layer-2 segment, and does the network permit peer traffic and ARP changes?
4. Which macOS version and CPU architecture must the application support?
5. Which JSON fields and transformations are needed for the first experiment?
6. What request sizes, concurrency, hold deadlines, and retention limits match the workload?

Resolve product defaults, limits, and supported build targets during offline milestones. Actual client paths, network policy, target addresses, and device behavior are lab inputs for M6 and do not block configurable implementation.

Recommended development order: M0 → M1 → M2 → M3 → M4 → M5 → M6 (when lab access is available).

M6 installed-helper state-directory preflight slice (November 7, 2026): `llm_interceptor_helper --check-state-dir` is a separate root-required executable that opens and validates the canonical private state directory through one close-on-exec descriptor. This is a read-only bootstrap check. It does not install or launch a persistent helper process, create a control socket, hand off a GUI capability, recover journals, or run Start/Heartbeat/Stop. The section A installed-helper gate remains open; see `docs/m6/INSTALLED_HELPER_BOOTSTRAP.md`.

M6 cross-process listener probe slice (November 7, 2026): the GUI-owned transparent listener now offers a fixed local challenge path with a random 32-byte secret; a separate bounded verifier checks a fresh nonce HMAC bound to the exact interface/client/upstream/listener tuple. It is offline groundwork only. The authenticated GUI-to-helper secret/tuple handoff, immutable helper snapshot binding, service call site, and immediate pre-PF recheck are still unwired, so this probe alone does not authorize PF installation.

M6 trusted bootstrap handoff groundwork (November 7, 2026): a bounded one-shot Unix-stream protocol transports a full validated snapshot and 32-byte transparent probe secret after bilateral injected peer authentication, using a fresh helper challenge. It rejects malformed/truncated/oversized frames and returns a move-only secret holder. It has no production code-signature authenticator or GUI/helper callsite. The secret remains in wipeable binary fields outside JSON, but this remains offline protocol plumbing and does not satisfy the installed-helper trust gate; see `docs/m6/TRUSTED_BOOTSTRAP_HANDOFF.md`.

M6 helper-side bootstrap adoption groundwork (November 8, 2026): `LeasedHelperHost::createFromBootstrap` consumes an authenticated handoff, acquires the host lease, supplies the transferred immutable snapshot and probe secret to an injected operations factory, then wipes its local probe-secret copy. It independently mints the host command capability and composes the dispatcher/watchdog; tests exercise Start, Heartbeat, and Stop with synthetic operations. The caller must bind `VerifiedPeer` to the same authenticated GUI socket peer, and any factory-retained secret copy must be wiped. This API cannot recheck the GUI-owned proxy listener and does not itself run the pre-mutation gate. It does not start a helper process, install a listener, provide a production authenticator/backend, or authorize live PF/ARP operations; installed-helper acceptance remains open. See `docs/m6/INSTALLED_HELPER_BOOTSTRAP.md` and `docs/m6/TRUSTED_BOOTSTRAP_HANDOFF.md`.

M6 helper-side pre-mutation gate groundwork (November 7, 2026): a read-only `HelperPreMutationGate` compares the handed-off snapshot against current interface MAC/IP/prefix, direct client/server routes and neighbor resolution, exact neighbor MACs, upstream TCP reachability, enabled PF plus active filter/translation attachments, and the exact listener challenge last. Failed or unknown observations block readiness. The exact neighbor adapter, production helper callsite, code-signature authentication, and immediate pre-PF integration remain unwired; see `docs/m6/HELPER_PRE_MUTATION_GATE.md`.

M6 exact neighbor-MAC observation groundwork (November 7, 2026): `MacNeighborIdentityVerifier` uses the existing typed bounded macOS `arp -i IF -n IP` runner and a strict one-line parser to return only an exact IP/interface, resolved unicast MAC observation. It supplies the previously injected neighbor adapter for the helper-side pre-mutation gate. This is read-only local cache evidence, not remote identity proof or live helper wiring; see `docs/m6/EXACT_NEIGHBOR_VERIFIER.md`.

M6 pre-mutation production adapter composition (November 7, 2026): `systemHelperPreMutationDependencies()` now supplies the existing read-only interface, route/neighbor, PF, exact neighbor MAC, and listener-probe adapters to a bundle overload of `HelperPreMutationGate::verify`. It does not grant root/anchor ownership or wire helper startup/mutation; the fully injected overload remains for offline tests.


M6 LAN transparent listener correction and manual trial (November 8, 2026): after inbound PF redirection to loopback failed in the lab, Transparent lab demo now binds only a usable IPv4 owned by the selected research interface. The exact configured client remains the only application-traffic source; local self-source connections can access only the authenticated readiness challenge. Current readiness rechecks IP ownership, snapshots require the same research/listener IP, and PF rules and HMAC probes bind to that LAN address. A manually staged Ubuntu neighbor override plus PF redirect to the Mac LAN listener returned HTTP 200 for `/api/version` with the original Ollama URL unchanged while the Mac's global `net.link.generic.system.hwcksum_rx` was temporarily `0`. A subsequent Ubuntu OpenCode `/v1/chat/completions` request to the unchanged Ollama URL received a successful response and appeared in the GUI Requests pane. After deleting the temporary neighbor entry, direct `/api/version` access recovered. The client neighbor and checksum setting were restored and owned PF rules were cleared. The user then loaded `build/demo-pf-original.conf` with `sudo pfctl -f` and released the trial's PF enable token with `sudo pfctl -X`; the reported output confirmed PF `Status: Disabled` and `No pf starter references held`. One established Mac-to-upstream PF state had been observed earlier; its disappearance was not separately verified. This is bounded manual lab evidence; operation with the default checksum setting, automatic ARP/PF activation, installed-helper trust/lifecycle, and automated crash recovery remain open. The application does not change checksum settings; see `docs/M6_LIVE_DEMO_RUNBOOK.md` for repeat-trial and rollback requirements.

M6 launchd Mach/XPC identity and request-gate groundwork (November 8, 2026): `MacXpcPeerCodeSignaturePolicy` validates an incoming XPC dictionary message against an explicit code requirement using Security.framework's audit-token-bound `SecCodeCreateWithXPCMessage` API. The injectable `XpcControlRequestGate` pins a copy of the locally configured requirement, authenticates each message before parsing, and accepts only a one-key `probe` or `status` request into a typed enum. It rejects additional fields and unsupported/malformed operations. At this gate-only checkpoint there was no serialized reply or service listener; the subsequent [read-only XPC listener foundation](#m6--authorized-lab-validation) adds bounded probe/status replies and an uninstalled listener shell. Launchd installation, GUI/helper rendezvous, and privileged dispatch remain absent; the CLI still fails closed, and no PF/ARP authority is granted. The requirement must be selected from trusted local configuration, never supplied by the message or GUI; see [the request-gate contract](docs/m6/XPC_CONTROL_REQUEST_GATE.md) and `docs/m6/INSTALLED_HELPER_BOOTSTRAP.md`.

M6 fail-closed launchd Mach-service bootstrap (November 9, 2026): `llm_interceptor_helper --mach-service --state-dir PATH` now opens the trusted configuration relative to the already validated root-owned `0700` state directory. The `mach-service.conf` file must be root-owned, regular, and exactly `0600`; its strict two-line config must explicitly enable the listener and provide a bounded Security.framework-compilable peer code requirement. The fixed service name is `org.local-llm-interceptor.helper`; neither the GUI nor an XPC message selects the name or peer requirement. The helper wires this requirement through `XpcControlRequestGate` and `XpcReadOnlyServiceListener`, whose only operations remain bounded read-only probe/status. The mode fails closed on absent, disabled, malformed, unsafe, or unusable config. A fixed LaunchDaemon plist is now present as a review artifact, with a validator and non-installing staging script; no installer, Developer ID identity default, GUI rendezvous, capability handoff, host startup, PF, or ARP operation was added. The script neither signs nor installs, bootstraps, or enables the service. An administrator must review and provision the signed GUI client's identity before any launchd binding; the sample config stays disabled and no current build is authenticated for production use. This slice does not satisfy the installed-helper gate; see [the helper bootstrap contract](docs/m6/INSTALLED_HELPER_BOOTSTRAP.md).
