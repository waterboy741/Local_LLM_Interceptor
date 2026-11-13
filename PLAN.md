# llm_interceptor — Development Plan

M0–M5 met their offline acceptance criteria. Explicit HTTP proxying was verified from a second device. One manually staged transparent trial succeeded under a temporary checksum setting. M6 remains open for automated activation, installed-helper verification, and recovery.

## Purpose and scope

Build a macOS-first research application that uses scoped ARP redirection to observe, forward, and optionally edit authorized local LLM traffic. Target selection and activation are explicit. Launching the application must leave network state unchanged.

- Stack uses C++20, Qt 6 Widgets, CMake, Ninja, and Qt Test.
- The intended topology puts one client, one Ollama server, and the research Mac on the same IPv4 layer-2 segment.
- Support HTTP/1.1 JSON requests and JSON or streamed NDJSON responses. Configure the client/server IPv4, server port, and API paths. Synthetic coverage starts with `POST /api/generate`; the observed OpenCode path is `/v1/chat/completions`. Port 11434 is an example default.
- Transparent mode preserves the client’s server URL. Explicit proxy mode uses a client-configured listener URL.
- Define and test forwarding or rejection for IPv6, HTTP/2, HTTP/3, WebSockets, compressed requests, and multipart uploads. TLS inspection, modification, and trust configuration are out of scope.

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

Run the GUI unprivileged. Authenticate and validate the helper’s local IPC, scoped to the active session targets. Review compatibility, maintenance, licensing, and macOS packaging for mature HTTP and JSON dependencies.

The relay terminates selected client connections, inspects or edits HTTP, and connects to the configured upstream. Response delivery must preserve the server identity in transparent mode. Prove both traffic directions, proxy delivery, loop avoidance, and bypass in M6.

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

Measure added latency and verify application behavior against the direct path.

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

Define the configurable topology and synthetic HTTP samples. Review macOS capture, injection, forwarding, transparent proxying, and helper privileges, lifecycle, signing, and packaging. See the [redirection design](docs/TRAFFIC_REDIRECTION.md) and [M0 lab definition and evidence](docs/M0_LAB.md).

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

Completed October 9, 2026. All three roles voted COMPLETE. Debug, release, and sanitizer each passed 3/3. See [the baseline and provisional targets](docs/M2_BASELINE.md).

Acceptance:
- Matching requests appear in the GUI; nonmatching content is not retained.
- Unmodified body bytes and response content match mock-server expectations.
- Tests cover concurrent connections, keep-alive, chunked framing, malformed/truncated messages, disconnects, cancellation, timeouts, and NDJSON streaming.
- A repeatable baseline reports latency, streaming time-to-first-byte, throughput, and memory under stated limits. Agree on numeric performance targets before live testing.

### M3 — Manual and Rule-Based Modification (Offline)

Add request holding, JSON editing, diffs, rule configuration, validation, deadlines, and modification audit records.

Completed October 9, 2026. All three roles voted COMPLETE. Debug and sanitizer passed 4/4. Release was untested for this milestone. See [behavior and limits](docs/M3_MODIFICATION.md) and [milestone state](docs/M3_STATE.md).

Acceptance:
- The mock LLM receives exactly the intended modified JSON; unmatched requests remain unchanged.
- Tests cover nested fields, Unicode, missing fields, invalid JSON, oversized bodies, rule ordering, concurrent held requests, deadlines, cancellation, and disconnects.
- Observe mode cannot apply modifications. Switching modes has explicit behavior for already held requests.

### M4 — Network Helper Integration (Offline)

Implement the scoped helper module, offline command/authorization boundary, preflight/session orchestration, PF rule generation, watchdog, rollback, and cleanup reporting behind an injectable system-operation boundary. Develop with synthetic Ethernet frames, fake neighbor/settings/PF state, and parse-only platform checks. Keep live activation opt-in and explicitly unvalidated.

Completed October 12, 2026. All three roles voted COMPLETE. Debug, release, and sanitizer each passed 5/5, including an independent standard debug run. The documentation-address PF sample passed syntax-only validation. See [the offline helper contract](docs/M4_OFFLINE_HELPER.md).

Acceptance:
- Offline tests cover ARP parsing and generation, packet bounds, malformed/truncated frames, unsupported types, interface/target validation, and configurable nondefault ports.
- Generated PF rules and proxy routing derive from one validated session snapshot; tests prove client/interface/server/port scope and loop avoidance by rule construction.
- Mocked startup failures, watchdog expiry, interface loss, conditional setting restoration, PF token ownership, and owned-state cleanup produce correct rollback/status results.
- Available PF syntax-only checks pass without installing rules. Dedicated anchor attachment and privilege/packaging prerequisites are documented for M6.
- Offline dispatch rejects unverified/wrong transport peer credentials, wrong session capability/anchor, mismatched frozen snapshots, and unsupported/malformed commands before system operations. Real authenticated IPC transport and helper installation remain M6.
- Mocked results are labeled as such; active anchors, actual routing, neighbor changes, and recovery are not claimed as verified.

### M5 — Research Usability and Hardening

Add sanitized request export/import, bounded retention settings, session summaries, and reproducible offline replay into the inspection pipeline. Packet recording and CSV export mentioned in repository guidelines are secondary features; implement them after the core interceptor works, with explicit recording controls and bounded storage.

Completed October 18, 2026. All three roles voted COMPLETE. Socket-enabled debug, release, and sanitizer each passed 7/7, including a 300-request synthetic GUI load test and bounded retention. See [inspection behavior](docs/M5_INSPECTION.md) and [unsigned packaging and lab preparation](docs/M5_PACKAGE_AND_LAB.md).

Acceptance:
- Long-running synthetic load stays within configured memory/storage limits and leaves the UI responsive.
- Exports omit credentials by default and round-trip supported research records. Offline replay cannot accidentally send requests to a live server.
- Relevant debug, release, and sanitizer checks pass. Packaging artifacts and the lab runbook are prepared; installation/privilege and device walkthrough verification are deferred to M6.

### M6 — Authorized Lab Validation

Use the [live handoff](docs/M6_LIVE_HANDOFF.md) for implementation order and the [completion plan](docs/PROJECT_COMPLETION_PLAN.md) for lab prerequisites. The [historical minimal demo plan](docs/M6_MINIMAL_LAB_DEMO.md) records the bounded manual trial; its former GUI controls have been removed.

Record current OS, interface, addressing, subnet/L2 and network policy, client/API paths, and Ollama version/model, LAN bind, and firewall.

Acceptance:
- Confirm peer reachability, selected endpoint/protocol, Wi-Fi ARP compatibility, and both-direction MAC/IP delivery using sanitized synthetic traffic first.
- Demonstrate that the dedicated PF anchor is actively evaluated, a fresh SYN reaches the proxy, and expected state/counters and reverse translation exist.
- The client keeps its configured server address; the proxy uses the selected server IP/port, including a nondefault-port test. No recursive upstream connections occur.
- Actual LLM requests are visible and native NDJSON responses stream; representative non-LLM bypass traffic works in both directions. Shorter and longer edited JSON bodies arrive intact and exactly once at the mock server in the real network path before testing edits against Ollama.
- Repeated start/stop, partial startup failure, interface loss, GUI/helper/proxy failure, existing connections, stale neighbors, and cleanup have measured outcomes. Unrelated PF rules/state/references remain intact.
- Helper packaging, installation, authentication, required privileges, watchdog behavior, and a multi-device walkthrough are verified with actual limitations.
- Compare live latency/streaming/throughput against stated targets. Resolve findings and obtain all three COMPLETE votes before claiming live support.

#### Live evidence through November 8, 2026

| Date | Result | Limit |
| --- | --- | --- |
| October 19 | Source-bound TCP, a client ICMP echo, both local neighbor rows, HTTP 200 from the Ollama version endpoint, and one synthetic chat completion succeeded. PF diagnostics returned `permission_denied` without admin privileges. A second device reached Ollama through the displayed explicit proxy URL. Debug, release, sanitizer, and the push workflow for `ceb7030` passed. | Explicit proxy verification required a client URL change. No network settings changed during the read-only checks. |
| October 22 | Both peer routes matched the selected interface and subnet. Both neighbor entries were absent, direct-route status was unknown, and source-bound server TCP timed out. | Reachability was unresolved on this run. |
| November 5 | Source-bound TCP reached the server and both peer neighbor rows appeared on `en0`. Unprivileged BPF open failed. The administrator open-only probe verified device open, interface bind, Ethernet type, complete-header mode, and descriptor close with zero writes. | Neighbor rows may be stale. The open-only run verified BPF setup. |
| November 5 | The privileged one-second ARP probe reported accepted redirect and corrective writes, descriptor close, and no interruption. The user observed the Ubuntu client’s neighbor mapping change and return to the original server MAC. [CI passed for `a83cf10`.](https://github.com/waterboy741/Local_LLM_Inteceptor/actions/runs/42149093558) | The CLI reported `peer_cache_change_verified: false`. Exact transition timing and the restoration mechanism were not independently captured. Continuous refresh and crash recovery remain open. |
| November 6–7 | PF readiness reported `pf_disabled` and stopped after the status query. Separate privileged listings showed stock references only. Two syntax-only candidates passed for the current on-disk configuration. The merge tool’s before-marker candidate added exactly two references (58 bytes). All four privileged route/neighbor queries on November 7 matched `en0`, with both neighbor rows resolved and direct-route status unproven. | Syntax and cache evidence leave active evaluation, attachment coexistence, and packet egress unproven. |
| November 8 | Loopback redirection failed. A manual Ubuntu neighbor override and PF redirect to the Mac’s LAN listener succeeded with `net.link.generic.system.hwcksum_rx=0`. The unchanged Ollama URL returned HTTP 200 for `/api/version` and a successful OpenCode chat response visible in the GUI. After neighbor deletion, direct HTTP recovered. The user restored the neighbor and checksum setting, cleared owned rules, reloaded the saved PF configuration, and released the trial token. PF reported disabled with no starter references. | One established upstream PF state was not separately checked for disappearance. Default checksum behavior, automatic ARP/PF activation, installed-helper trust and lifecycle, and automated crash recovery remain open. The app does not change the checksum setting. [Trial and rollback runbook.](docs/M6_LIVE_DEMO_RUNBOOK.md) |

#### Implemented M6 groundwork through November 9, 2026

- **Relay and readiness.** The transparent listener binds the selected interface’s usable LAN IPv4 and accepts application traffic only from the configured client. Local self-source connections can access only the challenge. The frozen snapshot binds the interface, research/listener IPv4 and port, client, and fixed upstream. Its HMAC challenge uses a fresh nonce and 32-byte secret. The helper pre-mutation gate checks current interface identity, direct routes, exact resolved neighbor MACs, upstream TCP, enabled PF and attachments, then listener readiness. Read-only adapters are composed. Authenticated handoff and immediate pre-PF integration remain open. [Listener probe](docs/m6/TRANSPARENT_PROBE.md), [pre-mutation gate](docs/m6/HELPER_PRE_MUTATION_GATE.md), [neighbor verifier](docs/m6/EXACT_NEIGHBOR_VERIFIER.md).
- **Host and recovery.** The helper host combines an exclusive lease, snapshot, dispatcher, and owner-thread watchdog. Lease and both journals require one canonical private directory inode. The one-request Unix listener uses kernel UID/GID, a private `0600` socket, bounded Heartbeat/Stop, and inode-owned cleanup. It keeps Stop available while cleanup is pending. The watchdog uses the trusted monotonic clock and needs a running helper event loop. Session identities use 16 random bytes for the ID and a 32-byte capability with timing-safe comparison and owned-secret wiping. Same-UID clients are indistinguishable on the Unix socket. The one-shot authenticated bootstrap seam transfers the frozen snapshot and wipeable probe secret and issues the host capability only after Active. Its production authentication, rendezvous, and privileged backend remain open. [Bootstrap and state-directory contract](docs/m6/INSTALLED_HELPER_BOOTSTRAP.md), [handoff protocol](docs/m6/TRUSTED_BOOTSTRAP_HANDOFF.md).
- **PF anchors and references.** Typed bounded runners scope operations to one owned `llm_interceptor/<session-id>` anchor. Install requires root, a lease, ownership, enabled PF, and current filter/translation references. Removal remains available if PF or attachment disappears. The anchor coordinator journals before mutation and clears only after authorized removal and an independent empty listing for both rule types. The reference coordinator journals before `-E`, persists the exact captured token before anchor install, and permits token-bound `-X` only after verified anchor cleanup. Uncertain commands or persistence retain recovery obligations. Restart may clear a verified absent token. Active `release_pending`, unknown tokens, and uncertain writes block or require manual recovery. Active `release_needed` requires independent anchor cleanup before a verified, journaled release retry. Global disable and unrelated PF state changes are forbidden. Production authorization, wiring, and recovery for ARP and forwarding remain open.
- **Lab operators and ARP.** `pf_readiness` performs bounded status and reference checks. `pf_attachment_prepare` and `pf_attachment_merge` emit syntax-checked review candidates; the merger preserves supplied bytes outside the two insertions. The offline ARP adapter validates both snapshot frames before writing and reports partial writes as potentially applied. The BPF writer restricts writes to the exact snapshot allowlist. The separate client-only lab probe verifies the selected interface and requires freshly checked peer identities, explicit confirmation, and a 1–5000 ms interval. It sends one redirect and one correction on timeout or recoverable interruption, with immediate correction after a failed or uncertain redirect. SIGKILL, crash, power loss, and failed correction can prevent recovery.
- **Mach/XPC.** `--check-state-dir` checks the root-owned private directory. `--process --state-dir PATH --bootstrap-fd FD` still exits with `production_peer_authenticator_unavailable` (5). The opt-in `--mach-service --state-dir PATH` reads a root-owned `0600` config from the validated `0700` directory. It requires explicit enablement and a locally selected, compilable code requirement. The fixed service `org.local-llm-interceptor.helper` uses Security.framework’s message audit identity to authenticate before parsing. The bounded listener and client support only fixed `probe` and `status` requests and replies. The GUI can request read-only status. The staging artifact does not install the service, and the sample config stays disabled. Signed identity provisioning, service installation, capability handoff, and privileged dispatch remain open. [Helper bootstrap contract](docs/m6/INSTALLED_HELPER_BOOTSTRAP.md), [XPC request and reply contract](docs/m6/XPC_CONTROL_REQUEST_GATE.md).

#### Recorded offline validation

- The PF journal focused test passed debug, release, and sanitizer. Local full debug had timing failures during macOS sleep in M2, M5, and Unix transport tests. M5 and Unix transport passed isolated reruns while awake. Full CI passed for [`a73cdb7`](https://github.com/waterboy741/Local_LLM_Inteceptor/actions/runs/40242824300). Filesystem-sync failure injection and live PF were outside this test.
- The PF anchor coordinator and cleanup verifier each passed their focused debug, release, and sanitizer tests. Those increments did not run full presets, CI, or live PF.
- Focused M4 network, Unix transport, and helper identity tests passed 3/3 in debug, release, and sanitizer with injected entropy. System entropy and live capability use were outside this test.
- The ARP adapter, BPF writer, and one-client plan increments passed 19/19, 20/20, and 21/21 respectively in debug, release, and sanitizer. Fake-backed tests cover pair/interface/frame scope, partial writes, restoration retry, and descriptor cleanup.
- Anonymous XPC endpoint tests cover native round trips, malformed replies, and deadline expiry. They do not validate an installed, signed service.

## Validation and milestone review

Use deterministic tests and synthetic or sanitized fixtures. Run opt-in live tests separately from normal CTest. Follow [AGENTS.md](AGENTS.md) for agent assignments, separate build directories, review, three COMPLETE votes, commit, push, and verification. Review ownership, packet bounds, thread safety, cleanup, and acceptance criteria. Record actual test results and gaps.

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug --output-on-failure
git diff --check
```
