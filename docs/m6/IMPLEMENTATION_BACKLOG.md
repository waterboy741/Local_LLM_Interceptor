# M6 implementation backlog

This is the execution queue for the remaining transparent-mode work. It complements the [live handoff](../M6_LIVE_HANDOFF.md) and [completion plan](../PROJECT_COMPLETION_PLAN.md). M0–M5 and the explicit HTTP proxy are usable. The November 8 manual lab trial proved one unchanged-URL OpenCode request and response under a temporary checksum setting. It did not prove automated activation, installed-helper operation, or recovery. Do not mark a work package complete from a synthetic test alone.

## Critical path and ownership

| Package | Dependency | Reviewable output | Exit gate |
| --- | --- | --- | --- |
| A. Trusted GUI/helper boundary | Signed app and disabled identity proposal | Installation/rendezvous design and authenticated control contract | A test GUI can reach an installed **read-only** helper; an unsigned or wrong build cannot |
| B. Helper lifecycle with synthetic operations | A | One process owns the lease, watchdog, state directory, journals, and command endpoint | Start/Stop, loss of GUI, restart, and cleanup-pending tests pass without live network changes |
| C. Scoped network-operation integration | B | Frozen-snapshot authorization, fresh readiness gate, and owned-operation adapters | Synthetic failure matrix preserves unrelated state and never reports ready prematurely |
| D. Bounded lab verification | C and lab assets | Sanitized observations of traffic, state, and rollback | Unchanged-URL HTTP, restoration, and nonmatching-traffic checks pass |
| E. Product finish | D | GUI status/recovery flow, packaging, upgrade/uninstall guide | Repeated walkthrough and CI pass; limits are documented |

Complete A and B before joining any live network operation to a persistent process. Each package is a separate milestone: implementation, tests, and independent review must record three COMPLETE votes, then run relevant Debug, Release, and Sanitizer checks, commit, push, and verify CI as required by [AGENTS.md](../../AGENTS.md).

## A. Trusted GUI/helper boundary

Start with the [read-only trust-boundary slice](GUI_HELPER_TRUST_BOUNDARY.md). It records the current endpoints, the helper-identity gap, the signing decisions, and the offline acceptance checks before any control protocol expansion.

**Present:** `src/installed_helper_main.cpp` has a root-gated, read-only Mach service. `--process` deliberately exits with `production_peer_authenticator_unavailable`. `src/network/MachServiceIdentityPreviewCli.cpp` verifies the selected app's exact code requirement, including a self-match check. `resources/launchd/` and `scripts/package_launchd_helper.py` stage review artifacts but do not install them.

**Next decisions and implementation:**

1. Specify one GUI-accessible rendezvous for an unprivileged app. The existing control socket under the root-only state directory is not reachable by the GUI. Bind any state-changing request to the authenticated XPC message identity, not only to a Unix UID, PID, or caller-supplied path.
2. Define a versioned request/reply contract for a single fixed service. Keep read-only `probe` and `status` behavior intact. Specify how the frozen `SessionSnapshot`, readiness proof, one-time secret, and returned session capability cross the boundary, with byte limits, deadlines, replay behavior, and ownership of every descriptor and secret.
3. Keep the root-owned directory descriptor, lease, and PF journals tied to one canonical inode. Separate the GUI's authorization to request a session from the helper's fresh pre-mutation verification. Reject mismatched app identity, changed build hash, malformed fields, stale snapshots, or repeated Start before any operation factory runs.
4. Add a non-installing integration harness and an opt-in installed **read-only** smoke test. The latter must verify launch, authenticated status, rejected wrong signer, stop, and uninstall without PF or ARP changes. Document any local signing requirement and the exact build tested.

**Done when:** `--process` is either replaced by the authenticated production path or removed; no dead production entrypoint remains. The GUI can establish a trusted session channel, but this package grants no live redirection authority.

## B. Helper lifecycle using synthetic operations

**Present:** `InstalledHelperProcessBootstrap`, `LeasedHelperHost`, `LeasedUnixHelperCommandListener`, `HostSessionLease`, watchdog, and recovery journals have injectable seams and focused tests. They are not one installed process flow.

**Runtime boundary to resolve first:** The temporarily installed read-only service is the system-library-only `llm_interceptor_read_only_helper`. The existing `LeasedHelperHost` and process bootstrap live in `interceptor_network` and link Qt; the separate Qt-linked `llm_interceptor_helper` is not the reviewed service artifact. The new opt-in XPC Start parser is only a fixture and is not enabled by the installed service. Before adding a production Start handler, choose and review how one installed executable will own the host state, event loop, lease, watchdog, and journals without silently replacing the dependency-reviewed service artifact. A synthetic lifecycle can use an injectable system-only owner; the Qt host remains an offline behavioral reference until that boundary is resolved.

The next implementation slice should prove, without PF or ARP, that a single installed-service-shaped process accepts one authenticated synthetic Start, returns a session handle only after an injected operation reports active, and handles Heartbeat/Stop on the same owner loop. Tests should cover duplicate Start, wrong peer, lost peer, Stop retry, and process restart with pending cleanup. Keep the current read-only service protocol and packaging unchanged until the new path passes its own dependency and identity reviews.

**Work:** compose one owner-thread runtime whose startup order is: authenticate handoff, validate/freeze snapshot, acquire lease and recover journals, establish fresh listener readiness, start synthetic operations, expose a control endpoint, then release the capability. A failed step must retain any cleanup obligation and report the real state. Stop and watchdog paths must preserve access to recovery while cleanup is pending. The process must not acknowledge Active until its owned operations have completed and been verified.

**Offline test matrix:** duplicate Start, wrong signer, wrong capability, lost client, invalid clock, listener bind failure, factory failure, failure at each journal boundary, Stop retry, helper restart with pending journal, and wrong-thread destruction. Use temporary directories and fake operations; assert the exact state and resource ownership after every failure. No test should require root or a live network to pass in normal CTest.

**Done when:** a child-process integration test exercises authenticated Start, Heartbeat, Stop, and restart with synthetic operations. The test verifies that unrelated files and process state remain unchanged.

**Recorded first increment (offline, fixture only):** The runtime boundary is resolved by the [session-control contract](HELPER_SESSION_CONTROL_CONTRACT.md): the installed privileged service stays the single system-library-only `llm_interceptor_read_only_helper`, the control transport stays in the Qt-free `interceptor_read_only_xpc`, and the lifecycle owner for this increment is the fixture `HelperLifecycleRuntime` in `interceptor_network` — an owner-thread runtime composing the reviewed lease/journal/dispatch/watchdog pieces behind injectable seams in the production startup order (authenticated handoff → frozen snapshot → lease + journal recovery → fresh listener readiness → verified synthetic Start → one-time capability release → Heartbeat/Stop on the same loop). No production entrypoint constructs it; the installed `--mach-service` path and probe/status v1 are unchanged; `--process` still fails closed. The versioned Start/Heartbeat/Stop grammar and bounded reply shape are parser/encoder fixtures gated behind the `SyntheticLifecycle` constructor mode. The offline test matrix above, the child-process integration test, and the Qt-free extraction of the decision core into `interceptor_read_only_xpc` remain open work for the testing and review roles before any production Start handler is enabled.

## C. Scoped operation integration

Reuse the existing typed PF runners, attachment verifier, enable-reference owner, and bounded ARP packet adapter; avoid a second unjournaled command path. Immediately before any state change, re-evaluate the selected interface, addresses, direct routes, exact neighbor identities, upstream reachability, PF attachment, and proxy readiness against the frozen snapshot. Treat an uncertain command result as potentially applied and retain its journal obligation. Keep one selected client, one server, one port, and one owned anchor per session.

The integration review must explicitly cover operation order, upstream loop avoidance, return traffic, ordinary traffic bypass, checksum behavior observed in the lab, and rollback when the GUI, helper, or network disappears. A process crash or power loss cannot promise immediate neighbor-cache restoration; state and operator recovery must remain visible. Do not make global PF changes or report cleanup success from an empty command response alone.

**Done when:** fake-backed tests prove no mutation before the fresh gate, narrow ownership, correct reverse-order cleanup, and resumable recovery for every uncertain step. Live behavior remains gated by D.

**Recorded first increment (offline, factory seam only):** The Qt-free `PosixSpawnChildProcess` engine and the spawn-backed typed-command child factories now exist beside the QProcess runners (the runner, coordinator, and journal layers are reused unchanged), `ArpRedirectRefresher` grows the one-shot probe into the bounded session refresh loop described above, and `ScopedSessionSystemOperations` (via `scopedSessionOperationsFactory`) composes gate → recovery/lease → journaled PF reference capture → anchor install with ownership/attachment authorization → active-evaluation verification before ARP → refresh loop, with teardown in the existing reverse order. All collaborators are injectable; no production entrypoint constructs the factory, the lifecycle runtime remains a fixture, and `PfAnchorRecoverySystemOperations` is no longer `final` so the composed object can own its collaborators. The failure matrix, child-process integration test, and live adapter observations remain open per the [integration record](SCOPED_OPERATION_INTEGRATION.md).

## D. Bounded lab verification

Before a session, obtain fresh interface and device identities, direct-route and neighbor state, Ollama reachability, current PF rules/references, app build hash, and a saved rollback baseline. The historical addresses and MACs in older notes are examples, not defaults. Use synthetic HTTP and a mock upstream first; retain no real prompt bodies or credentials in committed evidence.

Run opt-in checks in this order: installed read-only helper; authenticated synthetic lifecycle; PF-only evaluation and cleanup; short authorized neighbor trial and correction; one ordinary HTTP request; one streaming request; one shorter and one longer JSON edit; nonmatching traffic; repeated Start/Stop; then failure/recovery cases. Record request count, upstream delivery, response completion, client neighbor recovery, owned PF cleanup, and unrelated state before and after. Stop on a mismatch and use the existing rollback runbook.

**Done when:** OpenCode reaches Ollama at its unchanged URL, the GUI records the request, the response completes, edits arrive exactly once, and Stop restores the authorized client and owned system state. Repeat the walkthrough and document any topology or checksum limitation.

## E. Product finish and release gate

Expose only states the helper can prove: uninstalled, ready, active, stopping, cleanup pending, and recovery needed. Prevent configuration changes to a frozen active session and show the selected client/server/port and actionable error without displaying prompt data in diagnostics. Preserve explicit proxy, request inspection, Hold/Modify, export/import, and offline replay behavior. Review signing, installation, upgrade, stop, and uninstall on the supported macOS build. Keep the privileged helper separate from the GUI and keep normal CI free of live-network actions.

M6 closes only when the three review roles accept the installed lifecycle and lab evidence, all build presets and CI pass, the operator can repeat the demo and cleanup, and every known limitation has an explicit supported behavior or recovery instruction.

**Enablement increment (offline, code-complete; live lab and full test phase remain):** The Qt-free decision core now exists as `InstalledSessionControlCore` in `interceptor_read_only_xpc` (dispatch-queue owner loop, per-message pinned peer authentication through the new `InstalledLifecycle` gate mode, fresh transparent-listener probe verification, one-session-per-process and capability/watchdog rules of the contract). The installed `--mach-service` entrypoint constructs it only behind the exact operator config line `session-control=true` in `mach-service.conf`; every other config serves byte-identical read-only behavior. The GUI drives the pinned-helper `XpcSessionControlClient` with a Transparent session tab (Start/Stop, off-GUI-thread heartbeats with generation guards, contract-state surfacing, config freeze while active, close-time blocking stop). Owned PF/ARP operations are deliberately fail-closed (`scoped_backend_unavailable`) until the scoped Qt backend is ported behind `InstalledSessionControlBackend`; the new offline test phase for the installed grammar, adapter, core, client, and GUI flow is deferred to the final testing phase along with packages B/C's matrices.
