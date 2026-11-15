# GUI/helper trust boundary: next offline slice

This document narrows package A of the [M6 implementation backlog](IMPLEMENTATION_BACKLOG.md) to a reviewable, read-only first increment. It does not authorize network redirection or extend the helper's control protocol. A manually staged lab trial succeeded, but the product still has no installed, authenticated helper lifecycle.

## What exists today

- `src/installed_helper_main.cpp` can launch a root-gated Mach service with only `probe` and `status`. Its separate `--process` entrypoint deliberately exits with `production_peer_authenticator_unavailable`.
- `src/network/LaunchdMachServiceBootstrap.cpp` reads an opt-in, root-owned config. An enabled config accepts only one exact, locally compilable GUI cdhash requirement. The checked-in example is disabled.
- `src/network/MachServicePeerAuthenticator.cpp` checks the signed identity of an incoming XPC message before `XpcControlRequestGate` parses its operation.
- `src/network/XpcReadOnlyServiceClient.cpp` enforces a bounded wait and exact reply shape. `src/gui/MainWindow.cpp` runs the status call off the GUI thread and discards stale results after a session clear.
- The GUI reads the separately provisioned **helper** cdhash from the fixed identity file described in the [helper bootstrap contract](INSTALLED_HELPER_BOOTSTRAP.md#gui-helper-identity). It requests status from the privileged Mach service only when that identity loads successfully and reports a verified identity only after the OS peer check and reply validation succeed.
- `scripts/package_launchd_helper.py` only stages files for review. It does not sign, install, or load a service. The root-only state directory is intentionally inaccessible to the ordinary GUI process.
- The offline package smoke test checks the staged helper's embedded signature, verifies that its literal cdhash requirement matches the staged executable, and checks rejection of a different cdhash. This verifies the file selected for review. An installed-service smoke test remains part of A3. [Helper bootstrap contract](INSTALLED_HELPER_BOOTSTRAP.md)

## Boundary requirements

1. The GUI stays unprivileged. It must not read or write the root-only state directory. Any supported rendezvous must be reachable through an OS-managed service endpoint, with a fixed name and no caller-supplied socket path.
2. The helper authenticates the GUI from the OS-provided message identity before parsing request fields. The selected app requirement must match the exact reviewed build. A changed or unprovisioned identity fails closed.
3. The GUI must distinguish a valid installed helper from an absent, incompatible, or unexpected endpoint before treating status as authoritative. Establish how the expected helper identity is provisioned and pinned across updates; do not infer trust from a successful `status` payload alone.
4. Keep read-only protocol v1 unchanged during this increment: exactly `probe` and `status`, fixed reply fields, bounded deadline, and no capability, file descriptor, snapshot, or state-changing operation in a reply.
5. Secret and descriptor ownership for a later session handoff must be specified before coding it. The current Unix bootstrap seam cannot itself prove that a caller on a root-owned socket is the reviewed GUI build. A UID/PID check is insufficient as an app-identity policy.
6. Every failure returns a bounded, non-sensitive reason. No prompt body, session secret, signing metadata beyond the reviewed requirement, or untrusted path enters normal GUI status text or default logs.

## Implementation order

| Slice | Code and artifact focus | Offline acceptance |
| --- | --- | --- |
| A1. Identity policy decision | `docs/m6/INSTALLED_HELPER_BOOTSTRAP.md`, signing/staging scripts, fixed launchd artifact | Document the exact locally signed GUI and helper builds, who approves their hashes, how update/rollback changes them, and the failure when either is absent. Keep sample config disabled. |
| A2. Read-only peer verification | `XpcReadOnlyServiceClient`, `MachServicePeerAuthenticator`, `XpcControlRequestGate`, focused Qt tests | A real signed local test service is accepted only under its reviewed helper requirement. Wrong helper identity, wrong GUI identity, malformed request/reply, protocol mismatch, timeout, and service loss fail closed. No root or PF/ARP operation in normal CTest. |
| A3. Installed read-only smoke | staged plist/helper, GUI status panel, opt-in operator procedure | On the target Mac, the ordinary GUI reaches the installed read-only service; a wrong build is rejected; stopping/removing the service leaves no owned state. This test may need local administrator action and is excluded from CI. |
| A4. Session handoff design | versioned contract and ownership table, then a separate reviewed implementation milestone | Specify limits, deadlines, replay handling, immutable snapshot, one-time secret, capability delivery, event-loop owner, and cleanup ownership. Do not add a state-changing XPC operation until A1–A3 and the synthetic lifecycle gate pass. |

## Tests that make A2 reviewable

Use anonymous XPC endpoints for deterministic malformed-message and timeout cases. Add a separate signed local-service test for actual code-signature verification; an anonymous endpoint alone cannot prove a launchd installation or signed peer. The test fixture must never use a broad requirement such as `anchor apple` as a successful production policy. Exercise concurrent status calls and a late reply after timeout so stale UI state cannot be presented as current. Keep the normal CI path rootless and read-only.

## Decisions to record before installation

- Exact helper signing method for the target Mac and review of the resulting cdhash before it is provisioned in the fixed identity file.
- GUI signing method and whether a local ad-hoc identity is acceptable for the research installation. Rebuilding or re-signing changes a pinned cdhash.
- Service domain, upgrade behavior, and uninstall order. The review package currently supplies a launchd artifact but no supported installer.
- Whether the operator will approve one fixed build or a signed update channel. A broader signer/team requirement changes the trust model and needs a separate review.

**Exit criterion:** the GUI can query the installed helper read-only with mutual identity checks, and both endpoints reject the wrong build. A3 verifies this against the installed service on the target Mac. The next milestone after this is synthetic helper lifecycle integration.
