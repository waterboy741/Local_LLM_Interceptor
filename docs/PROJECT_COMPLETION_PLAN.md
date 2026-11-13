# Project completion plan

M0–M5 met their offline criteria. The GUI supports an explicit HTTP proxy, manually verified from a second device using the displayed listener URL. The November 8 manual transparent trial used the unchanged Ollama URL and a temporary Mac checksum setting. M6 still requires an installed authenticated helper, automated activation and recovery, and repeatable lab acceptance. See [recorded results](../PLAN.md#m6--authorized-lab-validation) and [the implementation handoff](M6_LIVE_HANDOFF.md).

## 1. Lab assets and operator actions

| Asset | Prepare before a live run |
| --- | --- |
| Research Mac | Record macOS version and architecture, app commit, and Wi-Fi interface. Keep a local administrator available for any OS authorization. Run the GUI unprivileged. |
| OpenCode client | Confirm current IPv4/MAC and version. The last reported IPv4 was `192.168.1.169`. Keep its original Ollama URL for transparent tests and send synthetic `/v1/chat/completions` requests. |
| Ollama server | Confirm IPv4, port, version/model, LAN bind, and firewall. The last reported endpoint was `192.168.1.141:11434`. |
| Authorized Wi-Fi/L2 | Verify the intended SSID/VLAN, peer reachability, and AP isolation or ARP policy. A shared IPv4 prefix alone leaves these unproven. |
| Disposable HTTP mock | Use a configurable nondefault port, deterministic ordinary and streaming replies, and synthetic prompts. |
| Maintenance window | Get explicit authorization for the pair and reserve time for possible disruption. Keep local access to all devices and a rollback path. |

Record a fresh sanitized baseline with the date, versions, selected interface, current configuration, subnet/routes, neighbor resolution, and direct HTTP behavior. Recheck reachability before each run. Historical neighbor rows can be stale. Keep real addresses, prompts, credentials, captures, and recovery tokens out of committed evidence and default diagnostics.

Before helper installation, review the signed GUI identity and approve any required OS privilege prompt locally. A Developer ID team/certificate is unavailable. Validate the chosen local installation and authentication path on the target macOS. If AP policy blocks the ARP path, decide whether to change the authorized lab policy or support explicit proxy only.

## 2. Build and prove the transparent path

1. **Install and authenticate the helper.** Start with synthetic backends. Wire a reviewed install/uninstall path, trusted signed caller identity, capability handoff, authenticated Start/Heartbeat/Stop, and a watchdog independent of the GUI. Use one private state directory and host lease. The current read-only Mach service and its GUI status check are groundwork.
2. **Wire scoped PF and recovery.** Require effective privilege, exact owned anchor and attachment, and fresh proxy/interface readiness. Journal before mutations, since failed commands may apply. Extend recovery to ARP, forwarding, and exact PF references. Preserve global rules and unrelated state. Validate atomic compare-and-set for owned settings or redesign the contract before enabling forwarding changes.
3. **Prove PF before ARP.** Check the dedicated anchor’s active filter/translation attachment, order, `set skip`, fresh SYN delivery, rule counters/state, and reverse translation. Redirect to the selected-interface LAN listener. Keep the proxy’s fixed upstream connection outside the inbound match. Verify one proxy receipt and one upstream request.
4. **Add scoped ARP and bypass.** Check the client’s mapping for the server IP, destination MAC at the Mac, inbound IP packet, translated socket, upstream connection, and reply with the original server identity. Test other paths and TCP traffic in both directions, including checksums, MTU, and existing state. Scope any server-side mapping change separately if needed. Refresh only the authorized pair while healthy, then send correction and verify cache/traffic recovery. See [trial and rollback commands](M6_LIVE_DEMO_RUNBOOK.md).
5. **Test lifecycle and failure recovery.** Freeze interface/client/server/port at activation. Exercise repeated Start/Stop, lease collision, stale owner, partial startup, interface loss, GUI/helper/proxy failure, existing flows, stale neighbors, and restart with pending journals. Measure restoration of neighbors, PF rules/state/references, forwarding settings, and ordinary connectivity. Keep ownership and surface `CleanupPending` until restoration is proven.

## 3. Product, validation, and closeout

- Keep local and remote explicit proxy workflows usable. Expose Transparent mode after helper and lab gates pass. Show selected scope, upstream, listener, readiness, active/stopping/recovery state, and actionable failures. Require explicit Start/Stop, prevent conflicting sessions, freeze routing inputs during activation, and expose recovery on reconnect.
- Send synthetic Observe, Hold, and automatic Modify requests through the transparent path. Verify untouched Observe bodies and exactly one copy of each shorter and longer edit at the mock server. Test default/nondefault ports, framing, model warm-up, timeouts, cancellation, native streaming, and nonmatching traffic. Keep the configurable Ollama endpoint and inspection, audit, export/import, and offline replay behavior.
- Maintain fake-backed tests for ARP bounds and malformed frames, invalid IPC, bounded processes, partial writes, watchdog, crashes/restarts, state conflicts, and repeated cleanup. Keep live checks opt-in and compare latency, time to first byte, throughput, memory, and recovery against agreed targets.
- Validate helper packaging, installation, upgrade, stop, uninstall, logs/status, and post-crash recovery on the target Mac. Document privilege prompts, rollback, and supported macOS versions. The current package is unsigned.
- Follow the milestone review, commit, push, and verification requirements in [AGENTS.md](../AGENTS.md). Run debug, release, sanitizer, and CI checks. Close M6 only after the unchanged-client-URL walkthrough, installed-helper lifecycle, and measured recovery pass. Document any topology limitation and keep unmet gates open.
