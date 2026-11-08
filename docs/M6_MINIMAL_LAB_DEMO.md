# Minimal lab demo plan

Goal: record one OpenCode request from the Ubuntu client to the **unchanged** Ollama URL (`192.168.1.141:11434`) passing through `llm_interceptor` on the research Mac, appearing in its GUI, reaching Ollama, and returning a response. This is a bounded, manually operated lab proof, not a claim that the M6 product is complete. Reconfirm all addresses, interface names, MACs, and host permissions at the lab before starting.

## Fast fallback: explicit proxy (already demonstrated)

The GUI already supports a LAN listener with a single-client allowlist. Point OpenCode at the Mac's displayed listener URL, show the request and JSON in the GUI, then restore its Ollama URL. This can be recorded immediately and demonstrates observation/modification and HTTP relay, but **does not** demonstrate unchanged-address redirection, PF, or ARP. Use this as the opening or fallback clip.

## Recommended short transparent segment

Use a temporary **static neighbor mapping on the Ubuntu client**, not continuous ARP spoofing, while keeping OpenCode's Ollama URL unchanged. This works only if Ubuntu actually sends packets for Ollama directly on `wlp2s0`. The November 8 read-only `ip route get 192.168.1.141` result instead selected `via 192.168.1.1 dev wlp2s0`, so a neighbor override for `192.168.1.141` alone would not redirect that routed traffic. Recheck the interface prefix and routing policy; if the gateway route persists, the bounded demo needs a temporary, single-destination **on-link host route** as well as the neighbor entry, with both original route and neighbor state recorded and both changes rolled back. Do not change the gateway's neighbor entry. With a direct route, packets retain destination IP `192.168.1.141` but arrive at the Mac's MAC. A single-client PF `rdr` on `en0` sends that flow to the Mac's loopback transparent proxy listener. This proves the core MAC/IP/PF/HTTP path; it deliberately omits automatic ARP, installed helper lifecycle, and crash recovery.

### Small development work before the lab

1. Add a clearly labeled, opt-in **Transparent lab demo** start option in the existing GUI. It must start `ProxyServer` with `transparentRedirect=true`, bind only `127.0.0.1`, allow only the configured client IP, show the actual listener port, and keep the existing request panes and Observe/Modify controls. Do not claim that starting the listener changes routing.
2. Expose a read-only status panel or copyable line containing the exact selected interface, client/server IP and port, actual listener port, and whether the listener is currently ready. Never display the probe secret. Stop must close the listener. Keep this code separate from the existing explicit proxy start path.
3. Add one deterministic GUI/proxy test for the demo option and one offline test that generates the exact scoped PF rules from the bound listener port. Existing transparent proxy and PF snapshot tests cover much of the underlying behavior.
4. Prepare **review-only** PF candidate and rollback files using the existing attachment merge and syntax checker. Do not automate PF reload in the GUI. A human reviews the full candidate and current active PF state before the lab trial.

This is the complete pre-lab implementation scope for the short demo. Do not wait for an installed helper, production peer authentication, continuous ARP refresh, or automatic crash recovery. Mark the GUI option as lab-only and require an explicit Start click.

### Lab assets and operator actions

- Research Mac with administrator access, `en0` on the same Wi-Fi subnet, and an available loopback listener port.
- Ubuntu client with sudo access for one neighbor entry, running OpenCode. Keep its Ollama URL at `http://192.168.1.141:11434` for the transparent clip.
- Reachable Ollama server at `192.168.1.141:11434`, with a known working model warmed before the clip.
- A fresh Mac `en0` MAC, Ubuntu interface name, original server MAC, and **selected route to the server** observed in the lab. The prior ARP probe showed the Ubuntu mapping could change, but it did not prove packet delivery or that packets use the server's neighbor entry.
- Before any PF or neighbor change, prepare the exact undo commands and have a second terminal open for rollback. The operator executes privileged commands; the app does not silently modify PF or Ubuntu networking.

### Lab sequence

1. **Baseline:** on the Mac, confirm `en0` address/MAC and Ollama HTTP reachability; on Ubuntu, record `ip route get 192.168.1.141`, relevant IPv4 interface/routes, the server's original neighbor MAC, and confirm OpenCode succeeds directly. Record current PF status, main rules/attachments, and a backup of the configuration that would be changed. Use a warmed Ollama model to avoid first-request delay. If the server route goes via the gateway, prepare a one-host on-link route change and its exact rollback before touching the neighbor table.
2. **Listener:** start Transparent lab demo in Observe mode. Confirm its displayed loopback port and use the existing authenticated listener probe to verify readiness. Ordinary loopback HTTP is deliberately rejected by the transparent listener's client allowlist, so a local `curl` to it is not a valid data-path check. Stop if the probe fails.
3. **PF preparation:** enable/attach only the dedicated `llm_interceptor/*` references and load one session anchor whose `rdr` matches `en0`, the Ubuntu client IP, Ollama IP, TCP port 11434, and the displayed listener port. Verify that the active filter and translation references and owned anchor exist. Rule evaluation and counters require an inbound client packet in the next step. Do not flush unrelated anchors or globally disable PF. A packet sent from the Mac itself is not evidence for inbound `en0` redirection.
4. **One client packet path:** after recording ready-to-run route and neighbor rollback commands, install the one-host on-link route only if fresh `ip route get` still selects the gateway, and verify it now selects direct `wlp2s0`. Then temporarily replace only the Ubuntu neighbor entry for `192.168.1.141` with the verified Mac `en0` MAC. First send a small synthetic HTTP request to the unchanged Ollama address and confirm the PF rule counter changes, the request appears in the GUI, and it reaches upstream. Then send one short OpenCode `/v1/chat/completions` request. Record the GUI request and response plus the client result.
5. **Rollback immediately:** restore or delete the temporary Ubuntu neighbor override, remove the temporary one-host route if one was added, verify the original route and server MAC are selected again, remove and verify empty only the owned PF anchor, release only the PF enable reference acquired for this trial, restore the original PF attachment configuration if changed, and stop the listener. Confirm a direct OpenCode request still works.

Every privileged command, backup path, exact MAC, session anchor name, and rollback command should be filled in **after** fresh lab observations and reviewed before execution. Do not hard-code stale MACs in a script or run a broad PF flush. If the listener probe, PF attachment, inbound counter, reverse translation, or synthetic request fails, stop and roll back rather than proceeding to OpenCode.

### Go/no-go checkpoints

| Checkpoint | Continue only when | If it fails |
| --- | --- | --- |
| Baseline | Direct Ollama request succeeds; original route, neighbor MAC, and PF state are recorded | Do not start the transparent segment |
| Listener | GUI displays a ready loopback listener and its authenticated probe succeeds | Stop listener; record explicit-proxy fallback |
| PF setup | Both dedicated attachments and only the intended session anchor are active | Remove owned state; restore the saved PF configuration |
| Synthetic client request | Ubuntu route is direct to `wlp2s0`; PF counter changes and the GUI plus Ollama see one request with a successful response | Restore Ubuntu neighbor and any temporary host route first, then owned PF state |
| OpenCode request | Unchanged URL succeeds and appears once in GUI | Stop after recording the failure; roll back |
| Cleanup | Original route, neighbor mapping, unrelated PF state, and direct Ollama access are restored | Keep the demo marked incomplete and resolve cleanup before retry |

The first recording can focus on Observe mode. Manual JSON modification is optional after the unmodified path succeeds; it should not be required for the minimum transparent proof.

### Recording and pass criteria

Capture one continuous sequence showing: unchanged OpenCode server URL; the temporary one-IP neighbor mapping; the active scoped PF rule; the request in the GUI; a successful Ollama response; then restored neighbor/PF state. Redact prompt text, credentials, local MACs, and any unrelated traffic from the published video. A passing demo proves only this manual one-client path. It does **not** prove automatic ARP redirection, restart recovery, safe unattended operation, or general network support.

## Estimates and fallback

The GUI demo option and offline checks are roughly one focused development session. PF candidate review and the staged lab recording are roughly one lab session, with time reserved for routing/PF troubleshooting. If the transparent segment cannot be made reliable in that session, record the already working explicit-proxy path and the bounded ARP neighbor-change probe as separate, accurately labeled clips. Do not splice them into a claim of end-to-end transparent delivery.

The manual neighbor override is supported by the Linux [`ip-neighbour(8)`](https://man7.org/linux/man-pages/man8/ip-neighbour.8.html) `replace` operation. PF's [redirection documentation](https://man.openbsd.org/pf.conf) describes inbound redirection to a loopback-bound daemon; actual behavior on this lab Mac still requires the PF-only and client-packet checks above.
