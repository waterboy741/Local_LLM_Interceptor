# Minimal lab demo plan

Goal: record one OpenCode request from the Ubuntu client to the **unchanged** Ollama URL (`192.168.1.141:11434`) passing through `llm_interceptor` on the research Mac, appearing in its GUI, reaching Ollama, and returning a response. This is a bounded, manually operated lab proof, not a claim that the M6 product is complete. Reconfirm all addresses, interface names, MACs, and host permissions at the lab before starting.

## Fast fallback: explicit proxy (already demonstrated)

The GUI already supports a LAN listener with a single-client allowlist. Point OpenCode at the Mac's displayed listener URL, show the request and JSON in the GUI, then restore its Ollama URL. This can be recorded immediately and demonstrates observation/modification and HTTP relay, but **does not** demonstrate unchanged-address redirection, PF, or ARP. Use this as the opening or fallback clip.

## Recommended short transparent segment

Use a temporary **static neighbor mapping on the Ubuntu client**, not continuous ARP spoofing. Map only Ollama's IPv4 address to the research Mac's `en0` MAC, while keeping OpenCode's Ollama URL unchanged. This makes packets retain destination IP `192.168.1.141` but arrive at the Mac's MAC. A single-client PF `rdr` on `en0` sends that flow to the Mac's loopback transparent proxy listener. The proxy forwards to the real Ollama address. Remove the Ubuntu mapping immediately after the clip. This proves the core MAC/IP/PF/HTTP path; it deliberately omits automatic ARP, installed helper lifecycle, and crash recovery.

### Small development work before the lab

1. Add a clearly labeled, opt-in **Transparent lab demo** start option in the existing GUI. It must start `ProxyServer` with `transparentRedirect=true`, bind only `127.0.0.1`, allow only the configured client IP, show the actual listener port, and keep the existing request panes and Observe/Modify controls. Do not claim that starting the listener changes routing.
2. Expose a read-only status panel or copyable line containing the exact selected interface, client/server IP and port, actual listener port, and whether the listener is currently ready. Never display the probe secret. Stop must close the listener. Keep this code separate from the existing explicit proxy start path.
3. Add one deterministic GUI/proxy test for the demo option and one offline test that generates the exact scoped PF rules from the bound listener port. Existing transparent proxy and PF snapshot tests cover much of the underlying behavior.
4. Prepare **review-only** PF candidate and rollback files using the existing attachment merge and syntax checker. Do not automate PF reload in the GUI. A human reviews the full candidate and current active PF state before the lab trial.

### Lab sequence

1. **Baseline:** on the Mac, confirm `en0` address/MAC and Ollama HTTP reachability; on Ubuntu, record the server's original neighbor MAC and confirm OpenCode succeeds directly. Record current PF status, main rules/attachments, and a backup of the configuration that would be changed. Use a warmed Ollama model to avoid first-request delay.
2. **Listener:** start Transparent lab demo in Observe mode. Confirm its displayed loopback port and run a direct local HTTP check to the proxy before changing routes. Stop if the listener is not ready.
3. **PF-only proof:** enable/attach only the dedicated `llm_interceptor/*` references and load one session anchor whose `rdr` matches `en0`, the Ubuntu client IP, Ollama IP, TCP port 11434, and the displayed listener port. Verify the active filter and translation references, owned anchor, and rule counters. Do not flush unrelated anchors or globally disable PF. A packet sent from the Mac itself is not evidence for inbound `en0` redirection.
4. **One client packet path:** on Ubuntu, temporarily replace only the neighbor entry for `192.168.1.141` with the verified Mac `en0` MAC. First send a small synthetic HTTP request to the unchanged Ollama address and confirm it appears in the GUI and reaches the upstream. Then send one short OpenCode `/v1/chat/completions` request. Record the GUI request and response plus the client result.
5. **Rollback immediately:** restore or delete the temporary Ubuntu neighbor override, verify the original server MAC is resolved again, remove and verify empty only the owned PF anchor, release only the PF enable reference acquired for this trial, restore the original PF attachment configuration if changed, and stop the listener. Confirm a direct OpenCode request still works.

Every privileged command, backup path, exact MAC, session anchor name, and rollback command should be filled in **after** fresh lab observations and reviewed before execution. Do not hard-code stale MACs in a script or run a broad PF flush. If PF attach/reverse translation or the synthetic request fails, stop and roll back rather than proceeding to OpenCode.

### Recording and pass criteria

Capture one continuous sequence showing: unchanged OpenCode server URL; the temporary one-IP neighbor mapping; the active scoped PF rule; the request in the GUI; a successful Ollama response; then restored neighbor/PF state. Redact prompt text, credentials, local MACs, and any unrelated traffic from the published video. A passing demo proves only this manual one-client path. It does **not** prove automatic ARP redirection, restart recovery, safe unattended operation, or general network support.

## Estimates and fallback

The GUI demo option and offline checks are roughly one focused development session. PF candidate review and the staged lab recording are roughly one lab session, with time reserved for routing/PF troubleshooting. If the transparent segment cannot be made reliable in that session, record the already working explicit-proxy path and the bounded ARP neighbor-change probe as separate, accurately labeled clips. Do not splice them into a claim of end-to-end transparent delivery.

The manual neighbor override is supported by the Linux [`ip-neighbour(8)`](https://man7.org/linux/man-pages/man8/ip-neighbour.8.html) `replace` operation. PF's [redirection documentation](https://man.openbsd.org/pf.conf) describes inbound redirection to a loopback-bound daemon; actual behavior on this lab Mac still requires the PF-only and client-packet checks above.
