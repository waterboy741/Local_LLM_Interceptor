# Minimal lab demo plan (historical)

The November 8, 2026 manual trial demonstrated one Ubuntu OpenCode request to the **unchanged** Ollama URL through the research Mac, visible in the GUI and answered by Ollama. The former **Transparent lab demo** GUI controls have since been removed; this is an archived plan, not current GUI instructions. Transparent/loopback `ProxyServer` APIs remain for offline tests and future helper work.

Use [the historical runbook](M6_LIVE_DEMO_RUNBOOK.md) for the recorded topology, commands, checksum workaround, results, and rollback. Use [the live handoff](M6_LIVE_HANDOFF.md) for remaining implementation and acceptance work.

## Scope and prerequisites

- Minimum proof: one client, one server/port, manual neighbor override, scoped PF redirect, successful unmodified HTTP response. Automatic ARP, installed-helper lifecycle, crash recovery, and unattended operation are excluded.
- Reobserve interface/IP/MAC identities, server reachability, and the client's selected route before every trial. A shared SSID alone is insufficient.
- The Ubuntu route must select the server directly. If it selects a gateway, prepare and later remove a single-destination on-link host route; never change the gateway's neighbor entry.
- Prepare exact rollback commands, a PF configuration backup, and a second terminal before mutation. Warm the model and use synthetic payloads.
- The historical listener bound the selected research-interface IPv4, allowed only the configured client, displayed its actual port, and retained Observe/Modify controls. Starting it did not change routing.

## Review-only rule preview

`pf_session_preview` validates the tuple with `SessionSnapshot`, syntax-checks via `/sbin/pfctl -n -f -`, prints rules to stdout and sanitized status/anchor JSON to stderr. Supplied readiness/attachment facts are assumptions, not live verification. It does not load PF, change ARP, or write files.

```sh
./build/debug/pf_session_preview \
  --interface en0 --client-ip 192.0.2.10 --server-ip 192.0.2.30 \
  --server-port 11434 --listen-port 54321 --research-ip 192.0.2.20 \
  --research-mac 02:00:00:00:00:20 --client-mac 02:00:00:00:00:10 \
  --server-mac 02:00:00:00:00:30 --prefix-length 24 --session-id lab_demo
```

Replace every documentation value with fresh observations, especially the actual listener port. Review the rules, full PF attachment candidate, and active PF state before privileged action.

## Trial gates

| Stage | Required evidence |
| --- | --- |
| Baseline | Direct Ollama request succeeds; original route, neighbor MAC, PF rules/references, and any setting to be changed are recorded |
| Listener | Selected-interface listener is ready and its authenticated probe succeeds; Mac-local HTTP does not test the client-allowlisted inbound path |
| PF | Dedicated filter/translation attachments and only the intended session anchor are active; redirect targets the actual LAN listener |
| Synthetic request | Direct client route, increased PF counter, request at GUI and upstream, successful response |
| OpenCode | Unchanged URL succeeds and appears once in GUI; record response and counters |
| Cleanup | Neighbor and any temporary host route restored, checksum baseline restored if changed, owned PF rules/state cleaned, exact enable token released, direct access verified |

On failure, stop and follow the runbook's ordered rollback. Never flush unrelated PF state or globally disable PF. A syntax check or Mac-local connection does not prove inbound evaluation or reverse translation.

## Recording and fallback

Record the unchanged URL, temporary one-IP mapping, scoped PF rule, GUI request, successful response, and verified cleanup. Redact prompts, credentials, local MACs, and unrelated traffic. Observe mode is sufficient; JSON modification is optional after the unmodified path succeeds.

If transparent routing fails, record the demonstrated explicit-proxy path: temporarily point OpenCode at the Mac's single-client LAN listener, show relay/inspection/modification, then restore the Ollama URL. This fallback does not prove unchanged-address redirection. The bounded ARP probe alone proves neither HTTP delivery nor continuous redirection.
