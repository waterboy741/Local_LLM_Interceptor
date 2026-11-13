# M5 package and M6 lab preparation

The package is an unsigned explicit HTTP proxy, without a signed privileged helper, working Network Extension, or automatic redirection. Installed-helper status and remaining gates are in [the bootstrap contract](m6/INSTALLED_HELPER_BOOTSTRAP.md) and [live handoff](M6_LIVE_HANDOFF.md).

## Reproducible package

Install the README dependencies, including `macdeployqt`, then run:

```sh
bash scripts/package_macos.sh
```

The script builds release, requires release tests to pass, copies the bundle, deploys Qt frameworks, and writes `dist/llm_interceptor-macos.zip`. It neither notarizes the app nor grants capture, injection, PF, or Network Extension privileges. Exclude real recordings and machine-specific settings.

Unpack into a disposable directory, inspect the executable/frameworks, and test the loopback listener with a synthetic server on the build Mac or a compatible Mac. Live Ollama/Wi-Fi verification belongs to M6.

## Diagnostic tools

All tools below are opt-in. They do not change routes, PF, ARP, forwarding, or interfaces; none elevates or retries with `sudo`. TCP preflight can create remote connection state/logs. Reports omit supplied network identities and raw output; keep actual configuration in controlled lab notes. Successful diagnostics are point-in-time observations, not proof of packet egress, shared layer 2, ARP compatibility, active PF evaluation, reverse translation, or interception.

### Endpoint preflight

`lab_preflight` validates configuration, an up selected interface with usable IPv4/unicast MAC, and client/server host addresses in one of its IPv4 subnets. Its bounded server TCP probe binds the selected local IPv4; the OS may still route over another interface. A shared prefix does not establish shared layer 2.

```sh
./build/debug/lab_preflight \
  --interface "$RESEARCH_INTERFACE" \
  --client-ip "$CLIENT_IPV4" \
  --server-ip "$SERVER_IPV4" \
  --server-port "$SERVER_TCP_PORT" \
  --timeout-ms 1500 \
  --evidence preflight.json
```

Interface, peer addresses, and port have no inferred defaults. Timeout is 1–5000 ms (default 1500). TCP outcomes are `reachable`, `refused`, `timed_out`, `error`, or `not_checked`. JSON includes UTC time, configured-field presence, outcomes, timeout, and status, omitting interface name, addresses, MACs, prefix/source address, credentials, and payloads. Stdout and optional `--evidence` contain the same report. Exit codes: 0 checks/TCP succeeded; 1 check failed; 2 arguments or evidence writing failed. Layer-2/ARP and proxy readiness remain unproven.

October 19, 2026 evidence: preflight, one client ICMP echo, and both local neighbor entries succeeded; Ollama `/api/version` returned HTTP 200/version 0.40.4, and a synthetic `/v1/chat/completions` returned one completion. This established those endpoint observations only. Raw address-bearing output stays in ignored build evidence files; see [PLAN.md](../PLAN.md) for subsequent observations.

### Route and neighbor inspection

`--route-neighbor-diagnostics` runs four read-only processes without a shell: `/sbin/route -n get <address>` for each peer, then `/usr/sbin/arp -i <interface> -n <address>` for each peer. Per-query timeout is 1–5000 ms (default 1500), with 32 KiB combined output.

```sh
./build/debug/lab_preflight \
  --route-neighbor-diagnostics \
  --interface "$RESEARCH_INTERFACE" \
  --client-ip "$CLIENT_IPV4" \
  --server-ip "$SERVER_IPV4" \
  --server-port "$SERVER_TCP_PORT" \
  --network-timeout-ms 1500 \
  --evidence route-neighbors.json
```

JSON reports recognized output, route/neighbor interface matches, explicit direct `link#` gateway, and resolved unicast neighbor MAC presence. Missing gateway means directness unknown; `(incomplete)` or `no entry` means unresolved. `complete` means all four observations were recognized, not that connectivity succeeded. Queries neither send resolution traffic nor refresh potentially stale cache entries.

### PF inspection

`lab_preflight --pf-diagnostics` requires the same tuple plus `--session-id`. Fixed allowlisted show queries inspect PF status, main filter/translation rules, the application/session anchor tree, scoped rules/counters, and the state table. Permission failures are unavailable results, without escalation.

```sh
./build/debug/lab_preflight \
  --pf-diagnostics \
  --session-id "$SESSION_ID" \
  --interface "$RESEARCH_INTERFACE" \
  --client-ip "$CLIENT_IPV4" \
  --server-ip "$SERVER_IPV4" \
  --server-port "$SERVER_TCP_PORT" \
  --pf-timeout-ms 3000 \
  --evidence pf-diagnostics.json
```

State output is global: `pfctl(8)` does not promise anchor-scoped `-s states`. Each query drains at most 256 KiB plus an overflow sentinel; Qt may buffer more internally, so this is not a hard memory bound. The tool filters states in memory by client/server IP and server port, discards raw output, and reports only global candidate counts, never anchor ownership.

Main attachment references and loaded session rules are separate evidence. Counters do not prove a fresh packet matched; `evaluation_proven` stays false. Caps, timeouts, permissions, or unrecognized output make the result incomplete. A complete report does not imply references were found. JSON also omits session ID, rule text, and raw states. Run against an existing session anchor for meaningful inspection; the preliminary lab run returned `permission_denied` at its first query and read no rules/states.

### PF readiness and attachment candidates

`pf_readiness` queries only status and main filter/translation listings, requiring enabled PF and both `llm_interceptor/*` references. Its per-query timeout is 1–5000 ms; malformed/duplicate options fail before queries. Non-macOS returns `unsupported_platform` without a command. Output explicitly sets `references_observed_only: true` and `packet_evaluation_proven: false`; readiness does not establish a session anchor, counters, listener/upstream reachability, or forwarding. The recorded host baseline was disabled, including the recognized `Debug: Urgent` suffix; reobserve before use.

```sh
./build/debug/pf_readiness --timeout-ms 3000
```

`pf_attachment_prepare` emits [the attachment fragment](m6/llm_interceptor_attachment.pf) only after `/sbin/pfctl -n -f -` accepts it. Stdout contains the fragment; stderr contains sanitized status. Non-macOS returns `unsupported_platform`. It writes no files itself.

```sh
./build/debug/pf_attachment_prepare > "$TMPDIR/llm_interceptor_attachment.pf"
cat "$TMPDIR/llm_interceptor_attachment.pf"
```

Place `rdr-anchor` in the translation section and `anchor` in the filter section, before each section's rules; do not append both after filtering. Preserve all existing rules and `com.apple/*` references. This is an insertion proposal, not a complete or active configuration.

`pf_attachment_merge` accepts at most 1 MiB of supplied configuration on stdin. It requires exactly one active stock `rdr-anchor "com.apple/*"` marker followed by one active stock `anchor "com.apple/*"` marker, inserting the corresponding `llm_interceptor/*` reference before each. It rejects missing/duplicate/reversed markers, mixed line endings, active continuations, or active `llm_interceptor` namespace text. Comment-only mentions are ignored; quoted `#`, comments, line endings, and all other bytes are preserved.

```sh
./build/debug/pf_attachment_merge < /etc/pf.conf > "$TMPDIR/pf.conf.llm-interceptor-review"
```

The merger emits the full candidate only after `/sbin/pfctl -n -f -` succeeds; stderr status omits supplied text and PF diagnostics. Neither preparation tool loads rules, enables PF, edits `/etc/pf.conf`, or flushes state. Review the full diff before any separately authorized change. Syntax acceptance applies only to the supplied snapshot and proves neither effective placement nor packet behavior.

## Package/lab checklist

Record date, OS, commit, client/server versions, interface/addresses, port/API path, Wi-Fi policy, PASS/FAIL, and sanitized observations. Use synthetic payloads; exclude credentials and real prompts.

1. Verify direct client-to-mock connectivity, configured path/port, server LAN bind, and research-Mac reachability.
2. Test packaged loopback Observe: one upstream delivery, intact response, incremental stream, nonmatching path, and closed listener after Stop.
3. Test Modify: shorter/longer synthetic bodies arrive exactly once; response, hold timeout, and stop cancellation work.
4. Verify bounded history, sanitized archive roundtrip, and replay without server connections or exported test credentials.
5. Only after reviewed redirection implementation, exercise the [M0 live gates](M0_LAB.md): topology, MAC/IP delivery, attachment/evaluation, reverse translation, bypass, cleanup, and recovery. An unsigned package or loopback success does not pass these gates.
