# One-client transparent lab trial (8 November 2026)

This runbook is for the authorized, manually operated lab trial only. The app's **Transparent lab demo** listener must display `Ready: interface=en0 client=192.168.1.169 server=192.168.1.141:11434 listener=192.168.1.16:11434` throughout the trial. The research Mac currently has `en0=192.168.1.16/24`, MAC `7c:d1:ad:b8:5a:8e`; Ubuntu is `192.168.1.169/24` on `wlp2s0`; Ollama is `192.168.1.141:11434`. Recheck these facts before running any mutation. The Mac's PF baseline was **Disabled**, with only stock `com.apple/*` references and no PF enable references. The Ubuntu shell's selected route to Ollama was direct through `wlp2s0`. These observations expire when the network changes.

A November 8 Ubuntu client `/api/version` request returned HTTP 200 using the LAN-bound listener, the client neighbor override, and PF LAN redirection while the Mac's global receive-checksum offload setting `net.link.generic.system.hwcksum_rx` was temporarily set to `0`. A subsequent Ubuntu OpenCode `/v1/chat/completions` request to the unchanged Ollama URL received a successful response and appeared in the GUI Requests pane. After deleting the temporary neighbor entry, direct `/api/version` access recovered. The client neighbor and checksum setting were restored and owned PF rules were cleared. The user then loaded `build/demo-pf-original.conf` with `sudo pfctl -f` and released the trial's PF enable token with `sudo pfctl -X`; the reported output confirmed PF `Status: Disabled` and `No pf starter references held`. One established Mac-to-upstream PF state had been observed earlier; its disappearance was not separately verified. This is bounded lab evidence, not proof that the default checksum setting works. The application does not change this global setting. Any repeat must record its exact original value, make only an explicitly authorized temporary change, and restore and verify that value during rollback; do not assume `1` is the original value. Never leave it disabled after the trial.

Regenerate session rules for the current displayed LAN address and actual port before loading anything. For the current tuple they must contain `rdr ... -> 192.168.1.16 port 11434` and `pass in ... to 192.168.1.16 port 11434`; reject stale loopback targets. A previously syntax-checked file does not establish that its target matches the new listener.

The two prepared, ignored files are `build/demo-pf-candidate.conf` and `build/demo-lan-rules.pf`. The first differs from `/etc/pf.conf` only by one `rdr-anchor "llm_interceptor/*"` and one `anchor "llm_interceptor/*"` reference. The second contains one scoped redirect and two scoped pass rules for `llm_interceptor/lab_demo_20261108`. Both passed `/sbin/pfctl -n -f` syntax checks. `build/demo-pf-original.conf` is an exact copy of the stock main configuration for rollback. No system PF file has been edited. Do not use a broad PF flush or a global PF disable.

## Before changes

On the Mac, leave the app open in Observe mode. From the repository root, check the listener, files, and baseline again:

```sh
sysctl net.link.generic.system.hwcksum_rx
lsof -nP -iTCP@192.168.1.16:11434 -sTCP:LISTEN
cmp /etc/pf.conf build/demo-pf-original.conf
diff -u /etc/pf.conf build/demo-pf-candidate.conf
/sbin/pfctl -n -f build/demo-pf-candidate.conf
/sbin/pfctl -a llm_interceptor/lab_demo_20261108 -n -f build/demo-lan-rules.pf
sudo /sbin/pfctl -s info | head -n 2
sudo /sbin/pfctl -sr
sudo /sbin/pfctl -sn
sudo /sbin/pfctl -s References
```

Stop if the listener port, PF baseline, main configuration, or candidate diff changed. On Ubuntu, confirm `ip -4 route get 192.168.1.141` selects `dev wlp2s0` without `via`, and record `ip neigh show 192.168.1.141 dev wlp2s0`. The original Ollama MAC observed earlier was `bc:c7:46:9e:b3:30`; verify it again. A host route is unnecessary while the selected route remains direct.

## Stage PF on the Mac

Keep a second Mac terminal open for the rollback below. Run each command separately from the repository root and inspect its output before continuing:

```sh
sudo /sbin/pfctl -f build/demo-pf-candidate.conf
sudo /sbin/pfctl -a llm_interceptor/lab_demo_20261108 -f build/demo-lan-rules.pf
sudo /sbin/pfctl -E
```

**Record the exact token** printed by `-E`; it is needed to release only this trial's PF enable reference. If any command fails or an unexpected rule appears, perform the Mac rollback before touching Ubuntu. Verify both active attachment types and both owned rule types:

```sh
sudo /sbin/pfctl -s info | head -n 2
sudo /sbin/pfctl -s References
sudo /sbin/pfctl -sn
sudo /sbin/pfctl -sr
sudo /sbin/pfctl -a llm_interceptor/lab_demo_20261108 -sn
sudo /sbin/pfctl -a llm_interceptor/lab_demo_20261108 -sr
```

The main `-f` command can replace rules dynamically inserted into the main ruleset by macOS services. The observed baseline contained only stock anchor references, but stop and roll back if that changes. This staged trial does not edit `/etc/pf.conf` on disk.

## One Ubuntu client request

Record the exact original checksum value from the pre-change `sysctl` output in the rollback terminal. Only for this explicitly authorized, bounded trial, temporarily disable receive-checksum offload immediately before redirecting the client:

```sh
sudo sysctl -w net.link.generic.system.hwcksum_rx=0
sysctl net.link.generic.system.hwcksum_rx
```

Stop if the setting did not become `0`. This changes a global Mac setting; restore the recorded original value as soon as the client neighbor override has been removed, before PF cleanup.

Only after the PF checks pass, on Ubuntu reconfirm the direct route and original neighbor MAC. Keep the original OpenCode URL unchanged. Then redirect **only the Ollama neighbor entry** to the verified research Mac MAC:

```sh
sudo ip neigh replace 192.168.1.141 lladdr 7c:d1:ad:b8:5a:8e nud permanent dev wlp2s0
ip neigh show 192.168.1.141 dev wlp2s0
```

First repeat the bounded `/api/version` request to the unchanged Ollama address and require HTTP 200. The first successful trial established this endpoint; a later Ubuntu OpenCode `/v1/chat/completions` request also succeeded and appeared in Requests. For a repeat chat validation, use a small synthetic request with the installed `qwen3.5:9b` model and inspect the GUI and response. Use a short timeout and a harmless prompt. If it succeeds, send one short OpenCode request and record the GUI, response, and PF counters. If it fails, roll back immediately and preserve the HTTP status, PF counter, and GUI observation for diagnosis. Do not change the gateway neighbor mapping.

## Rollback

On Ubuntu, remove the temporary permanent neighbor entry **first**, then confirm the server's own MAC is learned again:

```sh
sudo ip neigh del 192.168.1.141 dev wlp2s0
ip -4 route get 192.168.1.141
curl --max-time 5 http://192.168.1.141:11434/api/version
ip neigh show 192.168.1.141 dev wlp2s0
```

If a one-host route was required after a route change, remove only that route and verify the original selected route. It was **not** required by the most recent direct-route observation.

On the Mac, immediately restore the recorded original checksum value **before beginning PF cleanup**, so a stalled PF cleanup cannot leave the global checksum setting changed:

```sh
sudo sysctl -w net.link.generic.system.hwcksum_rx=ORIGINAL_VALUE
sysctl net.link.generic.system.hwcksum_rx
```

Replace `ORIGINAL_VALUE` with the exact value recorded before this trial; never execute the placeholder. Verify that the output equals that recorded value. If the temporary checksum change was not made, skip the write and verify the baseline only. If restoration fails, keep rollback incomplete and address that failure immediately.

On the Mac, clear only the owned anchor's translation rules first. **Stop and keep the PF enable reference** if the command fails or the follow-up `-sn` output is not empty:

```sh
sudo /sbin/pfctl -a llm_interceptor/lab_demo_20261108 -F nat
sudo /sbin/pfctl -a llm_interceptor/lab_demo_20261108 -sn
```

Only after that check succeeds, clear the owned filter rules. Again, stop and keep the PF reference if the command fails or `-sr` is not empty:

```sh
sudo /sbin/pfctl -a llm_interceptor/lab_demo_20261108 -F rules
sudo /sbin/pfctl -a llm_interceptor/lab_demo_20261108 -sr
```

Close the test client connection, then inspect `sudo /sbin/pfctl -ss` for states involving this trial's client, server, or listener tuple. Rule removal does **not** remove existing states. Wait for those states to close or expire before restoring the main PF ruleset. If they remain, keep the PF reference and inspect them before considering a targeted state removal; never use global `-F states`.

Once both owned rule sets are confirmed empty and the trial's states have cleared, restore the original main ruleset and verify that the only main references are the stock `com.apple/*` ones. Stop and keep the PF reference if restoration or verification fails:

```sh
sudo /sbin/pfctl -f build/demo-pf-original.conf
sudo /sbin/pfctl -sn
sudo /sbin/pfctl -sr
sudo /sbin/pfctl -s References
```

Finally, release **only the token returned by this trial's `-E`** and verify the original disabled/no-reference baseline:

```sh
sudo /sbin/pfctl -X TOKEN_FROM_THIS_TRIAL
sudo /sbin/pfctl -s info | head -n 2
sudo /sbin/pfctl -s References
```

Replace `TOKEN_FROM_THIS_TRIAL` with the actual token; never paste that placeholder as a command. If `-E` did not return a token, skip `-X`. Do not release the reference if any prior cleanup or verification stage failed. Stop the GUI listener. Verify direct OpenCode access to Ollama is restored. If the original neighbor MAC or PF baseline does not return, keep the trial marked incomplete and diagnose that state before another attempt.

If a temporary receive-checksum change was made, restore the recorded original `net.link.generic.system.hwcksum_rx` value and verify it with `sysctl` before declaring rollback complete. The GUI does not own or recover this manual global change.
