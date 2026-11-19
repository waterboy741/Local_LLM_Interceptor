# Installed-helper transparent session runbook (live lab)

Procedure and evidence checklist for the staged M6 lab only. This is a research capture/redirection tool; run it exclusively on the authorized lab topology. Sanitized results only — never commit prompts, captures, credentials, or machine-specific configuration. The commands below were exercised on November 18, 2026 on the lab topology research Mac `en0` `192.168.1.16`, client `192.168.1.169`, Ollama `192.168.1.141:11434`; recheck every address before each run.

## Stage and sign

1. Build the GUI: `cmake --build --preset debug` (or release). Stage the app bundle where the pinned cdhash matches the configured requirement.
2. Build the helper root binary: `cmake --build --preset debug` and locate `llm_interceptor_read_only_helper`. Ad-hoc/sign it exactly as provisioned; the helper pins the GUI's exact cdhash and the GUI pins the helper's.
3. Preflights: helper `--check-state-dir` must pass on the trusted state directory; GUI launches normally with no session active.

## Provision the installed helper

```sh
# trusted, root-owned state directory (adjust to the documented install location)
sudo install -d -o root -g wheel -m 700 /var/db/llm_interceptor
# 3-line operator gate config (exact 40-hex GUI cdhash)
sudo sh -c 'printf "enabled=true\npeer-code-requirement=cdhash H\"<GUI-CDHASH>\"\nsession-control=true\n" \
  > /var/db/llm_interceptor/mach-service.conf'
sudo launchctl bootstrap system /Library/LaunchDaemons/org.local-llm-interceptor.helper.plist
```

Expectation: on-demand launch pulls no visible output; the GUI's **Check helper status** must print `Helper identity verified — state: inactive (protocol v1)`. Any differently built GUI is refused (connection closed, no reply).

## PF attachment references (required)

Transparent interception requires the `llm_interceptor/*` references in the **main** ruleset. Without them, redirected traffic is IP-forwarded and never reaches the interceptor — the helper does not yet verify attachment references before Start (open hardening item; see [SCOPED_OPERATION_INTEGRATION.md](SCOPED_OPERATION_INTEGRATION.md)).

```sh
sudo /sbin/pfctl -s rules | grep -c llm_interceptor   # expect the merged references
```

Merge with `pf_attachment_prepare`/merge tools (syntax-validated, non-persistent load), keeping a rollback backup of `/etc/pf.conf`. Deliberately keep the anchor references out of any persistent config until the persistent-load policy is decided.

## Warm neighbors (fail-closed precondition)

Both peer entries must resolve on the session interface immediately before Start:

```sh
/usr/sbin/arp -n 192.168.1.169    # client, must show "on en0"
/usr/sbin/arp -n 192.168.1.141    # upstream, must show "on en0"
```

Cold or stale entries reject Start with `neighbor_identity_unavailable` by design; ping each peer first.

## GUI transparent Start

1. Configuration tab: prepare an interface configuration (physical interface, client, upstream, ports).
2. Transparent session tab: **Start**. Expect the state to pass `start` → `active`. A bounded reject reason names the failing boundary; the helper log carries one `llm_interceptor.scoped-phase … duration_ms=` line per phase on Start and Stop.
3. Client/OpenCode sends to the **unchanged** Ollama URL; the request must appear in GUI **Requests**; manual modification delivers the edited payload to the client.

## Capture checklist (during the active session)

```sh
/usr/sbin/arp -n 192.168.1.141                # client rows: research MAC present for client mapping
sudo /sbin/pfctl -s References                # captured token listed (expect pfctl notices on stderr)
sudo /sbin/pfctl -s nat -a llm_interceptor/<key> -v   # owned rdr evaluation
ssh client 'ip neigh | grep 192.168.1.141'    # client sees: server IP at research-MAC MAC
```

## Stop and restoration checks

GUI **Stop**, then verify: client `ip neigh` shows the original server MAC restored; `pfctl -s References` shows the token released (`No pf starter references held` is this build's empty state); the anchor's `nat`/`rules` listings are verified empty; the obligations journal in the state directory is empty/absent. Main-ruleset anchor reference rows deliberately remain.

## Troubleshooting

| Symptom | Meaning / action |
| --- | --- |
| `neighbor_identity_unavailable` | Peer neighbor rows cold/stale. Warm them and retry; fail-closed by design. |
| `recovery_pending` | Journal obligations outstanding. A named token reconciles automatically on the next Start; an **unnamed** (`pf-token-uncertain`) record has no verifiable release: note it, `sudo /sbin/pfctl -X <token-if-known>`, then remove the journal record per the operator path and retry. |
| `journal_unavailable` / `pf_reference_uncertain` | Historical fixed defects (fd lifetime, stderr-mode pfctl parsing); on the current build re-run and capture the helper log. If it recurs, preserve the journal and `llm_interceptor.scoped-uncertain` preview line before any manual action. |
| `hwcksum` receive errors on the client | Set `sudo sysctl net.link.generic.system.hwcksum_rx=0` (lab fallback used November 18); restore to `1` afterwards. Default-checksum operation is unverified. |
| Helper wedges at 100% CPU | A historical fixed defect (stdio-drain spin). If it recurs, capture the phase log tail, SIGKILL, release the token (`pfctl -X`), reconcile via the journal, and report. |

## Manual recovery order (teardown with journal first)

1. Read the journal records (token, anchor, settings restores) in the trusted state directory.
2. Verify/remove any anchor: `sudo pfctl -a llm_interceptor/<key> -F nat; sudo pfctl -a … -F rules`, then verify empty listings.
3. Restore kernel settings if journaled (`net.inet.ip.forwarding`, `net.inet.ip.redirect`).
4. Release the exact token: `sudo /sbin/pfctl -X <token>` and confirm absence.
5. Only then remove/clear the journal record — never before every obligation is verified.

## Uninstall / restore baseline

GUI config frozen? Stop session first. `sudo launchctl bootout system/org.local-llm-interceptor.helper`, remove the LaunchDaemon plist and state directory, restore `hwcksum_rx=1`, reload the saved PF configuration, and confirm `pfctl -s References` shows no starter references.
