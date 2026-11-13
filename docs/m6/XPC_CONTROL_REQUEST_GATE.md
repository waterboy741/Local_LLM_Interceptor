# XPC control request gate

`XpcControlRequestGate` pins the trusted code requirement from local configuration. It authenticates each actual XPC dictionary message before reading its fields. In helper Mach service mode, the Security.framework policy checks the sender's code signature using the message's kernel-bound identity.

After authentication, the parser accepts exactly one key, `operation`, with a string value of `probe` or `status` (at most 16 bytes). It returns a typed operation and rejects extra keys, wrong types, invalid strings, and unsupported operations. The gate borrows the message for synchronous inspection. The injected policy must outlive the gate, and callers must serialize `parse` calls.

`XpcReadOnlyControlAdapter` returns fixed fields for authenticated requests. Both replies include `ok`, the service label, and protocol version. A `status` reply adds the constant state `inactive`. Rejected messages receive no reply. This service has no session capability or Start, Heartbeat, Stop, PF, or ARP operation.

`XpcReadOnlyServiceListener` requires a valid service name and a trusted code requirement. It caps concurrent peers at 16, accepted peers at 256 per run, dictionary messages at 128 per peer, and total dictionary messages at 4096 per run. A new connection or message beyond its corresponding run cap closes the listener. The helper's root-gated `--mach-service` mode wires the listener for `org.local-llm-interceptor.helper` when explicitly enabled with a local code requirement. The launchd plist is a review artifact and there is no default trusted GUI identity. See [the helper bootstrap contract](INSTALLED_HELPER_BOOTSTRAP.md).

`XpcReadOnlyServiceClient` sends only `probe` or `status` to that fixed service and accepts only the exact reply fields and values. Each request has a 1–5000 ms deadline (1500 ms by default) and distinguishes timeout, unavailable service, connection failure, and malformed reply. The GUI's **Check helper status** button sends one `status` request asynchronously. It displays availability, the returned state and protocol version on success, or an unavailable, timeout, or failure message. An `inactive` reply confirms the read-only endpoint responded.

Offline tests cover authentication and rejection with injected peer policies, fixed replies, configuration rejection, anonymous native endpoint round trips, deadline/error handling, exact reply validation, and GUI status handling with injected results. Launchd registration, real code-signature enforcement, and live enforcement of peer and request caps remain unverified.
