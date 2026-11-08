# Helper-side pre-mutation revalidation

`HelperPreMutationGate::verify()` is an offline, read-only gate for a future installed helper. Given a previously authenticated `SessionSnapshot` and listener probe secret, it obtains fresh observations from injected adapters in this order:

1. Revalidate the snapshot structure and 32-byte probe secret.
2. Read the selected interface's current MAC, research IPv4 address, and prefix; compare all three with the snapshot.
3. Run bounded route/neighbor diagnostics for the exact client and server IPv4 addresses; require recognized direct routes on the selected interface and resolved neighbors on that interface.
4. Independently observe the client and server neighbor MACs and require exact identity matches.
5. Connect to the exact upstream server from the research source address, then check that PF is enabled and both dedicated main-ruleset attachment references are active.
6. Run the nonce/HMAC transparent listener probe against the exact interface/client/upstream/listener tuple last.

Every failed, unknown, or throwing observation blocks readiness with a specific status code. The gate does not mutate PF, ARP, interfaces, or routing. The upstream TCP check may create a remote connection or log entry. Its successful result is only point-in-time evidence and cannot be cached as mutation authority.

The exact neighbor-identity verifier remains injectable for tests, and the production read-only adapter is now composed; no installed-helper call site exists. The prior GUI-provided `authorized`, `proxyReady`, and `anchorAttached` booleans are historical and do not substitute for these fresh checks. The future helper must also enforce its root-owned lease and journal recovery order, authenticate the GUI through a production code-signature verifier, and call this gate immediately before each PF install. A successful offline test does not authorize live PF or ARP mutation.

The production dependency bundle `systemHelperPreMutationDependencies()` now binds the system interface probe, the same typed macOS route/neighbor command runner used by the exact MAC verifier, the typed read-only PF query runner, and the loopback listener challenge verifier. The bundle is only a set of read-only references; it grants no root privilege, host lease, anchor ownership, or permission to mutate. The original injected overload remains available for deterministic tests. No installed-helper call site invokes this bundle yet.
