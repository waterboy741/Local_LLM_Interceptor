# XPC control request gate

`XpcControlRequestGate` owns a copy of the trusted code requirement supplied by local configuration when the gate is constructed. For each received XPC dictionary message, it passes that exact message and pinned requirement to the injectable `XpcPeerCodeSignaturePolicy` before reading any protocol fields.

After authentication, the parser accepts exactly one dictionary key, `operation`, with a string value of `probe` or `status` (at most 16 bytes). It returns only the bounded `XpcControlOperation` enum. Extra keys, wrong value types, empty or oversized strings, and unsupported operations fail closed. The XPC message is borrowed and inspected synchronously. The injected policy must outlive the gate, and the caller must serialize `parse` calls. The gate does not encode a reply, dispatch to a host, carry a capability, or call PF, ARP, or other system operations. Start, Heartbeat, and Stop are not accepted.

This is a reusable authentication and request-parsing boundary, not a registered Mach service. It has no launchd listener or event callback, no serialized response contract, no GUI/helper rendezvous, and no production code-signing identity default. The caller must source the requirement from trusted local configuration and pass the actual inbound XPC message. It does not complete installed-helper acceptance or authorize network mutation.
