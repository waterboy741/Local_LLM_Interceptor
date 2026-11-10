# Privileged helper bootstrap contract

The build produces `llm_interceptor_helper`, a separate command-line executable. Its `--check-state-dir` mode performs a read-only state-directory check and exits. The new `--process --state-dir PATH --bootstrap-fd FD` entrypoint validates the root-owned private directory, then deliberately exits with `production_peer_authenticator_unavailable` (code 5). It does not read the supplied descriptor, start a host, open a control socket, or mutate PF or ARP. Do not load it as a persistent launchd service or claim the installed-helper gate is met yet.

`InstalledHelperProcessBootstrap::create` is the injectable process seam: it opens and retains the private state-directory descriptor, authenticates and receives the handoff on one connected Unix socket, derives kernel UID/GID credentials from that same socket, and calls `LeasedHelperHost::createFromBootstrap`. It exposes explicit host start and one-time credentials retrieval. Its injected operations factory is responsible for the mandatory fresh pre-mutation gate; the production executable does not instantiate this seam until a production authenticator and gated backend are available. The factory must wipe any secret copy it retains. The transferred snapshot cannot recheck GUI-owned listener readiness. This seam does not install a service, create the GUI/helper rendezvous, or provide a live backend.

`MacXpcPeerCodeSignaturePolicy` asks Security.framework to resolve the sender from the message's kernel-associated audit token and validates the code against an explicit code requirement. `XpcControlRequestGate` pins a copy of that requirement at construction and authenticates each actual inbound message before parsing. It accepts only a single `operation` string with value `probe` or `status`. `XpcReadOnlyControlAdapter` returns fixed bounded probe/status replies, and `XpcReadOnlyServiceListener` provides a native event-listener foundation with peer and request limits.

The helper also has an opt-in `--mach-service --state-dir PATH` mode. It remains root-gated and requires `mach-service.conf` inside the already validated root-owned `0700` state directory. The config file must be a root-owned regular file with exact mode `0600`, opened relative to the validated directory descriptor without following symlinks. Its strict format is exactly two ordered lines (an optional final newline is allowed):

```text
enabled=false
peer-code-requirement=anchor apple
```

This example remains disabled; `anchor apple` is only a parser-valid fixture and is not an acceptable GUI identity policy. `enabled=false` fails closed. The requirement is bounded to 1024 UTF-8 bytes, rejects control characters, and must compile as a Security.framework code requirement. The service name is fixed as `org.local-llm-interceptor.helper`; it cannot come from config, the GUI, or an XPC message. A local administrator must replace the example requirement with the reviewed identity of the signed GUI client and explicitly set `enabled=true`. No Developer ID identity is available in this checkout, so no usable production identity is bundled.

There is still no launch daemon plist, installer, or enabled service configuration in the repository. To run this mode, launchd must bind `org.local-llm-interceptor.helper` under the same `MachServices` key in a reviewed system LaunchDaemon plist and invoke the staged helper with `--mach-service --state-dir /private/var/db/llm_interceptor`. Do not install or enable such a plist until the local signed-client requirement has been reviewed. When enabled, the listener returns only fixed read-only probe/status replies. It does not start a helper host, accept a capability, or authorize PF or ARP. The existing `--process` mode continues to fail closed. See [XPC control request gate](XPC_CONTROL_REQUEST_GATE.md).

The intended lab installation uses a system launch daemon, not a root GUI. The eventual executable path is `/Library/PrivilegedHelperTools/llm_interceptor_helper`, owned by `root:wheel` with mode `0755`. Its private state directory is `/private/var/db/llm_interceptor`, owned by `root:wheel` with mode `0700`. A GUI process running as an ordinary user cannot traverse that directory to connect to a socket beneath it, so the eventual GUI/helper rendezvous location and ownership must be designed before adding a control listener. A launch daemon plist under `/Library/LaunchDaemons` will be added only after that rendezvous, full startup and cleanup, code-signature authentication, and gated capability handoff are implemented. Kernel UID/GID credentials alone do not prove GUI identity.

For a read-only preflight after manually staging the executable and private directory, run:

```sh
sudo /Library/PrivilegedHelperTools/llm_interceptor_helper --check-state-dir /private/var/db/llm_interceptor
```

The command requires effective root and checks the directory's absolute canonical path, root ownership, exact `0700` mode, stable inode, and close-on-exec descriptor. The installer remains responsible for the `wheel` group; the checker does not inspect group ownership because mode `0700` grants it no access. It prints `state_directory_ready` only after those checks. The same opened descriptor is intended for the host lease and both PF journals when the service factory is wired. This check makes no PF or ARP call and does not establish recovery readiness.

There is no supported service installation or uninstall step yet. For a manually staged preflight binary, remove only the staged binary after use. Do not remove the private directory if any journal or recovery obligation exists; inspect and reconcile that state first. Never issue global `pfctl -d` during uninstall.
