# Privileged helper bootstrap contract

The build produces `llm_interceptor_helper`, a separate command-line executable. Its `--check-state-dir` mode performs a read-only state-directory check and exits. The `--process --state-dir PATH --bootstrap-fd FD` entrypoint validates the root-owned private directory, then deliberately exits with `production_peer_authenticator_unavailable` (code 5). It does not read the supplied descriptor, start a host, open a control socket, or mutate PF or ARP. Do not load it as a persistent launchd service or claim the installed-helper gate is met yet.

`InstalledHelperProcessBootstrap::create` is the injectable process seam: it opens and retains the private state-directory descriptor, authenticates and receives the handoff on one connected Unix socket, derives kernel UID/GID credentials from that same socket, and calls `LeasedHelperHost::createFromBootstrap`. It exposes explicit host start and one-time credentials retrieval. Its injected operations factory is responsible for the mandatory fresh pre-mutation gate; the production executable does not instantiate this seam until a production authenticator and gated backend are available. The factory must wipe any secret copy it retains. The transferred snapshot cannot recheck GUI-owned listener readiness. This seam does not install a service, create the GUI/helper rendezvous, or provide a live backend.

`MacXpcPeerCodeSignaturePolicy` asks Security.framework to resolve the sender from the message's kernel-associated audit token and validates the code against an explicit code requirement. `XpcControlRequestGate` pins a copy of that requirement at construction and authenticates each actual inbound message before parsing. It accepts only a single `operation` string with value `probe` or `status`. `XpcReadOnlyControlAdapter` returns fixed bounded probe/status replies, and `XpcReadOnlyServiceListener` provides a native event-listener foundation with peer and request limits.

The helper also has an opt-in `--mach-service --state-dir PATH` mode. It remains root-gated and requires `mach-service.conf` inside the already validated root-owned `0700` state directory. The config file must be a root-owned regular file with exact mode `0600`, opened relative to the validated directory descriptor without following symlinks. Its strict format is exactly two ordered lines (an optional final newline is allowed):

```text
enabled=false
peer-code-requirement=anchor apple
```

This example remains disabled; `anchor apple` is only a parser-valid fixture and is not an acceptable GUI identity policy. `enabled=false` fails closed. The requirement is bounded to 1024 UTF-8 bytes, rejects control characters, and must compile as a Security.framework code requirement. The service name is fixed as `org.local-llm-interceptor.helper`; it cannot come from config, the GUI, or an XPC message. A local administrator must replace the example requirement with the reviewed identity of the signed GUI client and explicitly set `enabled=true`. No Developer ID identity is available in this checkout, so no usable production identity is bundled.

`mach_service_identity_preview --app /absolute/path/to/llm_interceptor.app` is a read-only way to prepare the peer requirement for review. It accepts only the expected app bundle and executable path, runs `/usr/bin/codesign --verify --strict --deep`, and reads a single literal `designated => cdhash H"…"` requirement from `codesign -d -r-`. Any signature error, timeout, excess output, unexpected output, alternate requirement form, symlinked bundle component, or identity/path mismatch fails closed. It checks the executable's filesystem identity and modification time around both `codesign` calls and rejects detected changes. This narrows path replacement during preview but cannot eliminate every race, such as replacement while restoring the same observable metadata. On success, standard output is exactly the two-line config format above, with `enabled=false`; redirecting it is optional and is the user's own file operation. The tool does not create a file, change permissions, install or enable the helper, or alter system configuration. This is an advisory review aid: strict verification checks code integrity and does not identify or vouch for a publisher, while a cdhash only pins the exact executable bytes. With no Developer ID/team identity available, the administrator must trust the selected review build and independently establish its provenance. Before enabling any separately provisioned config, reverify the signature and exact cdhash of the app at installation against the reviewed build. The current linker ad-hoc debug app may fail strict bundle verification; do not weaken this check to make it pass. Use a fully valid, locally signed review build. The cdhash changes whenever the app executable is rebuilt or re-signed, so generate and review a fresh proposal for each exact build that will be installed. The proposal never enables the service and still requires administrator review of the exact installed build.

The repository contains a review artifact at [`resources/launchd/org.local-llm-interceptor.helper.plist`](../../resources/launchd/org.local-llm-interceptor.helper.plist). Its fixed `ProgramArguments` invoke `/Library/PrivilegedHelperTools/llm_interceptor_helper --mach-service --state-dir /private/var/db/llm_interceptor`; its sole `MachServices` key is `org.local-llm-interceptor.helper`, and launchd is asked to run it as `root:wheel`. This plist is not installed, bootstrapped, or enabled by the repository tooling.

The non-installing package script checks the plist's exact keys and values, then can stage a built helper and the plist under a caller-selected review directory. For example, after a local build:

```sh
python3 scripts/package_launchd_helper.py --validate-only
python3 scripts/package_launchd_helper.py \
  --helper build/debug/llm_interceptor_helper \
  --output-dir /private/tmp/llm-interceptor-launchd-review
```

The staging directory must be an absolute, empty or new path outside macOS system locations. The helper is staged with mode `0755` and the plist with mode `0644`, preserving their intended relative locations under `/Library`. The script does not sign, install, bootstrap, enable, unload, or remove a service. Review the staged files before any separately authorized installation work.

Before installation, review the helper's signature and ownership and provision the exact signed GUI identity as described above. The staged plist has not been loaded into launchd. Even with valid configuration, Mach service mode returns only read-only probe/status replies: it starts no helper host, accepts no capability, and authorizes no PF or ARP. The `--process` mode still fails closed. See [XPC control request gate](XPC_CONTROL_REQUEST_GATE.md).

The intended lab installation uses a system launch daemon, not a root GUI. The executable path is `/Library/PrivilegedHelperTools/llm_interceptor_helper`, intended to be owned by `root:wheel` with mode `0755`. Its private state directory is `/private/var/db/llm_interceptor`, owned by `root:wheel` with mode `0700`. A GUI process running as an ordinary user cannot traverse that directory to connect to a socket beneath it, so the GUI/helper rendezvous location and ownership must be designed before adding a control listener. The plist under `/Library/LaunchDaemons` is only an uninstalled artifact; installation remains gated on that rendezvous, full startup and cleanup, code-signature authentication, and gated capability handoff. Kernel UID/GID credentials alone do not prove GUI identity.

For a read-only preflight after manually staging the executable and private directory, run:

```sh
sudo /Library/PrivilegedHelperTools/llm_interceptor_helper --check-state-dir /private/var/db/llm_interceptor
```

The command requires effective root and checks the directory's absolute canonical path, root ownership, exact `0700` mode, stable inode, and close-on-exec descriptor. The installer remains responsible for the `wheel` group; the checker does not inspect group ownership because mode `0700` grants it no access. It prints `state_directory_ready` only after those checks. The same opened descriptor is intended for the host lease and both PF journals when the service factory is wired. This check makes no PF or ARP call and does not establish recovery readiness.

There is no supported service installation or uninstall command. The package script only creates a review directory and never loads launchd. If a future separately approved installation is removed, unload that exact service using the reviewed macOS procedure, then remove only `/Library/LaunchDaemons/org.local-llm-interceptor.helper.plist` and `/Library/PrivilegedHelperTools/llm_interceptor_helper`. Preserve `/private/var/db/llm_interceptor` until every journal and recovery obligation has been inspected and reconciled. Never issue global `pfctl -d` during uninstall.
