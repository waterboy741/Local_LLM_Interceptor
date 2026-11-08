# Privileged helper bootstrap contract

The build produces `llm_interceptor_helper`, a separate command-line executable. It currently performs only a read-only state-directory check and exits. It does not run as a daemon, start `LeasedHelperHost`, open a control socket, or mutate PF or ARP. Do not load it as a persistent launchd service or claim the installed-helper gate is met yet.

The offline `LeasedHelperHost::createFromBootstrap` seam can now adopt a `TrustedBootstrapHandoff`: it acquires the host lease, passes the transferred snapshot and probe secret to an injected operations factory, wipes its local secret copy, and creates a separate command capability for the helper session. Synthetic tests cover adoption followed by Start, Heartbeat, and Stop. The caller remains responsible for proving that the supplied `VerifiedPeer` is the same GUI peer authenticated on the handoff socket; the API does not establish that binding. The factory must wipe any secret copy it retains. This seam cannot recheck GUI-owned listener readiness and does not itself run the pre-mutation gate. It is not called from `llm_interceptor_helper` and does not implement a process loop, installed service, production authenticator, or live backend.

The intended lab installation uses a system launch daemon, not a root GUI. The eventual executable path is `/Library/PrivilegedHelperTools/llm_interceptor_helper`, owned by `root:wheel` with mode `0755`. Its private state directory is `/private/var/db/llm_interceptor`, owned by `root:wheel` with mode `0700`; the eventual local control socket is `/private/var/db/llm_interceptor/llm_interceptor.helper.sock`, mode `0600`. A launch daemon plist under `/Library/LaunchDaemons` will be added only when the service has a full startup, cleanup, and authenticated capability handoff. This design does not treat same-UID kernel credentials as proof of GUI identity.

For a read-only preflight after manually staging the executable and private directory, run:

```sh
sudo /Library/PrivilegedHelperTools/llm_interceptor_helper --check-state-dir /private/var/db/llm_interceptor
```

The command requires effective root and checks the directory's absolute canonical path, root ownership, exact `0700` mode, stable inode, and close-on-exec descriptor. The installer remains responsible for the `wheel` group; the checker does not inspect group ownership because mode `0700` grants it no access. It prints `state_directory_ready` only after those checks. The same opened descriptor is intended for the host lease and both PF journals when the service factory is wired. This check makes no PF or ARP call and does not establish recovery readiness.

There is no supported service installation or uninstall step yet. For a manually staged preflight binary, remove only the staged binary after use. Do not remove the private directory if any journal or recovery obligation exists; inspect and reconcile that state first. Never issue global `pfctl -d` during uninstall.
