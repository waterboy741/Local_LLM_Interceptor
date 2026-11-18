# A3 installed read-only lab smoke

Use a dedicated macOS lab machine or VM with a clean baseline for this service. The ordinary GUI will exercise only **Check helper status**. Leave capture and session controls idle. This procedure uses the system-only helper introduced by commit `05452fe`, the fixed service `org.local-llm-interceptor.helper`, and protocol v1. Run each block separately in the same terminal, starting with a shell as the ordinary user. Stop at the first unexpected result and use the cleanup section for any changes already made.

## Stage and review as an ordinary user

From the repository root, build the GUI, signing preview, and system-only helper for both presets. Use a checkout you have reviewed and record its exact revision. Use Debug as the approved pair and Release as the alternate pair.

```sh
revision=$(git rev-parse --verify HEAD) &&
printf '%s\n' "$revision" &&
cmake --preset debug &&
  cmake --build --preset debug --target llm_interceptor llm_interceptor_read_only_helper mach_service_identity_preview &&
  cmake --preset release &&
  cmake --build --preset release --target llm_interceptor llm_interceptor_read_only_helper mach_service_identity_preview
```

Stage into a new private directory and record its path. Keep both staged copies fixed throughout the smoke.

```sh
umask 077
lab=$(/usr/bin/mktemp -d /private/tmp/llm-interceptor-a3.XXXXXXXX) && (
  printf '%s\n' "$lab" || exit 1
  for variant in debug release; do
    python3 scripts/stage_signed_gui_review.py \
      --app "$PWD/build/$variant/llm_interceptor.app" \
      --preview-tool "$PWD/build/$variant/mach_service_identity_preview" \
      --output-dir "$lab/$variant-gui" &&
    python3 scripts/package_launchd_helper.py \
      --helper "build/$variant/llm_interceptor_read_only_helper" \
      --output-dir "$lab/$variant-service" &&
    python3 scripts/preflight_helper_dependencies.py \
      --helper "$lab/$variant-service/Library/PrivilegedHelperTools/llm_interceptor_helper" &&
    /usr/bin/codesign -d -r- "$lab/$variant-service/Library/PrivilegedHelperTools/llm_interceptor_helper" ||
      exit 1
  done
)
```

Proceed only if the block succeeds and both variants report `a3_helper_dependency_preflight_passed`. Independently review the staged code and provenance before approving the exact hashes. Record the GUI hashes from the disabled staging proposals and the helper hashes from the displayed literal designated requirements. Replace the placeholders below with the four reviewed hexadecimal strings in lowercase.

```sh
approved_gui='DEBUG_GUI_HASH'
approved_helper='DEBUG_HELPER_HASH'
alternate_gui='RELEASE_GUI_HASH'
alternate_helper='RELEASE_HELPER_HASH'

test "$approved_gui" != "$alternate_gui" &&
test "$approved_helper" != "$alternate_helper" &&
python3 scripts/preflight_launchd_helper.py \
  --staged-root "$lab/debug-service" --app "$lab/debug-gui/llm_interceptor.app" \
  --gui-cdhash "$approved_gui" --helper-cdhash "$approved_helper" &&
python3 scripts/preflight_launchd_helper.py \
  --staged-root "$lab/release-service" --app "$lab/release-gui/llm_interceptor.app" \
  --gui-cdhash "$alternate_gui" --helper-cdhash "$alternate_helper"
```

Require two `a3_offline_preflight_passed` results. Record the SHA-256 of the launchd plist from the reviewed Git revision. Compare the staged plist copies byte-for-byte with that revision and prepare the two local policy files.

```sh
git show "${revision}:resources/launchd/org.local-llm-interceptor.helper.plist" > "$lab/reviewed.plist" &&
/usr/bin/cmp "$lab/reviewed.plist" "$lab/debug-service/Library/LaunchDaemons/org.local-llm-interceptor.helper.plist" &&
/usr/bin/cmp "$lab/reviewed.plist" "$lab/release-service/Library/LaunchDaemons/org.local-llm-interceptor.helper.plist" &&
plist_digest=$(/usr/bin/shasum -a 256 < "$lab/reviewed.plist") &&
plist_sha256=${plist_digest%% *} &&
printf '%s\n' "$plist_sha256" &&
printf 'enabled=true\npeer-code-requirement=cdhash H"%s"\n' "$approved_gui" > "$lab/mach-service.conf" &&
printf 'helper-code-requirement=cdhash H"%s"\n' "$approved_helper" > "$lab/helper.identity"
```

**Pause here. Explicitly approve this run's four identity hashes, plist SHA-256, target Mac, and temporary administrator actions below before proceeding.**

## Verify a clean baseline

Keep the GUI under the ordinary account throughout. Use administrator privileges only for the commands marked `sudo`. Record which paths this run actually creates, including whether it creates the shared `PrivilegedHelperTools` directory.

```sh
service=system/org.local-llm-interceptor.helper
tools=/Library/PrivilegedHelperTools
helper=$tools/llm_interceptor_helper
pin=$helper.identity
state=/private/var/db/llm_interceptor
plist=$state/org.local-llm-interceptor.helper.plist
autoload_plist=/Library/LaunchDaemons/org.local-llm-interceptor.helper.plist
staged_helper=Library/PrivilegedHelperTools/llm_interceptor_helper
staged_plist=Library/LaunchDaemons/org.local-llm-interceptor.helper.plist

/bin/launchctl print "$service"
/bin/launchctl print-disabled system
/bin/ls -lde /Library /Library/LaunchDaemons /private /private/var /private/var/db
```

Proceed only if launchd explicitly reports the service missing, with no disabled override for this label. If an inspection cannot be read by the ordinary account, confirm the same read-only inspection as administrator. Confirm the listed directories are real directories, owned by root, with group and world writes disabled, and free of extended ACLs. If `$tools` exists, check it the same way. Confirm that each of `$helper`, `$pin`, `$state`, and `$autoload_plist` is absent, including dangling symlinks. For example, a listing should report "No such file or directory" for each.

```sh
sudo /bin/ls -ld "$helper" "$pin" "$state" "$autoload_plist"
```

Stop if any of these paths exists or if any absence or permission check is ambiguous. Preserve existing installations and any pre-existing state. Copy the staged plist unchanged into the private state directory. The planned path is outside the standard `LaunchDaemons` locations for automatic discovery.

## Start and verify the approved pair

If the baseline showed `/Library/PrivilegedHelperTools` absent, create it with the first command and record that this run owns its creation. Otherwise, skip that command.

```sh
sudo /usr/bin/install -d -o root -g wheel -m 0755 "$tools"
```

```sh
sudo /bin/mkdir -m 0700 "$state" &&
sudo /usr/sbin/chown root:wheel "$state" &&
sudo /usr/bin/install -o root -g wheel -m 0600 "$lab/mach-service.conf" "$state/mach-service.conf" &&
sudo /usr/bin/install -o root -g wheel -m 0644 "$lab/helper.identity" "$pin" &&
sudo /usr/bin/install -o root -g wheel -m 0755 "$lab/debug-service/$staged_helper" "$helper" &&
sudo /usr/bin/install -o root -g wheel -m 0644 "$lab/debug-service/$staged_plist" "$plist"
```

Verify root:wheel ownership, exact modes shown above, and absence of extended ACLs on the created files and state directory. Verify exact bytes and signature before the first privileged helper invocation.

```sh
sudo /bin/ls -lde "$state" "$state/mach-service.conf" "$tools" "$helper" "$pin" "$plist" &&
printf 'enabled=true\npeer-code-requirement=cdhash H"%s"\n' "$approved_gui" |
  sudo /usr/bin/cmp - "$state/mach-service.conf" &&
printf 'helper-code-requirement=cdhash H"%s"\n' "$approved_helper" |
  /usr/bin/cmp - "$pin" &&
/usr/bin/cmp "$lab/debug-service/$staged_helper" "$helper" &&
installed_plist_digest=$(sudo /usr/bin/shasum -a 256 "$plist") &&
test "${installed_plist_digest%% *}" = "$plist_sha256" &&
/usr/bin/codesign --verify --strict --all-architectures "-R=cdhash H\"$approved_helper\"" "$helper"
```

Once the ownership, modes and ACLs have been reviewed, run the state-directory check and bootstrap the exact plist. The check must print `state_directory_ready`. Verify the launchd record points to this run's plist and executable.

```sh
sudo "$helper" --check-state-dir "$state" &&
sudo /bin/launchctl bootstrap system "$plist" &&
/bin/launchctl print "$service"
```

Finish cleanup before rebooting or ending the lab session. After an interruption or reboot, resume at cleanup and inspect the service before removing files. The staged plist and other files still need removal.

Open a second ordinary-user terminal for GUI invocations and assign the recorded private staging path to `lab` there. Launch the actual executable so each test exercises the selected signature. In every instance, click **Check helper status**, wait for the final text, record it, and quit the GUI before the next instance.

```sh
"$lab/debug-gui/llm_interceptor.app/Contents/MacOS/llm_interceptor"
```

Require **Helper identity verified — state: inactive (protocol v1).** Its first launch may occur during this check. After each successful or rejected status check, inspect `/bin/launchctl print "$service"` and record any PID shown for this exact service. After each bootout, verify the service record is gone and any recorded helper PID has exited. To inspect one PID, use `/bin/ps -p "$recorded_pid" -o pid=,user=,command=` after setting `recorded_pid` from the service record. If that helper is still running or its exit is unclear, stop and inspect before replacing or deleting files.

## Reject both alternate builds

1. With the approved helper, config and pin in place, run the alternate GUI directly as the ordinary user.

   ```sh
   "$lab/release-gui/llm_interceptor.app/Contents/MacOS/llm_interceptor"
   ```

   Require **Helper status check timed out.** The helper silently drops unauthenticated requests. Quit the alternate GUI, rerun the approved GUI, and require the verified status again to confirm the service remained reachable. An identity configuration error or unavailable endpoint is inconclusive.

2. With both GUIs closed, unload the exact service target. Confirm `launchctl print "$service"` explicitly reports it missing before replacing the executable. Keep the original config and GUI pin in place.

   ```sh
   sudo /bin/launchctl bootout "$service"
   /bin/launchctl print "$service"
   ```

3. Install the already reviewed alternate helper, verify its ownership and mode, verify its exact bytes and signature, and restart the same service.

   ```sh
   sudo /usr/bin/install -o root -g wheel -m 0755 "$lab/release-service/$staged_helper" "$helper" &&
   /bin/ls -lde "$helper" &&
   /usr/bin/cmp "$lab/release-service/$staged_helper" "$helper" &&
   /usr/bin/codesign --verify --strict --all-architectures "-R=cdhash H\"$alternate_helper\"" "$helper"
   ```

   Require root:wheel, mode `0755`, and no extended ACL before restarting the service.

   ```sh
   sudo /bin/launchctl bootstrap system "$plist" &&
   /bin/launchctl print "$service"
   ```

   Launch the approved GUI as the ordinary user. Require **Helper identity does not match the configured requirement.** An unavailable endpoint or timeout is inconclusive for this direction. Quit the GUI.

4. Boot out the exact service again and confirm it is absent. Restore the approved helper with the commands in step 3, substituting `debug-service` and `approved_helper`. Verify ownership and signature, bootstrap the exact plist again, and require the approved GUI's verified status.

## Roll back and verify

Quit the GUIs. If the service is registered, boot out only this service and verify it is missing. If it was never registered or is already absent, verify absence and skip bootout. Stop if bootout fails and the service still appears or if its status is ambiguous.

```sh
sudo /bin/launchctl bootout "$service"
/bin/launchctl print "$service"
```

For a completed smoke, retain the pin briefly and use the approved GUI to confirm that no helper status can be verified after bootout. Then quit it and remove only the files this run created. On a partial setup, run only the individual removal commands for files recorded as created by this run.

```sh
sudo /bin/rm "$plist" &&
sudo /bin/rm "$helper" &&
sudo /bin/rm "$pin" &&
sudo /bin/rm "$state/mach-service.conf" &&
sudo /bin/rmdir "$state"
```

If this run created `$tools`, use `sudo /bin/rmdir "$tools"` to remove it only if empty. If either directory has unexpected content, preserve it for inspection. Rerun the initial service, override and filesystem checks and confirm the results match the baseline. Record the revision, four identity hashes, plist SHA-256, GUI status observations, and final absence checks. Keep the private staging directory until the evidence is recorded. The local staging files can then be removed independently of system cleanup.

Use the Apple reference for service targets and command semantics. [Apple launchctl manual](https://github.com/apple-oss-distributions/launchd/blob/main/man/launchctl.1)
