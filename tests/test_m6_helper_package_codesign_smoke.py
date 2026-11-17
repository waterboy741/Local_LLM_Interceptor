"""Stage the built macOS helper and verify its embedded code signature."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PACKAGER_PATH = REPOSITORY_ROOT / "scripts/package_launchd_helper.py"
DEPENDENCY_PREFLIGHT = REPOSITORY_ROOT / "scripts/preflight_helper_dependencies.py"
PLIST_NAME = "org.local-llm-interceptor.helper.plist"
PLIST_PATH = REPOSITORY_ROOT / "resources/launchd" / PLIST_NAME
STAGED_HELPER = Path("Library/PrivilegedHelperTools/llm_interceptor_helper")
STAGED_PLIST = Path("Library/LaunchDaemons") / PLIST_NAME
CODESIGN = "/usr/bin/codesign"


def run_command(*command: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=REPOSITORY_ROOT,
        env={**os.environ, "LC_ALL": "C"},
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )


def run_checked(*command: str) -> subprocess.CompletedProcess[str]:
    result = run_command(*command)
    if result.returncode != 0:
        raise AssertionError(
            f"{command!r} exited with {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--expect-non-system-runtime", action="store_true")
    options = parser.parse_args()
    helper = options.helper.resolve(strict=True)
    original_bytes = helper.read_bytes()
    original_stat = helper.stat()
    original_plist = PLIST_PATH.read_bytes()

    with tempfile.TemporaryDirectory(
        prefix="helper-codesign-smoke-", dir="/private/tmp"
    ) as temporary_directory:
        stage = Path(temporary_directory)
        run_checked(
            sys.executable,
            str(PACKAGER_PATH),
            "--helper",
            str(helper),
            "--output-dir",
            str(stage),
        )

        staged_entries = {path.relative_to(stage) for path in stage.rglob("*")}
        expected_entries = {
            Path("Library"),
            STAGED_HELPER.parent,
            STAGED_PLIST.parent,
            STAGED_HELPER,
            STAGED_PLIST,
        }
        require(staged_entries == expected_entries, f"unexpected staging tree: {staged_entries}")
        for directory in (Path("Library"), STAGED_HELPER.parent, STAGED_PLIST.parent):
            require(stat.S_ISDIR((stage / directory).lstat().st_mode), f"not a directory: {directory}")

        staged_helper = stage / STAGED_HELPER
        staged_plist = stage / STAGED_PLIST
        for path, mode in ((staged_helper, 0o755), (staged_plist, 0o644)):
            staged_mode = path.lstat().st_mode
            require(stat.S_ISREG(staged_mode), f"not a regular file: {path}")
            require(stat.S_IMODE(staged_mode) == mode, f"expected mode {mode:o}: {path}")

        preflight = run_command(sys.executable, str(DEPENDENCY_PREFLIGHT), "--helper", str(staged_helper))
        if options.expect_non_system_runtime:
            expected_rejections = {
                "a3_helper_dependency_preflight_error: helper has a non-system dynamic dependency\n",
                "a3_helper_dependency_preflight_error: helper declares an unsupported runtime search path or environment override\n",
            }
            require(
                preflight.returncode == 1 and not preflight.stdout
                and preflight.stderr in expected_rejections,
                f"expected non-system runtime rejection, got {preflight!r}",
            )
        else:
            require(
                preflight.returncode == 0 and not preflight.stderr
                and preflight.stdout == "a3_helper_dependency_preflight_passed\n",
                f"expected system-only dependency preflight success, got {preflight!r}",
            )
        verify = (CODESIGN, "--verify", "--strict", "--all-architectures")
        run_checked(*verify, str(staged_helper))
        displayed = run_checked(CODESIGN, "-d", "-r-", str(staged_helper))
        designated_lines = re.findall(
            r"^(?:# )?designated\b[^\r\n]*",
            f"{displayed.stdout}\n{displayed.stderr}",
            re.MULTILINE,
        )
        require(
            len(designated_lines) == 1,
            f"expected one designated requirement, got {designated_lines!r}",
        )
        literal = re.fullmatch(
            r'(?:# )?designated => (cdhash H"([0-9a-fA-F]{40}|[0-9a-fA-F]{64})")',
            designated_lines[0],
        )
        if literal is None:
            raise AssertionError(f"expected a literal cdhash requirement: {designated_lines[0]!r}")
        requirement, cdhash = literal.groups()
        run_checked(*verify, f"-R={requirement}", str(staged_helper))

        wrong_nibble = "1" if cdhash[0] == "0" else "0"
        wrong_requirement = f'cdhash H"{wrong_nibble}{cdhash[1:]}"'
        rejected = run_command(*verify, f"-R={wrong_requirement}", str(staged_helper))
        require(
            rejected.returncode > 0 and "test-requirement:" in rejected.stderr,
            f"expected cdhash mismatch rejection, got exit {rejected.returncode}\n"
            f"stdout: {rejected.stdout}\nstderr: {rejected.stderr}",
        )
        unsigned_helper = stage / "unsigned-review-copy"
        shutil.copyfile(staged_helper, unsigned_helper)
        run_checked(CODESIGN, "--remove-signature", str(unsigned_helper))
        rejected_unsigned = run_command(*verify, f"-R={requirement}", str(unsigned_helper))
        require(
            rejected_unsigned.returncode > 0 and "not signed" in rejected_unsigned.stderr,
            f"expected unsigned helper rejection, got exit {rejected_unsigned.returncode}\n"
            f"stdout: {rejected_unsigned.stdout}\nstderr: {rejected_unsigned.stderr}",
        )

        for args in (
            ("--process",),
            ("--mach-service", "--state-dir", str(stage)),
            ("--mach-service", "--state-dir", "/private/var/db/llm_interceptor", "--extra"),
        ):
            refused = run_command(str(staged_helper), *args)
            require(
                refused.returncode == 2 and not refused.stdout and refused.stderr.startswith("usage:"),
                f"expected unsupported invocation rejection for {args!r}, got {refused!r}",
            )
        if os.geteuid() != 0:
            denied = run_command(
                str(staged_helper), "--mach-service", "--state-dir", "/private/var/db/llm_interceptor"
            )
            require(
                denied.returncode == 3 and not denied.stdout and denied.stderr == "effective_root_required\n",
                f"expected privilege rejection, got {denied!r}",
            )

        require(staged_helper.read_bytes() == original_bytes, "staged helper bytes differ")
        require(staged_plist.read_bytes() == original_plist, "staged plist bytes differ")

        current_stat = helper.stat()
        require(current_stat.st_ino == original_stat.st_ino, "source helper was replaced")
        require(current_stat.st_mode == original_stat.st_mode, "source helper mode changed")
        require(current_stat.st_mtime_ns == original_stat.st_mtime_ns, "source helper was modified")
        require(helper.read_bytes() == original_bytes, "source helper bytes changed")
        require(PLIST_PATH.read_bytes() == original_plist, "source plist bytes changed")


if __name__ == "__main__":
    main()
