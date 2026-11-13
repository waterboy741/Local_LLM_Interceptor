"""Stage the built macOS helper and verify its embedded code signature."""

from __future__ import annotations

import argparse
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PACKAGER_PATH = REPOSITORY_ROOT / "scripts/package_launchd_helper.py"
PLIST_NAME = "org.local-llm-interceptor.helper.plist"
PLIST_PATH = REPOSITORY_ROOT / "resources/launchd" / PLIST_NAME
STAGED_HELPER = Path("Library/PrivilegedHelperTools/llm_interceptor_helper")
STAGED_PLIST = Path("Library/LaunchDaemons") / PLIST_NAME


def run_checked(*command: str) -> None:
    result = subprocess.run(
        command,
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"{command!r} exited with {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", type=Path, required=True)
    helper = parser.parse_args().helper.resolve(strict=True)
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

        run_checked("/usr/bin/codesign", "--verify", "--strict", str(staged_helper))
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
