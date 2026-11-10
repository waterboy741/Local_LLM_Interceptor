#!/usr/bin/env python3
"""Validate and stage the launchd helper artifacts without installing them."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import plistlib
import shutil
import sys
from typing import NoReturn


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PLIST_SOURCE = REPOSITORY_ROOT / "resources/launchd/org.local-llm-interceptor.helper.plist"
SERVICE_NAME = "org.local-llm-interceptor.helper"
HELPER_INSTALL_PATH = "/Library/PrivilegedHelperTools/llm_interceptor_helper"
STATE_DIRECTORY = "/private/var/db/llm_interceptor"
STAGED_HELPER = Path("Library/PrivilegedHelperTools/llm_interceptor_helper")
STAGED_PLIST = Path("Library/LaunchDaemons/org.local-llm-interceptor.helper.plist")


def fail(message: str) -> NoReturn:
    raise ValueError(message)


def load_and_validate_plist(path: Path = PLIST_SOURCE) -> bytes:
    try:
        contents = path.read_bytes()
        config = plistlib.loads(contents)
    except (OSError, plistlib.InvalidFileException, ValueError) as error:
        fail(f"launchd plist cannot be read: {error}")

    if not isinstance(config, dict):
        fail("launchd plist root must be a dictionary")
    expected_arguments = [HELPER_INSTALL_PATH, "--mach-service", "--state-dir", STATE_DIRECTORY]
    expected = {
        "Label": SERVICE_NAME,
        "ProgramArguments": expected_arguments,
        "UserName": "root",
        "GroupName": "wheel",
        "MachServices": {SERVICE_NAME: True},
    }
    if config != expected:
        fail("launchd plist does not match the reviewed fixed service configuration")
    return contents


def validate_staging_directory(path: Path) -> Path:
    if not path.is_absolute():
        fail("output directory must be an absolute staging path")
    if path.is_symlink():
        fail("output directory must not be a symlink")
    resolved = path.resolve(strict=False)
    forbidden_roots = (Path("/Library"), Path("/System"), Path("/private/var"))
    if any(resolved == root or root in resolved.parents for root in forbidden_roots):
        fail("output directory must be outside macOS system locations")
    if resolved == Path("/") or resolved == Path("/private"):
        fail("output directory is too broad")
    if resolved.exists():
        if not resolved.is_dir():
            fail("output directory exists and is not a directory")
        if any(resolved.iterdir()):
            fail("output directory must be empty")
    return resolved


def stage(helper: Path, output_directory: Path, plist_contents: bytes) -> None:
    if helper.is_symlink() or not helper.is_file():
        fail("helper input must be a regular, non-symlink file")
    if helper.stat().st_size == 0:
        fail("helper input is empty")
    destination = validate_staging_directory(output_directory)

    helper_destination = destination / STAGED_HELPER
    plist_destination = destination / STAGED_PLIST
    helper_destination.parent.mkdir(parents=True)
    plist_destination.parent.mkdir(parents=True)
    shutil.copyfile(helper, helper_destination, follow_symlinks=False)
    os.chmod(helper_destination, 0o755)
    plist_destination.write_bytes(plist_contents)
    os.chmod(plist_destination, 0o644)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate-only", action="store_true", help="validate the checked-in plist")
    parser.add_argument("--helper", type=Path, help="built llm_interceptor_helper executable to stage")
    parser.add_argument("--output-dir", type=Path, help="new or empty absolute non-system staging directory")
    arguments = parser.parse_args()
    if arguments.validate_only:
        if arguments.helper is not None or arguments.output_dir is not None:
            parser.error("--validate-only cannot be combined with staging arguments")
    elif arguments.helper is None or arguments.output_dir is None:
        parser.error("staging requires both --helper and --output-dir")
    return arguments


def main() -> int:
    try:
        arguments = parse_args()
        plist_contents = load_and_validate_plist()
        if not arguments.validate_only:
            stage(arguments.helper, arguments.output_dir, plist_contents)
            print("launchd_helper_staged_for_review")
        else:
            print("launchd_plist_valid")
        return 0
    except (OSError, ValueError) as error:
        print(f"launchd_helper_package_error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
