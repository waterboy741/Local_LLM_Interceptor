#!/usr/bin/env python3
"""Validate and stage the launchd helper artifacts without installing them."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import plistlib
import shutil
import stat
import sys
from typing import NoReturn


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PLIST_SOURCE = REPOSITORY_ROOT / "resources/launchd/org.local-llm-interceptor.helper.plist"
SERVICE_NAME = "org.local-llm-interceptor.helper"
HELPER_INSTALL_PATH = "/Library/PrivilegedHelperTools/llm_interceptor_helper"
STATE_DIRECTORY = "/private/var/db/llm_interceptor"
STAGED_HELPER = Path("Library/PrivilegedHelperTools/llm_interceptor_helper")
STAGED_PLIST = Path("Library/LaunchDaemons/org.local-llm-interceptor.helper.plist")
SYSTEM_ROOTS = tuple(
    Path(path)
    for path in (
        "/applications", "/bin", "/etc", "/library", "/private/etc",
        "/private/var", "/sbin", "/system", "/usr", "/var",
    )
)


def fail(message: str) -> NoReturn:
    raise ValueError(message)


class UniqueKeyDictionary(dict):
    def __setitem__(self, key: str, value: object) -> None:
        if key in self:
            fail(f"duplicate launchd plist key: {key}")
        super().__setitem__(key, value)


def load_and_validate_plist(path: Path = PLIST_SOURCE) -> bytes:
    try:
        contents = path.read_bytes()
        config = plistlib.loads(contents, dict_type=UniqueKeyDictionary)
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
    if config != expected or config["MachServices"][SERVICE_NAME] is not True:
        fail("launchd plist does not match the reviewed fixed service configuration")
    return contents


def resolve_without_symlinks(path: Path, label: str) -> Path:
    current = Path("/")
    for component in path.parts[1:]:
        if component == "..":
            fail(f"{label} path must not contain parent traversal")
        current /= component
        try:
            if stat.S_ISLNK(current.lstat().st_mode):
                fail(f"{label} path must not contain symlinked components")
        except (FileNotFoundError, NotADirectoryError):
            continue
    return current


def validate_helper(path: Path) -> Path:
    helper = resolve_without_symlinks(Path.cwd() / path, "helper input")
    details = helper.stat()
    if not stat.S_ISREG(details.st_mode):
        fail("helper input must be a regular, non-symlink file")
    if details.st_size == 0:
        fail("helper input is empty")
    return helper


def validate_staging_directory(path: Path) -> Path:
    if not path.is_absolute():
        fail("output directory must be an absolute staging path")
    resolved = resolve_without_symlinks(path, "output directory")
    # macOS volumes can resolve differently cased names to the same path.
    folded = Path(str(resolved).casefold())
    if any(folded == root or root in folded.parents for root in SYSTEM_ROOTS):
        fail("output directory must be outside macOS system locations")
    if folded in (Path("/"), Path("/private"), Path("/users")):
        fail("output directory is too broad")
    return resolved


def validate_staging_paths(helper: Path, output_directory: Path) -> tuple[Path, Path]:
    source = validate_helper(helper)
    destination = validate_staging_directory(output_directory)
    folded_source = Path(str(source).casefold())
    folded_destination = Path(str(destination).casefold())
    if (
        folded_source == folded_destination
        or folded_source in folded_destination.parents
        or folded_destination in folded_source.parents
    ):
        fail("helper input and output directory must be disjoint")
    if destination.exists():
        if not destination.is_dir():
            fail("output directory exists and is not a directory")
        if any(destination.iterdir()):
            fail("output directory must be empty")
    return source, destination


def stage(helper: Path, output_directory: Path, plist_contents: bytes) -> None:
    source, destination = validate_staging_paths(helper, output_directory)

    helper_destination = destination / STAGED_HELPER
    plist_destination = destination / STAGED_PLIST
    helper_destination.parent.mkdir(parents=True)
    plist_destination.parent.mkdir(parents=True)
    shutil.copyfile(source, helper_destination, follow_symlinks=False)
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
        if not arguments.validate_only:
            validate_staging_paths(arguments.helper, arguments.output_dir)
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
