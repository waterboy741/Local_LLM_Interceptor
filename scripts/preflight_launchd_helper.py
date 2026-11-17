#!/usr/bin/env python3
"""Verify the reviewed GUI and launchd package for the offline A3 preflight."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import stat
import sys
from xml.parsers.expat import ExpatError

# A direct invocation must not write cache files beside the staging scripts.
sys.dont_write_bytecode = True

from package_launchd_helper import (
    STAGED_HELPER,
    STAGED_PLIST,
    load_and_validate_plist,
    resolve_without_symlinks,
    validate_helper,
    validate_staging_directory,
)
from stage_signed_gui_review import run_tool, validate_app


CODESIGN = Path("/usr/bin/codesign")
MAX_PLIST_BYTES = 16 * 1024


def cdhash_requirement(value: str) -> str:
    if not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", value):
        raise argparse.ArgumentTypeError("expected a 40- or 64-digit hexadecimal cdhash")
    return f'cdhash H"{value.lower()}"'


def verify_signature(path: Path, requirement: str, label: str, *, deep: bool = False) -> None:
    options = ["--verify", "--strict", "--all-architectures"]
    if deep:
        options.append("--deep")
    try:
        run_tool(CODESIGN, [*options, f"-R={requirement}", str(path)], label)
    except (OSError, ValueError) as error:
        raise ValueError(f"{label} failed") from error


def preflight(staged_root: Path, app: Path, gui_requirement: str, helper_requirement: str) -> None:
    try:
        root = validate_staging_directory(staged_root)
        helper = validate_helper(root / STAGED_HELPER)
        if stat.S_IMODE(helper.stat().st_mode) != 0o755:
            raise ValueError("unexpected helper mode")
        plist = resolve_without_symlinks(root / STAGED_PLIST, "staged plist")
        plist_stat = plist.stat()
        if (
            not stat.S_ISREG(plist_stat.st_mode)
            or stat.S_IMODE(plist_stat.st_mode) != 0o644
            or not 0 < plist_stat.st_size <= MAX_PLIST_BYTES
        ):
            raise ValueError("unexpected plist type, mode, or size")
    except (OSError, ValueError) as error:
        raise ValueError("staged helper package validation failed") from error

    try:
        load_and_validate_plist(plist)
    except (AttributeError, ExpatError, OSError, OverflowError, TypeError, ValueError) as error:
        # Some plistlib versions raise raw parser errors for malformed XML scalars.
        raise ValueError("staged helper package validation failed") from error

    try:
        signed_app = validate_app(app)
    except (OSError, ValueError) as error:
        raise ValueError("GUI bundle validation failed") from error

    verify_signature(helper, helper_requirement, "staged helper signature check")
    verify_signature(signed_app, gui_requirement, "GUI signature check", deep=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged-root", type=Path, required=True, help="absolute helper staging directory")
    parser.add_argument("--app", type=Path, required=True, help="absolute path to the signed review GUI")
    parser.add_argument("--gui-cdhash", type=cdhash_requirement, required=True, help="reviewed GUI cdhash")
    parser.add_argument("--helper-cdhash", type=cdhash_requirement, required=True, help="reviewed helper cdhash")
    arguments = parser.parse_args()

    try:
        preflight(arguments.staged_root, arguments.app, arguments.gui_cdhash, arguments.helper_cdhash)
    except ValueError as error:
        print(f"a3_offline_preflight_error: {error}", file=sys.stderr)
        return 1

    print("a3_offline_preflight_passed")
    print("enabled=false")
    print(f"peer-code-requirement={arguments.gui_cdhash}")
    print(f"helper-code-requirement={arguments.helper_cdhash}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
