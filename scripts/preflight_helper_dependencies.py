#!/usr/bin/env python3
"""Screen the staged macOS helper for unsafe Mach-O load commands."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True

from package_launchd_helper import validate_helper
from stage_signed_gui_review import run_tool


OTOOL = Path("/usr/bin/otool")
MACH_COLUMNS = "magic cputype cpusubtype caps filetype ncmds sizeofcmds flags".split()
SYSTEM_PREFIXES = ("/System/Library/", "/usr/lib/")
INVALID_OUTPUT = "helper Mach-O load commands could not be inspected"
DYLIB_LOAD_COMMANDS = {
    "LC_LAZY_LOAD_DYLIB",
    "LC_LOAD_DYLIB",
    "LC_LOAD_UPWARD_DYLIB",
    "LC_LOAD_WEAK_DYLIB",
    "LC_REEXPORT_DYLIB",
}
DYLIB_FIELDS = (
    r"time stamp [0-9]+(?: [A-Za-z0-9: -]+)?",
    r"current version [0-9]+\.[0-9]+\.[0-9]+",
    r"compatibility version [0-9]+\.[0-9]+\.[0-9]+",
)


def system_load_path(path: str) -> bool:
    # Keep only canonical absolute Apple system names, including shared-cache names.
    return path.startswith(SYSTEM_PREFIXES) and all(
        part not in ("", ".", "..") for part in path.split("/")[1:]
    )


def checked_load_name(command: list[str], path_offset: int, fields: tuple[str, ...]) -> str:
    # A load name containing newlines must not be mistaken for otool metadata.
    if len(command) != 3 + len(fields) or not re.fullmatch(r"cmdsize [0-9]+", command[1]):
        raise ValueError(INVALID_OUTPUT)
    name = re.fullmatch(rf"name (.+) \(offset {path_offset}\)", command[2])
    if name is None or any(
        re.fullmatch(pattern, line) is None for pattern, line in zip(fields, command[3:])
    ):
        raise ValueError(INVALID_OUTPUT)
    return name[1]


def check_architecture(lines: list[str]) -> None:
    if len(lines) < 4 or lines[0] != "Mach header" or lines[1].split() != MACH_COLUMNS:
        raise ValueError(INVALID_OUTPUT)
    header = lines[2].split()
    if len(header) != len(MACH_COLUMNS) or header[0] != "0xfeedfacf" or header[4] != "2":
        raise ValueError(INVALID_OUTPUT)
    if not re.fullmatch(r"[0-9]{1,5}", header[5]):
        raise ValueError(INVALID_OUTPUT)

    load_commands: list[list[str]] = []
    for line in lines[3:]:
        if line.startswith("Load command "):
            if line != f"Load command {len(load_commands)}":
                raise ValueError(INVALID_OUTPUT)
            load_commands.append([])
        elif load_commands:
            load_commands[-1].append(line.strip())
        else:
            raise ValueError(INVALID_OUTPUT)
    if len(load_commands) != int(header[5]):
        raise ValueError(INVALID_OUTPUT)

    dylinker_count = 0
    for command in load_commands:
        match = re.fullmatch(r"cmd (LC_[A-Z0-9_]+)", command[0]) if command else None
        if match is None:
            raise ValueError(INVALID_OUTPUT)
        kind = match[1]
        if kind in ("LC_RPATH", "LC_DYLD_ENVIRONMENT"):
            raise ValueError("helper declares an unsupported runtime search path or environment override")
        if kind == "LC_LOAD_DYLINKER":
            dylinker_count += 1
            if checked_load_name(command, 12, ()) != "/usr/lib/dyld":
                raise ValueError("helper uses an unexpected dynamic linker")
        elif kind in DYLIB_LOAD_COMMANDS:
            if not system_load_path(checked_load_name(command, 24, DYLIB_FIELDS)):
                raise ValueError("helper has a non-system dynamic dependency")
        elif kind.endswith(("_DYLIB", "_DYLINKER", "FVMLIB")):
            raise ValueError("helper declares an unsupported library load command")
    if dylinker_count != 1:
        raise ValueError(INVALID_OUTPUT)


def inspect_load_commands(output: bytes, helper: Path) -> None:
    try:
        lines = output.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError(INVALID_OUTPUT) from error
    heading = re.compile(re.escape(str(helper)) + r"(?: \(architecture [a-zA-Z0-9_]+\))?:")
    architectures: list[list[str]] = []
    for line in lines:
        if heading.fullmatch(line):
            architectures.append([])
        elif architectures:
            architectures[-1].append(line)
        else:
            raise ValueError(INVALID_OUTPUT)
    if not architectures:
        raise ValueError(INVALID_OUTPUT)
    for architecture in architectures:
        check_architecture(architecture)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", type=Path, required=True, help="absolute path to the staged helper")
    helper = parser.parse_args().helper
    try:
        if not helper.is_absolute() or any(character in str(helper) for character in "\r\n"):
            raise ValueError(INVALID_OUTPUT)
        helper = validate_helper(helper)
        result = run_tool(OTOOL, ["-arch", "all", "-h", "-l", str(helper)], "helper Mach-O inspection")
        if result.stderr:
            raise ValueError(INVALID_OUTPUT)
    except (OSError, ValueError):
        print(f"a3_helper_dependency_preflight_error: {INVALID_OUTPUT}", file=sys.stderr)
        return 1
    try:
        inspect_load_commands(result.stdout, helper)
    except ValueError as error:
        print(f"a3_helper_dependency_preflight_error: {error}", file=sys.stderr)
        return 1

    print("a3_helper_dependency_preflight_passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
