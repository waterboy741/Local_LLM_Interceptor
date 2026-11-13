#!/usr/bin/env python3
"""Copy, ad-hoc sign, and inspect a GUI app in a non-installing review directory."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import sys
import time
from typing import NoReturn, Sequence


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
APP_NAME = "llm_interceptor.app"
EXECUTABLE = Path("Contents/MacOS/llm_interceptor")
COMMAND_TIMEOUT_SECONDS = 30
MAX_COMMAND_OUTPUT_BYTES = 16 * 1024
SYSTEM_ROOTS = tuple(
    Path(path)
    for path in (
        "/system", "/library", "/applications", "/usr", "/bin", "/sbin", "/etc",
        "/private/var", "/private/etc", "/var",
    )
)


def fail(message: str) -> NoReturn:
    raise ValueError(message)


def has_symlink_component(path: Path) -> bool:
    """Check the named path and its ancestors without following a symlink."""
    absolute = path if path.is_absolute() else Path.cwd() / path
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            if current.is_symlink():
                return True
        except OSError:
            return True
    return False


def validate_app(app: Path) -> Path:
    if not app.is_absolute():
        fail("app path must be absolute")
    if ".." in app.parts:
        fail("app path must not contain parent traversal")
    if has_symlink_component(app):
        fail("app path must not contain symlinked components")
    try:
        app = app.resolve(strict=True)
    except OSError as error:
        fail(f"app path cannot be resolved: {error}")
    if app.name != APP_NAME or not app.is_dir():
        fail(f"app must be a built {APP_NAME} bundle")
    executable = app / EXECUTABLE
    if not executable.is_file() or executable.is_symlink() or executable.stat().st_size == 0:
        fail("app bundle has no regular non-empty GUI executable")
    for root, directories, files in os.walk(app, followlinks=False):
        root_path = Path(root)
        for name in directories + files:
            entry = root_path / name
            if entry.is_symlink():
                fail("app bundle must not contain symlinks")
            if not (entry.is_dir() or entry.is_file()):
                fail("app bundle contains an unsupported filesystem entry")
    return app


def validate_output_directory(path: Path) -> Path:
    if not path.is_absolute():
        fail("output directory must be an absolute path")
    if ".." in path.parts:
        fail("output directory path must not contain parent traversal")
    if has_symlink_component(path):
        fail("output directory path must not contain symlinked components")
    destination = path.resolve(strict=False)
    # macOS volumes can resolve differently cased names to the same path.
    folded = Path(str(destination).casefold())
    if folded in (Path("/"), Path("/private"), Path("/users")) or any(
        folded == root or root in folded.parents for root in SYSTEM_ROOTS
    ):
        fail("output directory must be outside macOS system locations")
    if destination.exists():
        if not destination.is_dir():
            fail("output directory exists and is not a directory")
        try:
            if next(destination.iterdir(), None) is not None:
                fail("output directory must be new or empty")
        except OSError as error:
            fail(f"output directory cannot be inspected: {error}")
    return destination


def disjoint(source: Path, destination: Path) -> None:
    folded_source = Path(str(source).casefold())
    folded_destination = Path(str(destination).casefold())
    if (
        folded_source == folded_destination
        or folded_source in folded_destination.parents
        or folded_destination in folded_source.parents
    ):
        fail("source app and output directory must be disjoint")


def run_tool(program: Path, arguments: Sequence[str], label: str) -> subprocess.CompletedProcess[bytes]:
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            [str(program), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        fail(f"{label} could not start: {error}")
    assert process.stdout is not None and process.stderr is not None
    output = {process.stdout: bytearray(), process.stderr: bytearray()}
    selector = selectors.DefaultSelector()
    for stream in output:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
    deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
    try:
        while selector.get_map() or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                fail(f"{label} timed out")
            for key, _ in selector.select(min(remaining, 0.1)):
                chunk = os.read(key.fileobj.fileno(), 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                collected = output[key.fileobj]
                collected.extend(chunk)
                if len(collected) > MAX_COMMAND_OUTPUT_BYTES:
                    fail(f"{label} exceeded the output limit")
        return_code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
    except (OSError, subprocess.TimeoutExpired) as error:
        fail(f"{label} could not be collected: {error}")
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
        process.stderr.close()
    if return_code != 0:
        details = bytes(output[process.stderr]).decode("utf-8", errors="replace").strip()
        fail(f"{label} failed with exit code {return_code}" + (f": {details}" if details else ""))
    return subprocess.CompletedProcess(
        [str(program), *arguments], return_code, bytes(output[process.stdout]), bytes(output[process.stderr])
    )


def validate_tool(program: Path, label: str) -> None:
    if not program.is_absolute() or not program.is_file() or not os.access(program, os.X_OK):
        fail(f"{label} is not an executable file: {program}")


def validate_proposal(output: bytes) -> None:
    if len(output) > 4096 or b"\0" in output:
        fail("identity preview output is invalid")
    try:
        text = output.decode("ascii")
    except UnicodeDecodeError:
        fail("identity preview output is not ASCII")
    if not re.fullmatch(
        r'enabled=false\npeer-code-requirement=cdhash H"(?:[0-9a-f]{40}|[0-9a-f]{64})"\n?', text
    ):
        fail("identity preview did not return the expected disabled cdhash proposal")


def stage(app: Path, output_dir: Path, xattr_tool: Path, codesign_tool: Path,
          preview_tool: Path) -> tuple[Path, bytes]:
    source = validate_app(app)
    destination = validate_output_directory(output_dir)
    disjoint(source, destination)
    validate_tool(xattr_tool, "xattr tool")
    validate_tool(codesign_tool, "codesign tool")
    validate_tool(preview_tool, "identity preview tool")
    # Repeat path and emptiness checks immediately before creating the staged copy.
    destination = validate_output_directory(output_dir)
    disjoint(source, destination)
    staged_app = destination / APP_NAME
    try:
        destination.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, staged_app, symlinks=False, copy_function=shutil.copy2)
    except OSError as error:
        fail(f"app could not be staged: {error}")

    # Attribute removal and signing are deliberately scoped to the staged copy.
    run_tool(xattr_tool, ["-cr", str(staged_app)], "staged xattr removal")
    run_tool(codesign_tool, ["--force", "--deep", "--sign", "-", str(staged_app)], "ad-hoc signing")
    run_tool(codesign_tool, ["--verify", "--strict", "--deep", str(staged_app)], "strict signature verification")
    preview = run_tool(preview_tool, ["--app", str(staged_app)], "identity preview")
    validate_proposal(preview.stdout)
    return staged_app, preview.stdout


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True, help="absolute path to built llm_interceptor.app")
    parser.add_argument("--output-dir", type=Path, required=True, help="new or empty absolute review directory")
    parser.add_argument(
        "--preview-tool", type=Path,
        default=REPOSITORY_ROOT / "build/debug/mach_service_identity_preview",
        help="built mach_service_identity_preview executable",
    )
    parser.add_argument("--xattr-tool", type=Path, default=Path("/usr/bin/xattr"), help=argparse.SUPPRESS)
    parser.add_argument("--codesign-tool", type=Path, default=Path("/usr/bin/codesign"), help=argparse.SUPPRESS)
    return parser.parse_args()


def main() -> int:
    try:
        args = parse_args()
        staged_app, preview = stage(args.app, args.output_dir, args.xattr_tool,
                                    args.codesign_tool, args.preview_tool)
        sys.stdout.write(f"staged_app={staged_app}\n")
        sys.stdout.flush()
        sys.stdout.buffer.write(preview)
        if preview and not preview.endswith(b"\n"):
            sys.stdout.buffer.write(b"\n")
        return 0
    except (OSError, ValueError) as error:
        print(f"signed_gui_stage_error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
