"""Offline tests for A3's conservative Mach-O dependency gate."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "preflight_helper_dependencies.py"
CORE_FOUNDATION = "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
HOME_BREW_QT = "/opt/homebrew/opt/qtbase/lib/QtCore.framework/Versions/A/QtCore"
DYLINKER = ("LC_LOAD_DYLINKER", "name /usr/lib/dyld (offset 12)")
LIB_SYSTEM = ("LC_LOAD_DYLIB", "name /usr/lib/libSystem.B.dylib (offset 24)")


class HelperDependencyPreflightTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.helper = self.root / "staged helper"
        self.helper.write_bytes(b"synthetic Mach-O fixture")
        self.helper.chmod(0o755)
        with (
            patch.object(sys, "path", [str(SCRIPT.parent), *sys.path]),
            patch.object(sys, "dont_write_bytecode", True),
        ):
            self.main = runpy.run_path(str(SCRIPT))["main"]
        self.calls = []

    def architecture(self, commands, name=None):
        heading = f"{self.helper} (architecture {name}):" if name else f"{self.helper}:"
        cpu_type = 16777223 if name == "x86_64" else 16777228
        lines = [
            heading,
            "Mach header",
            "magic cputype cpusubtype caps filetype ncmds sizeofcmds flags",
            f"0xfeedfacf {cpu_type} 0 0x00 2 {len(commands)} {len(commands) * 96} 0x00218085",
        ]
        for index, (command, payload) in enumerate(commands):
            lines.extend([f"Load command {index}", f"          cmd {command}", "      cmdsize 96"])
            if payload:
                lines.append(f"         {payload}")
            if command.endswith("_DYLIB"):
                lines.extend([
                    "   time stamp 2 Wed Dec 31 18:00:02 1969",
                    "      current version 6.12.0",
                    "compatibility version 6.0.0",
                ])
        return "\n".join(lines) + "\n"

    def invoke(self, output, *, helper=None, fail=False):
        self.calls.clear()

        def inspect(program, arguments, _label):
            command = [str(program), *arguments]
            self.calls.append(command)
            self.assertEqual(command, ["/usr/bin/otool", "-arch", "all", "-h", "-l", str(self.helper)])
            if fail:
                raise ValueError("synthetic private tool detail")
            return subprocess.CompletedProcess(command, 0, output, b"")

        stdout, stderr = StringIO(), StringIO()
        with (
            patch.object(sys, "argv", [str(SCRIPT), "--helper", str(helper or self.helper)]),
            patch.dict(self.main.__globals__, {"run_tool": inspect}),
            patch("subprocess.Popen", side_effect=AssertionError("unexpected external command")),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            try:
                status = self.main()
            except SystemExit as error:
                status = error.code
        return status, stdout.getvalue(), stderr.getvalue()

    def assert_rejected(self, output, *, expect_tool=True, **kwargs):
        status, stdout, stderr = self.invoke(output, **kwargs)
        self.assertNotEqual(status, 0)
        self.assertEqual(stdout, "")
        self.assertTrue(stderr)
        self.assertNotIn("synthetic private tool detail", stderr)
        self.assertEqual(bool(self.calls), expect_tool)

    def test_accepts_only_system_dependencies_without_modifying_helper(self):
        before = self.helper.stat()
        commands = [
            DYLINKER,
            ("LC_LOAD_DYLIB", f"name {CORE_FOUNDATION} (offset 24)"),
            LIB_SYSTEM,
        ]
        output = self.architecture(commands).encode()
        self.assertEqual(self.invoke(output), (0, "a3_helper_dependency_preflight_passed\n", ""))
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.helper.read_bytes(), b"synthetic Mach-O fixture")
        self.assertEqual(self.helper.stat().st_ino, before.st_ino)
        self.assertEqual(self.helper.stat().st_mode, before.st_mode)
        self.assertEqual(self.helper.stat().st_mtime_ns, before.st_mtime_ns)

    def test_checks_second_architecture_and_rejects_homebrew(self):
        first = self.architecture([DYLINKER, LIB_SYSTEM], "x86_64")
        second = self.architecture([DYLINKER, LIB_SYSTEM], "arm64")
        self.assertEqual(self.invoke((first + second).encode())[0], 0)
        second = self.architecture([
            DYLINKER,
            ("LC_LOAD_DYLIB", f"name {HOME_BREW_QT} (offset 24)"),
            LIB_SYSTEM,
        ], "arm64")
        self.assert_rejected((first + second).encode())

    def test_rejects_indirect_and_non_system_dependency_paths(self):
        for path in (
            "@rpath/libQtCore.dylib",
            "@loader_path/libQtCore.dylib",
            "@executable_path/libQtCore.dylib",
            "libQtCore.dylib",
            "/System/Library/../../tmp/libQtCore.dylib",
            "/usr/lib-custom/libQtCore.dylib",
        ):
            with self.subTest(path=path):
                commands = [DYLINKER, LIB_SYSTEM, ("LC_LOAD_WEAK_DYLIB", f"name {path} (offset 24)")]
                self.assert_rejected(self.architecture(commands).encode())

    def test_rejects_multiline_dependency_names(self):
        multiline_name = f"name /usr/lib/libSystem.B.dylib (offset 24)\n{HOME_BREW_QT} (offset 24)"
        for command in ("LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB"):
            with self.subTest(command=command):
                fixture = self.architecture([DYLINKER, LIB_SYSTEM, (command, multiline_name)])
                self.assert_rejected(fixture.encode())

    def test_rejects_runtime_search_path_and_environment_commands(self):
        for command in (
            ("LC_RPATH", "path /usr/lib (offset 12)"),
            ("LC_DYLD_ENVIRONMENT", "name DYLD_LIBRARY_PATH=/usr/lib (offset 12)"),
            ("LC_LOAD_DYLINKER", "name /opt/homebrew/lib/dyld (offset 12)"),
        ):
            with self.subTest(command=command):
                commands = [DYLINKER, LIB_SYSTEM, command]
                if command[0] == "LC_LOAD_DYLINKER":
                    commands = [command, LIB_SYSTEM]
                self.assert_rejected(self.architecture(commands).encode())

    def test_rejects_malformed_output_and_inspection_failure(self):
        for output in (
            b"",
            b"not otool output",
            self.architecture([DYLINKER, ("LC_LOAD_DYLIB", "")]).encode(),
            self.architecture([DYLINKER, LIB_SYSTEM]).encode() + b"Load command 2\n",
        ):
            with self.subTest(output=output):
                self.assert_rejected(output)
        self.assert_rejected(b"", fail=True)

    def test_rejects_relative_paths_and_symlinks_before_inspection(self):
        alias = self.root / "helper alias"
        alias.symlink_to(self.helper)
        for helper in (Path(self.helper.name), alias):
            with self.subTest(helper=helper):
                self.assert_rejected(b"", helper=helper, expect_tool=False)


if __name__ == "__main__":
    unittest.main()
