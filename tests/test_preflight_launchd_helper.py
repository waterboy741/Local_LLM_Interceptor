"""Offline tests for the staged helper and GUI preflight."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
import plistlib
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "preflight_launchd_helper.py"
PLIST_NAME = "org.local-llm-interceptor.helper.plist"
GUI_HASH = "a" * 40
HELPER_HASH = "b" * 64
WRONG_HASH = "c" * 40


class LaunchdHelperPreflightTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.stage = self.root / "staged helper"
        self.helper = self.stage / "Library/PrivilegedHelperTools/llm_interceptor_helper"
        self.plist = self.stage / "Library/LaunchDaemons" / PLIST_NAME
        self.app = self.root / "staged GUI" / "llm_interceptor.app"
        self.executable = self.app / "Contents/MacOS/llm_interceptor"
        self.helper.parent.mkdir(parents=True)
        self.plist.parent.mkdir(parents=True)
        self.executable.parent.mkdir(parents=True)
        self.helper.write_bytes(b"synthetic signed helper")
        self.helper.chmod(0o755)
        self.plist.write_bytes((ROOT / "resources/launchd" / PLIST_NAME).read_bytes())
        self.plist.chmod(0o644)
        self.executable.write_bytes(b"synthetic signed GUI")
        self.executable.chmod(0o755)
        (self.app / "Contents/Info.plist").write_bytes(plistlib.dumps({
            "CFBundleExecutable": "llm_interceptor",
            "CFBundleIdentifier": "org.local-llm-interceptor",
        }))
        self.calls = []

    def verify(self, program, arguments, _label):
        command = [str(program), *arguments]
        self.calls.append(command)
        identity = {str(self.helper): HELPER_HASH, str(self.app): GUI_HASH}
        expected_hash = identity[command[-1]]
        self.assertEqual(command[0], "/usr/bin/codesign")
        expected_options = ["--verify", "--strict", "--all-architectures"]
        if command[-1] == str(self.app):
            expected_options.append("--deep")
        self.assertEqual(command[1:-2], expected_options)
        if command[-2] != f'-R=cdhash H"{expected_hash}"':
            raise ValueError("test-requirement: synthetic private failure details")
        return subprocess.CompletedProcess(command, 0, b"", b"")

    def invoke(self, *, stage=None, app=None, gui_hash=GUI_HASH, helper_hash=HELPER_HASH):
        argv = [
            str(SCRIPT),
            "--staged-root", str(self.stage if stage is None else stage),
            "--app", str(self.app if app is None else app),
            "--gui-cdhash", gui_hash,
            "--helper-cdhash", helper_hash,
        ]
        self.calls.clear()
        stdout, stderr = StringIO(), StringIO()
        with (
            patch.object(sys, "path", [str(SCRIPT.parent), *sys.path]),
            patch.object(sys, "dont_write_bytecode", True),
        ):
            main = runpy.run_path(str(SCRIPT))["main"]
        with (
            patch.object(sys, "argv", argv),
            patch.dict(main.__globals__, {"run_tool": self.verify}),
            patch("subprocess.Popen", side_effect=AssertionError("unexpected external command")),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            try:
                status = main()
            except SystemExit as error:
                status = error.code
        return status, stdout.getvalue(), stderr.getvalue()

    def assert_rejected(self, *, expect_calls=False, **kwargs):
        status, stdout, stderr = self.invoke(**kwargs)
        self.assertNotEqual(status, 0)
        self.assertEqual(stdout, "")
        self.assertTrue(stderr)
        self.assertNotIn("synthetic private failure details", stderr)
        self.assertEqual(bool(self.calls), expect_calls)

    def snapshot(self):
        return {
            path.relative_to(self.root): (
                path.stat().st_ino,
                path.stat().st_mode,
                path.stat().st_mtime_ns,
                path.read_bytes() if path.is_file() else None,
            )
            for path in self.root.rglob("*")
        }

    def test_checks_both_approved_identities_without_changing_inputs(self):
        before = self.snapshot()
        expected = (
            "a3_offline_preflight_passed\n"
            "enabled=false\n"
            f'peer-code-requirement=cdhash H"{GUI_HASH}"\n'
            f'helper-code-requirement=cdhash H"{HELPER_HASH}"\n'
        )
        self.assertEqual(self.invoke(gui_hash=GUI_HASH.upper()), (0, expected, ""))
        self.assertCountEqual([command[-1] for command in self.calls], [str(self.helper), str(self.app)])
        self.assertEqual(self.snapshot(), before)

    def test_rejects_a_different_approved_identity_for_either_endpoint(self):
        before = self.snapshot()
        for argument, path in (("gui_hash", self.app), ("helper_hash", self.helper)):
            with self.subTest(argument=argument):
                self.assert_rejected(expect_calls=True, **{argument: WRONG_HASH})
                self.assertEqual(self.calls[-1][-1], str(path))
        self.assertEqual(self.snapshot(), before)

    def test_rejects_malformed_cdhash_before_verification(self):
        for argument in ("gui_hash", "helper_hash"):
            for value in ("a" * 39, "g" * 40, GUI_HASH + '" or true'):
                with self.subTest(argument=argument, value=value):
                    self.assert_rejected(**{argument: value})

    def test_rejects_symlinked_and_unsafe_paths(self):
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        for arguments in (
            {"stage": self.stage.name},
            {"stage": alias / self.stage.name},
            {"stage": self.root / "missing" / ".." / self.stage.name},
            {"stage": Path("/private/Etc")},
            {"app": alias / self.app.relative_to(self.root)},
        ):
            with self.subTest(arguments=arguments):
                self.assert_rejected(**arguments)

    def test_rejects_symlinked_helper(self):
        outside = self.root / "otherwise-valid-helper"
        self.helper.rename(outside)
        self.helper.symlink_to(outside)
        self.assert_rejected()
        self.assertEqual(outside.read_bytes(), b"synthetic signed helper")

    def test_rejects_changed_plist_and_incorrect_helper_mode(self):
        original = self.plist.read_bytes()
        configuration = plistlib.loads(original)
        configuration["KeepAlive"] = True
        self.plist.write_bytes(plistlib.dumps(configuration))
        self.assert_rejected()

        self.plist.write_bytes(original)
        self.helper.chmod(0o777)
        self.assert_rejected()

    def test_rejects_malformed_xml_without_disclosing_details(self):
        for invalid in (
            b'<?xml version="1.0"?><plist><dict><key>Label</key>',
            b'<?xml version="1.0"?><plist><dict><key>Date</key><date/></dict></plist>',
        ):
            with self.subTest(invalid=invalid):
                self.plist.write_bytes(invalid)
                self.assertEqual(
                    self.invoke(),
                    (1, "", "a3_offline_preflight_error: staged helper package validation failed\n"),
                )
                self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
