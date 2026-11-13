"""Offline safety checks for the signed GUI review staging script."""

from __future__ import annotations

import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPOSITORY_ROOT / "scripts" / "stage_signed_gui_review.py"
DISABLED_PROPOSAL = b"enabled=false\npeer-code-requirement=cdhash H\"" + b"a" * 40 + b"\"\n"


class SignedGuiReviewStagingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_context = tempfile.TemporaryDirectory(
            prefix=".signed-gui-stage-test-", dir=REPOSITORY_ROOT
        )
        self.root = Path(self.temp_context.name)
        self.source = self.root / "source" / "llm_interceptor.app"
        executable = self.source / "Contents" / "MacOS" / "llm_interceptor"
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"synthetic signed source executable\n")
        executable.chmod(0o755)
        (self.source / "Contents" / "Info.plist").write_bytes(b"synthetic bundle metadata\n")
        self.log = self.root / "tool-calls.jsonl"
        self.xattr_tool = self.make_tool("xattr", "raise SystemExit(0)")
        self.codesign_tool = self.make_tool(
            "codesign",
            "if '--sign' in sys.argv:\n"
            "    app = Path(sys.argv[-1])\n"
            "    (app / 'Contents' / 'signed-by-test-stub').write_text('signed')\n"
            "raise SystemExit(0)",
        )
        self.preview_tool = self.make_tool(
            "preview",
            "sys.stdout.buffer.write(os.environ.get('STAGE_TEST_PROPOSAL', PROPOSAL.decode()).encode())\n"
            "raise SystemExit(0)",
        )

    def tearDown(self) -> None:
        self.temp_context.cleanup()

    def make_tool(self, name: str, body: str) -> Path:
        tool = self.root / f"{name}-stub.py"
        tool.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "log = Path(os.environ['STAGE_TEST_LOG'])\n"
            f"entry = {{'tool': {name!r}, 'args': sys.argv[1:]}}\n"
            "with log.open('a', encoding='utf-8') as stream:\n"
            "    stream.write(json.dumps(entry) + '\\n')\n"
            "if os.environ.get('STAGE_TEST_FAIL') == " + repr(name) + ":\n"
            "    print('synthetic tool failure', file=sys.stderr)\n"
            "    raise SystemExit(19)\n"
            "if os.environ.get('STAGE_TEST_FAIL') == 'codesign-verify' and "
            "'--verify' in sys.argv and " + repr(name) + " == 'codesign':\n"
            "    print('synthetic verification failure', file=sys.stderr)\n"
            "    raise SystemExit(19)\n"
            f"PROPOSAL = {DISABLED_PROPOSAL!r}\n"
            f"{body}\n",
            encoding="utf-8",
        )
        tool.chmod(0o755)
        return tool

    def invoke(
        self,
        output: Path,
        app: Path | None = None,
        fail_tool: str | None = None,
        proposal: str | None = None,
    ):
        environment = os.environ.copy()
        environment["STAGE_TEST_LOG"] = str(self.log)
        if fail_tool is not None:
            environment["STAGE_TEST_FAIL"] = fail_tool
        if proposal is not None:
            environment["STAGE_TEST_PROPOSAL"] = proposal
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--app",
                str(app or self.source),
                "--output-dir",
                str(output),
                "--xattr-tool",
                str(self.xattr_tool),
                "--codesign-tool",
                str(self.codesign_tool),
                "--preview-tool",
                str(self.preview_tool),
            ],
            cwd=REPOSITORY_ROOT,
            env=environment,
            capture_output=True,
            check=False,
        )

    def tool_calls(self) -> list[dict[str, object]]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def test_stages_copy_only_and_returns_disabled_proposal(self) -> None:
        original_files = {
            str(path.relative_to(self.source)): path.read_bytes()
            for path in self.source.rglob("*")
            if path.is_file()
        }
        output = self.root / "review-output"

        result = self.invoke(output)

        staged_app = output / "llm_interceptor.app"
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(
            result.stdout,
            f"staged_app={staged_app}\n".encode() + DISABLED_PROPOSAL,
        )
        self.assertEqual(
            {
                str(path.relative_to(self.source)): path.read_bytes()
                for path in self.source.rglob("*")
                if path.is_file()
            },
            original_files,
        )
        self.assertTrue((staged_app / "Contents" / "signed-by-test-stub").is_file())
        calls = self.tool_calls()
        self.assertEqual([call["tool"] for call in calls], ["xattr", "codesign", "codesign", "preview"])
        self.assertTrue(all(str(staged_app) in call["args"] for call in calls))
        self.assertEqual(calls[1]["args"][:4], ["--force", "--deep", "--sign", "-"])
        self.assertIn("--verify", calls[2]["args"])
        self.assertEqual(calls[3]["args"][:1], ["--app"])

    def test_rejects_unsafe_or_reused_output_paths_before_running_tools(self) -> None:
        occupied = self.root / "occupied"
        occupied.mkdir()
        (occupied / "keep.txt").write_text("keep", encoding="utf-8")
        symlink = self.root / "output-link"
        symlink.symlink_to(self.root / "safe-target", target_is_directory=True)

        for output in (
            occupied,
            symlink,
            Path("relative-stage"),
            Path("/System/Library/stage-review"),
            Path("/private/etc/stage-review"),
        ):
            with self.subTest(output=output):
                result = self.invoke(output)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.tool_calls(), [])
        self.assertEqual((occupied / "keep.txt").read_text(encoding="utf-8"), "keep")

    def test_rejects_symlinked_source_bundle_content(self) -> None:
        outside = self.root / "outside-executable"
        outside.write_bytes(b"outside\n")
        executable = self.source / "Contents" / "MacOS" / "llm_interceptor"
        executable.unlink()
        executable.symlink_to(outside)

        result = self.invoke(self.root / "review-output")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.tool_calls(), [])
        self.assertEqual(outside.read_bytes(), b"outside\n")

    def test_rejects_parent_traversal_before_staging(self) -> None:
        regular_file = self.root / "regular-file"
        regular_file.write_bytes(b"keep\n")
        missing_parent = self.root / "missing-parent"
        output = self.root / "review-output"

        for parent in (regular_file, missing_parent):
            for app_path, output_path in (
                (parent / ".." / self.source.relative_to(self.root), output),
                (self.source, parent / ".." / output.name),
            ):
                with self.subTest(app=app_path, output=output_path):
                    result = self.invoke(output_path, app=app_path)
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(result.stdout, b"")
                    self.assertIn(b"signed_gui_stage_error:", result.stderr)
                    self.assertEqual(self.tool_calls(), [])
                    self.assertFalse(output.exists())
                    self.assertFalse(missing_parent.exists())
                    self.assertEqual(regular_file.read_bytes(), b"keep\n")

    def test_rejects_case_varied_protected_output_root(self) -> None:
        validate_output_directory = runpy.run_path(str(SCRIPT_PATH))["validate_output_directory"]

        # Validate directly so a regression cannot write under a system location.
        with self.assertRaisesRegex(ValueError, "outside macOS system locations"):
            validate_output_directory(Path("/private/Etc/stage-review"))

    def test_rejects_case_varied_source_output_overlap(self) -> None:
        output = self.source.with_name(self.source.name.upper()) / "review-output"
        result = self.invoke(output)

        self.assertEqual(result.returncode, 1)
        self.assertIn(b"disjoint", result.stderr)
        self.assertEqual(self.tool_calls(), [])
        self.assertFalse(output.exists())
        self.assertFalse((self.source / output.name).exists())

    def test_rejects_symlinked_source_and_output_ancestors(self) -> None:
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        output = self.root / "review-output"

        for app_path, output_path in (
            (alias / self.source.relative_to(self.root), output),
            (self.source, alias / output.name),
        ):
            with self.subTest(app=app_path, output=output_path):
                result = self.invoke(output_path, app=app_path)
                self.assertEqual(result.returncode, 1)
                self.assertIn(b"symlinked components", result.stderr)
                self.assertEqual(self.tool_calls(), [])
                self.assertFalse(output.exists())

    @unittest.skipUnless(Path("/private/tmp").is_dir(), "requires macOS private temporary directory")
    def test_stages_under_private_tmp(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            output = Path(temporary) / "review-output"
            result = self.invoke(output)

            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            self.assertTrue((output / self.source.name).is_dir())

    def test_each_tool_failure_stops_before_later_tools(self) -> None:
        expected = {
            "xattr": ["xattr"],
            "codesign": ["xattr", "codesign"],
            "codesign-verify": ["xattr", "codesign", "codesign"],
            "preview": ["xattr", "codesign", "codesign", "preview"],
        }
        for failed_tool, expected_calls in expected.items():
            with self.subTest(failed_tool=failed_tool):
                self.log.unlink(missing_ok=True)
                output = self.root / f"failure-{failed_tool}"
                result = self.invoke(output, fail_tool=failed_tool)
                self.assertEqual(result.returncode, 1)
                calls = self.tool_calls()
                names = [call["tool"] for call in calls]
                self.assertEqual(names, expected_calls)
                self.assertIn(b"signed_gui_stage_error:", result.stderr)
                self.assertEqual((self.source / "Contents" / "MacOS" / "llm_interceptor").read_bytes(), b"synthetic signed source executable\n")

    def test_rejects_preview_output_that_does_not_keep_service_disabled(self) -> None:
        output = self.root / "review-output"
        result = self.invoke(
            output,
            proposal='enabled=true\npeer-code-requirement=cdhash H"' + "a" * 40 + '"\n',
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn(b"disabled cdhash proposal", result.stderr)
        self.assertEqual(
            [call["tool"] for call in self.tool_calls()],
            ["xattr", "codesign", "codesign", "preview"],
        )
        self.assertEqual((self.source / "Contents" / "MacOS" / "llm_interceptor").read_bytes(), b"synthetic signed source executable\n")


if __name__ == "__main__":
    unittest.main()
