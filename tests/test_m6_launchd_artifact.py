"""Offline checks for the staged launchd helper artifact."""

from __future__ import annotations

import os
import plistlib
import runpy
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PLIST_PATH = (
    REPOSITORY_ROOT
    / "resources"
    / "launchd"
    / "org.local-llm-interceptor.helper.plist"
)
PACKAGER_PATH = REPOSITORY_ROOT / "scripts" / "package_launchd_helper.py"
CONTRACT_DOC_PATH = REPOSITORY_ROOT / "docs" / "m6" / "INSTALLED_HELPER_BOOTSTRAP.md"
SERVICE_LABEL = "org.local-llm-interceptor.helper"
HELPER_ARGUMENTS = [
    "/Library/PrivilegedHelperTools/llm_interceptor_helper",
    "--mach-service",
    "--state-dir",
    "/private/var/db/llm_interceptor",
]


class M6LaunchdArtifactTests(unittest.TestCase):
    def run_packager(self, helper: Path, output: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(PACKAGER_PATH),
                "--helper",
                str(helper),
                "--output-dir",
                str(output),
            ],
            cwd=REPOSITORY_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_packager_rejects_private_etc(self) -> None:
        validate = runpy.run_path(str(PACKAGER_PATH))["validate_staging_directory"]
        # Check validation directly so a regression cannot write under /private.
        for output in (Path("/private/etc"), Path("/private/Etc")):
            with self.subTest(output=output):
                with self.assertRaisesRegex(ValueError, "system"):
                    validate(output)

    def validate_plist_bytes(self, contents: bytes) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temp_name:
            root = Path(temp_name)
            packager = root / PACKAGER_PATH.relative_to(REPOSITORY_ROOT)
            packager.parent.mkdir()
            shutil.copyfile(PACKAGER_PATH, packager)
            plist = root / PLIST_PATH.relative_to(REPOSITORY_ROOT)
            plist.parent.mkdir(parents=True)
            plist.write_bytes(contents)

            return subprocess.run(
                [sys.executable, str(packager), "--validate-only"],
                cwd=root,
                text=True,
                capture_output=True,
                check=False,
            )

    def test_packager_rejects_integer_mach_service(self) -> None:
        config = self.load_plist()
        config["MachServices"] = {SERVICE_LABEL: 1}
        result = self.validate_plist_bytes(plistlib.dumps(config))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("launchd_helper_package_error", result.stderr)

    def test_packager_rejects_duplicate_plist_key(self) -> None:
        contents = plistlib.dumps(self.load_plist())
        duplicate = contents.replace(
            b"<key>UserName</key>",
            b"<key>UserName</key><string>nobody</string><key>UserName</key>",
        )
        self.assertNotEqual(duplicate, contents)
        result = self.validate_plist_bytes(duplicate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate launchd plist key", result.stderr)

    def test_packager_rejects_paths_traversing_through_a_file(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temp_name:
            root = Path(temp_name)
            helper = root / "helper"
            helper.write_bytes(b"synthetic helper")
            stage = root / "stage"
            for source, output in (
                (helper, helper / ".." / "stage"),
                (helper / ".." / "helper", stage),
            ):
                with self.subTest(source=source, output=output):
                    result = self.run_packager(source, output)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("parent traversal", result.stderr)
                    self.assertFalse(stage.exists())

    def test_packager_accepts_existing_empty_output(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temp_name:
            root = Path(temp_name)
            helper = root / "helper"
            helper.write_bytes(b"synthetic helper")
            stage = root / "stage"
            stage.mkdir()

            result = self.run_packager(helper, stage)

            self.assertEqual(result.returncode, 0, result.stderr)
            staged_helper = (
                stage / "Library" / "PrivilegedHelperTools" / "llm_interceptor_helper"
            )
            self.assertEqual(staged_helper.read_bytes(), helper.read_bytes())

    def test_packager_rejects_symlinked_output_ancestor(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temp_name:
            root = Path(temp_name)
            helper = root / "helper"
            helper.write_bytes(b"synthetic helper")
            target = root / "target"
            target.mkdir()
            alias = root / "alias"
            alias.symlink_to(target, target_is_directory=True)

            result = self.run_packager(helper, alias / "stage")

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("symlink", result.stderr)
            self.assertEqual(list(target.iterdir()), [])

    def test_packager_rejects_symlinked_helper_ancestor(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temp_name:
            root = Path(temp_name)
            target = root / "target"
            target.mkdir()
            (target / "helper").write_bytes(b"synthetic helper")
            alias = root / "alias"
            alias.symlink_to(target, target_is_directory=True)
            stage = root / "stage"

            result = self.run_packager(alias / "helper", stage)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("symlink", result.stderr)
            self.assertFalse(stage.exists())

    def test_packager_rejects_input_inside_output(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temp_name:
            stage = Path(temp_name)
            helper = stage / "helper"
            original = b"synthetic helper"
            helper.write_bytes(original)

            result = self.run_packager(helper, stage)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("disjoint", result.stderr)
            self.assertEqual(list(stage.iterdir()), [helper])
            self.assertEqual(helper.read_bytes(), original)

    def test_packager_rejects_output_inside_input(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temp_name:
            helper = Path(temp_name) / "helper"
            original = b"synthetic helper"
            helper.write_bytes(original)

            result = self.run_packager(helper, helper / "stage")

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("disjoint", result.stderr)
            self.assertEqual(helper.read_bytes(), original)

    def test_packager_rejects_reusing_nonempty_output(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temp_name:
            root = Path(temp_name)
            helper = root / "helper"
            helper.write_bytes(b"synthetic helper")
            stage = root / "stage"
            stage.mkdir()
            existing = stage / "keep"
            original = b"existing content"
            existing.write_bytes(original)

            result = self.run_packager(helper, stage)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("empty", result.stderr)
            self.assertEqual(list(stage.iterdir()), [existing])
            self.assertEqual(existing.read_bytes(), original)

    def load_plist(self) -> dict[str, object]:
        with PLIST_PATH.open("rb") as plist_file:
            value = plistlib.load(plist_file)
        self.assertIsInstance(value, dict)
        return value

    def test_plist_has_exact_read_only_service_contract(self) -> None:
        self.assertTrue(PLIST_PATH.is_file())
        plist = self.load_plist()

        self.assertEqual(
            set(plist),
            {"Label", "ProgramArguments", "MachServices", "UserName", "GroupName"},
        )
        self.assertEqual(plist["Label"], SERVICE_LABEL)
        self.assertEqual(plist["MachServices"], {SERVICE_LABEL: True})
        self.assertEqual(plist["ProgramArguments"], HELPER_ARGUMENTS)
        self.assertEqual(plist["UserName"], "root")
        self.assertEqual(plist["GroupName"], "wheel")

        arguments = plist["ProgramArguments"]
        self.assertIsInstance(arguments, list)
        self.assertNotIn("sh", arguments)
        self.assertNotIn("-c", arguments)
        self.assertNotIn("sudo", arguments)
        self.assertNotIn("launchctl", arguments)
        self.assertNotIn("--install", arguments)

    def test_documented_staging_paths_and_modes_match_artifact(self) -> None:
        documentation = CONTRACT_DOC_PATH.read_text(encoding="utf-8")
        for contract in (
            "resources/launchd/org.local-llm-interceptor.helper.plist",
            "/Library/PrivilegedHelperTools/llm_interceptor_helper",
            "/Library/LaunchDaemons/org.local-llm-interceptor.helper.plist",
            "0755",
            "0644",
            "python3 scripts/package_launchd_helper.py",
            "not installed, bootstrapped, or enabled",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, documentation)

    def test_packager_validates_and_stages_only_to_requested_directory(self) -> None:
        self.assertTrue(PACKAGER_PATH.is_file())
        validation = subprocess.run(
            [sys.executable, str(PACKAGER_PATH), "--validate-only"],
            cwd=REPOSITORY_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(validation.returncode, 0, validation.stderr)

        with tempfile.TemporaryDirectory(
            prefix="launchd-stage-test-", dir="/private/tmp"
        ) as temp_name:
            temp_root = Path(temp_name)
            helper = temp_root / "helper-input"
            helper.write_bytes(b"synthetic helper executable\n")
            helper.chmod(0o755)
            stage = temp_root / "staging"

            # If the packager tries to activate the service, this stub records it.
            fake_bin = temp_root / "bin"
            fake_bin.mkdir()
            invocation_marker = temp_root / "launchctl-was-called"
            launchctl_stub = fake_bin / "launchctl"
            launchctl_stub.write_text(
                f"#!/bin/sh\nprintf called > {invocation_marker}\n", encoding="utf-8"
            )
            launchctl_stub.chmod(0o755)
            environment = os.environ.copy()
            environment["PATH"] = str(fake_bin)

            result = subprocess.run(
                [
                    sys.executable,
                    str(PACKAGER_PATH),
                    "--helper",
                    helper.name,
                    "--output-dir",
                    str(stage),
                ],
                cwd=temp_root,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(invocation_marker.exists())

            staged_helper = (
                stage / "Library" / "PrivilegedHelperTools" / "llm_interceptor_helper"
            )
            staged_plist = (
                stage
                / "Library"
                / "LaunchDaemons"
                / "org.local-llm-interceptor.helper.plist"
            )
            self.assertEqual(staged_helper.read_bytes(), helper.read_bytes())
            self.assertEqual(stat.S_IMODE(staged_helper.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(staged_plist.stat().st_mode), 0o644)
            self.assertEqual(staged_plist.read_bytes(), PLIST_PATH.read_bytes())

            staged_files = {
                path.relative_to(stage).as_posix()
                for path in stage.rglob("*")
                if path.is_file()
            }
            self.assertEqual(
                staged_files,
                {
                    "Library/PrivilegedHelperTools/llm_interceptor_helper",
                    "Library/LaunchDaemons/org.local-llm-interceptor.helper.plist",
                },
            )


if __name__ == "__main__":
    unittest.main()
