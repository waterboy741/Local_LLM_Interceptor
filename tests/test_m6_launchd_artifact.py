"""Offline checks for the staged launchd helper artifact."""

from __future__ import annotations

import os
import plistlib
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
                    str(helper),
                    "--output-dir",
                    str(stage),
                ],
                cwd=REPOSITORY_ROOT,
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
            with staged_plist.open("rb") as plist_file:
                self.assertEqual(plistlib.load(plist_file), self.load_plist())

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
