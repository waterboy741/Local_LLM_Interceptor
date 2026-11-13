"""Exercise GUI review staging with macOS codesign and the built preview tool."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "stage_signed_gui_review.py"
CODESIGN = "/usr/bin/codesign"


def bundle_contents(app: Path) -> dict[Path, str]:
    return {
        path.relative_to(app): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in app.rglob("*")
        if path.is_file()
    }


def run(*command: str | Path, timeout: int = 30) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command, capture_output=True, check=False, timeout=timeout)


class CodesignSmokeTests(unittest.TestCase):
    def assert_success(self, result: subprocess.CompletedProcess[bytes]) -> None:
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))

    def test_stages_and_verifies_real_ad_hoc_signed_app(self) -> None:
        source = args.app.resolve(strict=True)
        preview_tool = args.preview_tool.resolve(strict=True)
        original_contents = bundle_contents(source)
        original_signature = run(CODESIGN, "--display", "--verbose=4", source)

        # The default macOS temporary directory is under /private/var, which staging rejects.
        with tempfile.TemporaryDirectory(prefix="codesign-smoke-", dir="/private/tmp") as temp:
            output = Path(temp) / "review"
            staged = output / source.name
            result = run(
                sys.executable, SCRIPT_PATH, "--app", source, "--output-dir", output,
                "--preview-tool", preview_tool, timeout=45,
            )

            self.assert_success(result)
            self.assert_success(run(CODESIGN, "--verify", "--strict", "--deep", staged))
            requirement = run(CODESIGN, "--display", "-r-", staged)
            self.assert_success(requirement)
            match = re.search(
                rb'^# designated => cdhash H"([0-9a-fA-F]{40}|[0-9a-fA-F]{64})"$',
                requirement.stdout + b"\n" + requirement.stderr,
                re.MULTILINE,
            )
            self.assertIsNotNone(match, (requirement.stdout, requirement.stderr))
            assert match is not None
            expected_hash = match.group(1).lower()
            expected_output = (
                f"staged_app={staged}\n".encode()
                + b'enabled=false\npeer-code-requirement=cdhash H"'
                + expected_hash
                + b'"\n'
            )
            self.assertEqual(result.stdout, expected_output)

        self.assertEqual(bundle_contents(source), original_contents)
        final_signature = run(CODESIGN, "--display", "--verbose=4", source)
        self.assertEqual(final_signature.returncode, original_signature.returncode)
        self.assertEqual(final_signature.stdout, original_signature.stdout)
        self.assertEqual(final_signature.stderr, original_signature.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", required=True, type=Path)
    parser.add_argument("--preview-tool", required=True, type=Path)
    args = parser.parse_args()
    unittest.main(argv=[sys.argv[0]])
