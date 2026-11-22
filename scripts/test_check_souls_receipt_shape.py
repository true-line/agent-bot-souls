"""Exercise the receipt shape CLI with a pinned Sigstore v0.3 layout fixture.

The fixture's signing bytes are synthetic. These tests check structural and
build-claim validation, not cryptographic verification.
"""

import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts/check-souls-receipt-shape.py"
FIXTURE = ROOT / "scripts/fixtures/souls-receipt-v0.3.bundle.json"
ARCHIVE = base64.b64decode(
    "H4sIAAAAAAAC/+3NPQoCMRiE4a/2FDmBZkmwF9zSRk8Qlk9dFAz5gT2+0UbYehHB92lmmGZiGG7hoptjv9sf+nWZiizONlvv39nM01rnP/21d511ToyVL6i5hNTu5T+dHvWeTdJBx1hMvoao5jxOpSZdCQAAAAAAAAAAAAAAAADgZz0By8QxVwAoAAA="
)
ARCHIVE_SHA256 = "b994adcb75eeaa96ec21930403030d4d3186cfd4dbbeeea672e7d4f84280cc44"
PREDICATE_TYPE = "https://true-line.ai/soul-contracts/adapter/v2/souls-build"
PREDICATE = {
    "source_repository": "true-line/agent-bot-souls",
    "source_commit": "1" * 40,
    "source_tree": "2" * 40,
    "builder_sha256": "sha256:" + "3" * 64,
    "toolchain_sha256": "sha256:" + "4" * 64,
    "workflow": ".github/workflows/souls-build-receipt.yml",
    "run_id": "1234567890",
    "run_attempt": 1,
}


class ReceiptShapeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.archive = self.directory / f"sha256-{ARCHIVE_SHA256}.tgz"
        self.archive.write_bytes(ARCHIVE)
        self.inputs = self.directory / "build-inputs.json"
        self.inputs.write_text(json.dumps({
            "predicate_type": PREDICATE_TYPE,
            "predicate": PREDICATE,
            "subject": {"name": self.archive.name, "sha256": ARCHIVE_SHA256},
        }))
        self.bundle = json.loads(FIXTURE.read_text())

    def check(self):
        path = self.directory / "receipt.bundle.json"
        path.write_text(json.dumps(self.bundle))
        result = subprocess.run(
            [sys.executable, str(CHECKER), str(path), str(self.inputs), str(self.archive)],
            capture_output=True, text=True, check=False,
        )
        return result, path

    def test_top_level_v03_dsse_bundle_matches_archive(self):
        self.assertEqual(hashlib.sha256(ARCHIVE).hexdigest(), ARCHIVE_SHA256)
        result, path = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout)
        self.assertEqual(evidence["package_sha256"], ARCHIVE_SHA256)
        self.assertEqual(evidence["bundle_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(evidence["source_commit"], PREDICATE["source_commit"])

    def test_legacy_nested_content_bundle_is_refused(self):
        self.bundle["content"] = {"dsseEnvelope": self.bundle.pop("dsseEnvelope")}
        result, _ = self.check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("top-level DSSE envelope", result.stderr)

    def test_extra_content_wrapper_is_refused(self):
        self.bundle["content"] = {"dsseEnvelope": self.bundle["dsseEnvelope"]}
        result, _ = self.check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("top-level DSSE envelope", result.stderr)


if __name__ == "__main__":
    unittest.main()
