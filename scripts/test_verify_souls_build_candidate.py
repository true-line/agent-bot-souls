"""Boundary tests for the local candidate checker; synthetic Cosign is not proof."""

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("verify-souls-build-candidate.py")
SPEC = importlib.util.spec_from_file_location("souls_candidate", SCRIPT)
candidate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(candidate)


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


class CandidateVerificationTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.archive_bytes = b"runtime archive fixture\n"
        self.archive = self.root / f"sha256-{sha(self.archive_bytes)[7:]}.tgz"
        self.archive.write_bytes(self.archive_bytes)
        self.trusted_root = self.root / "trusted-root.json"
        self.trusted_root.write_bytes(b'{"trusted":"fixture"}\n')
        self.cosign = self.root / "cosign"
        self.cosign.write_bytes(b"#!/bin/sh\nexit 0\n")
        self.cosign.chmod(0o700)
        self.source_commit = "a" * 40
        self.source_tree = "b" * 40
        self.builder_sha256 = sha(b"builder")
        self.toolchain_sha256 = sha(b"toolchain")
        self.statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": self.archive.name,
                         "digest": {"sha256": sha(self.archive_bytes)[7:]}}],
            "predicateType": candidate.PREDICATE,
            "predicate": {
                "source_repository": candidate.REPO,
                "source_commit": self.source_commit,
                "source_tree": self.source_tree,
                "builder_sha256": self.builder_sha256,
                "toolchain_sha256": self.toolchain_sha256,
                "workflow": candidate.WORKFLOW,
                "run_id": "12345",
                "run_attempt": 1,
            },
        }
        self.bundle = {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "dsseEnvelope": {"payloadType": "application/vnd.in-toto+json",
                             "payload": "", "signatures": [{"sig": "synthetic"}]},
            "verificationMaterial": {"certificate": {},
                                     "tlogEntries": [{"inclusionProof": {"checkpoint": "synthetic"}}]},
        }
        self.handoff = {
            "schema": "souls-private-r2-handoff-v1",
            "source_repository": candidate.REPO,
            "source_commit": self.source_commit,
            "source_tree": self.source_tree,
            "workflow": candidate.WORKFLOW,
            "run_id": "12345",
            "run_attempt": 1,
            "runtime_npm_archive": self.asset("souls-package", self.archive_bytes),
            "souls_build_bundle": {},
        }
        self.write_bundle()
        self.args = SimpleNamespace(
            archive=self.archive, bundle=self.bundle_path, handoff=self.handoff_path,
            trusted_root=self.trusted_root, cosign=self.cosign,
            trusted_root_sha256=sha(self.trusted_root.read_bytes()),
            cosign_sha256=sha(self.cosign.read_bytes()),
            source_commit=self.source_commit, source_tree=self.source_tree,
            builder_sha256=self.builder_sha256,
            toolchain_sha256=self.toolchain_sha256,
        )

    def asset(self, role, data):
        digest = sha(data)
        return {"uri": f"qualification://stage2a/{role}/{digest[7:]}",
                "sha256": digest, "byte_length": len(data)}

    def write_bundle(self):
        payload = (json.dumps(self.statement, sort_keys=True, separators=(",", ":")) + "\n").encode()
        self.bundle["dsseEnvelope"]["payload"] = base64.b64encode(payload).decode()
        data = (json.dumps(self.bundle, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if hasattr(self, "bundle_path"):
            self.bundle_path.unlink()
        self.bundle_path = self.root / f"sha256-{sha(data)[7:]}.sigstore.json"
        self.bundle_path.write_bytes(data)
        self.handoff["souls_build_bundle"] = self.asset("souls-build-bundle", data)
        self.handoff_path = self.root / "private-handoff.json"
        self.handoff_path.write_text(json.dumps(self.handoff))
        if hasattr(self, "args"):
            self.args.bundle = self.bundle_path

    def test_matching_synthetic_shape_reaches_pinned_cosign_and_records_limits(self):
        real_run = candidate.subprocess.run
        with patch.object(candidate.subprocess, "run", wraps=real_run) as run:
            record = candidate.verify(self.args)
        argv = run.call_args.args[0]
        self.assertEqual(argv[0:2], [str(self.cosign), "verify-blob-attestation"])
        self.assertIn("--check-claims=true", argv)
        self.assertEqual(argv[argv.index("--type") + 1], candidate.PREDICATE)
        self.assertEqual(argv[argv.index("--certificate-github-workflow-sha") + 1],
                         self.source_commit)
        self.assertEqual(argv[-1], str(self.archive))
        self.assertEqual(record["archive_sha256"], sha(self.archive_bytes))
        self.assertEqual(record["bundle_sha256"], sha(self.bundle_path.read_bytes()))
        self.assertFalse(record["release_certified"])
        self.assertFalse(record["physical_qualification"])
        self.assertFalse(record["network_isolation_verified_by_this_command"])

    def test_altered_archive_and_wrong_approved_source_refuse(self):
        self.archive.write_bytes(b"changed runtime\n")
        with self.assertRaisesRegex(ValueError, "asset bytes differ"):
            candidate.verify(self.args)
        self.archive.write_bytes(self.archive_bytes)
        self.args.source_commit = "c" * 40
        with self.assertRaisesRegex(ValueError, "handoff source differs"):
            candidate.verify(self.args)

    def test_changed_signed_subject_and_trusted_root_refuse(self):
        self.statement["subject"][0]["digest"]["sha256"] = "f" * 64
        self.write_bundle()
        with self.assertRaisesRegex(ValueError, "signed subject differs"):
            candidate.verify(self.args)
        self.statement["subject"][0]["digest"]["sha256"] = sha(self.archive_bytes)[7:]
        self.write_bundle()
        self.args.trusted_root_sha256 = sha(b"wrong root")
        with self.assertRaisesRegex(ValueError, "trusted root differs"):
            candidate.verify(self.args)

    def test_cosign_refusal_cannot_produce_a_positive_record(self):
        self.cosign.write_bytes(b"#!/bin/sh\nexit 1\n")
        self.args.cosign_sha256 = sha(self.cosign.read_bytes())
        with self.assertRaisesRegex(ValueError, "pinned Cosign refused"):
            candidate.verify(self.args)


if __name__ == "__main__":
    unittest.main()
