#!/usr/bin/env python3
"""Focused offline checks for the private object handoff record."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from contextlib import redirect_stdout


SCRIPT = Path(__file__).with_name("record-souls-private-handoff.py")
SPEC = importlib.util.spec_from_file_location("souls_private_handoff", SCRIPT)
handoff = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handoff)
WORKFLOW_PATH = SCRIPT.parents[1] / ".github/workflows/souls-build-receipt.yml"


def bundle_store_has_digest_binding(workflow):
    section = workflow.split("      - name: Store signed receipt once and verify through separate reader\n", 1)[1]
    section = section.split("      - name: ", 1)[0]
    environment = section.split("        run: |\n", 1)[0]
    return ("          BUNDLE_SHA256: ${{ steps.receipt.outputs.bundle_sha256 }}\n" in environment and
            '--sha256 "sha256:$BUNDLE_SHA256"' in section)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class HandoffTest(unittest.TestCase):
    def test_bundle_upload_binds_its_own_digest_output(self):
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertTrue(bundle_store_has_digest_binding(workflow))
        without_binding = workflow.replace(
            "          BUNDLE_SHA256: ${{ steps.receipt.outputs.bundle_sha256 }}\n", "")
        self.assertFalse(bundle_store_has_digest_binding(without_binding))

    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.package_bytes = b"private-runtime-archive\n"
        self.bundle_bytes = b'{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}\n'
        self.package = self.root / f"sha256-{sha(self.package_bytes)}.tgz"
        self.bundle = self.root / f"sha256-{sha(self.bundle_bytes)}.sigstore.json"
        self.package.write_bytes(self.package_bytes)
        self.bundle.write_bytes(self.bundle_bytes)
        self.env = {
            "GITHUB_REPOSITORY": handoff.REPOSITORY,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW_REF": f"{handoff.REPOSITORY}/{handoff.WORKFLOW}@refs/heads/main",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "2",
        }
        predicate = {
            "source_repository": handoff.REPOSITORY,
            "source_commit": self.env["GITHUB_SHA"],
            "source_tree": "b" * 40,
            "workflow": handoff.WORKFLOW,
            "run_id": self.env["GITHUB_RUN_ID"],
            "run_attempt": 2,
            "builder_sha256": "sha256:" + "c" * 64,
        }
        self.toolchain = {
            "node_version": "v26.13.1", "node_binary_sha256": "a" * 64,
            "npm_version": "11.20.0", "npm_tree_sha256": "b" * 64,
            "cosign_version": "v3.1.4", "cosign_binary_sha256": "c" * 64,
        }
        predicate["toolchain_sha256"] = "sha256:" + sha(handoff.canonical_json(self.toolchain))
        self.write("build-inputs.json", {"predicate_type": handoff.PREDICATE_TYPE,
            "predicate": predicate,
            "subject": {"name": self.package.name, "sha256": sha(self.package_bytes)}})
        self.write("toolchain.json", self.toolchain)
        self.write("package-store-receipt.json", self.receipt("souls-package", self.package_bytes))
        self.write("bundle-store-receipt.json", self.receipt("souls-build-bundle", self.bundle_bytes))

    def write(self, name, value):
        (self.root / name).write_bytes(handoff.canonical_json(value) + b"\n")

    def receipt(self, role, data):
        digest = sha(data)
        return {
            "uri": f"qualification://stage2a/{role}/{digest}",
            "sha256": f"sha256:{digest}",
            "byte_length": len(data),
            "operator_lock_gate": {"verified_by_ci": False},
            "canary": {"scope_test_cleaned": True, "locked_overwrite_denied": True,
                       "locked_delete_denied": True, "reader_bytes_unchanged": True},
        }

    def collect(self):
        return handoff.collect(self.root, self.package, self.bundle, self.env,
                               git_identity=("a" * 40, "b" * 40))

    def test_records_exact_nonsecret_locator_and_build_identity(self):
        package_receipt = handoff.read_json(self.root / "package-store-receipt.json")
        package_receipt["secret_access_key"] = "DO_NOT_LOG_ME"
        self.write("package-store-receipt.json", package_receipt)
        record = self.collect()
        self.assertEqual(record["source_commit"], "a" * 40)
        self.assertEqual(record["source_tree"], "b" * 40)
        self.assertEqual(record["run_id"], "12345")
        self.assertEqual(record["run_attempt"], 2)
        self.assertEqual(record["runtime_npm_archive"]["byte_length"], len(self.package_bytes))
        self.assertEqual(record["souls_build_bundle"]["sha256"], f"sha256:{sha(self.bundle_bytes)}")
        self.assertEqual(record["toolchain"], self.toolchain)
        self.assertEqual(record["toolchain_file_sha256"],
                         "sha256:" + sha((self.root / "toolchain.json").read_bytes()))
        output = io.StringIO()
        summary = self.root / "summary.md"
        with redirect_stdout(output):
            handoff.emit(record, summary, self.root / "private-handoff.json")
        self.assertEqual(json.loads((self.root / "private-handoff.json").read_text()), record)
        self.assertIn("qualification://stage2a/souls-build-bundle/", output.getvalue())
        self.assertIn("souls-private-r2-handoff-v1", summary.read_text())
        self.assertNotIn("DO_NOT_LOG_ME", output.getvalue() + summary.read_text())
        self.assertNotIn("secret_access_key", output.getvalue() + summary.read_text())

    def test_wrong_digest_length_or_role_is_rejected(self):
        for field, value in (("sha256", "sha256:" + "0" * 64),
                             ("byte_length", len(self.package_bytes) + 1),
                             ("uri", "qualification://stage2a/qualification/" + sha(self.package_bytes))):
            with self.subTest(field=field):
                receipt = self.receipt("souls-package", self.package_bytes)
                receipt[field] = value
                self.write("package-store-receipt.json", receipt)
                with self.assertRaisesRegex(ValueError, "private store"):
                    self.collect()
        self.write("package-store-receipt.json", self.receipt("souls-package", self.package_bytes))

    def test_changed_file_and_canary_failure_are_rejected(self):
        self.package.write_bytes(b"changed\n")
        with self.assertRaisesRegex(ValueError, "private store"):
            self.collect()
        self.package.write_bytes(self.package_bytes)
        receipt = self.receipt("souls-build-bundle", self.bundle_bytes)
        receipt["canary"]["locked_delete_denied"] = False
        self.write("bundle-store-receipt.json", receipt)
        with self.assertRaisesRegex(ValueError, "lock canary"):
            self.collect()

    def test_wrong_actions_identity_or_subject_is_rejected(self):
        self.env["GITHUB_SHA"] = "c" * 40
        with self.assertRaisesRegex(ValueError, "checked-out Git objects"):
            self.collect()
        self.env["GITHUB_SHA"] = "a" * 40
        self.env["GITHUB_REF"] = "refs/heads/feature"
        with self.assertRaisesRegex(ValueError, "source ref"):
            self.collect()
        self.env["GITHUB_REF"] = "refs/heads/main"
        inputs = handoff.read_json(self.root / "build-inputs.json")
        inputs["subject"]["sha256"] = "0" * 64
        self.write("build-inputs.json", inputs)
        with self.assertRaisesRegex(ValueError, "build subject"):
            self.collect()

    def test_checked_out_git_objects_must_match_build_claim(self):
        with self.assertRaisesRegex(ValueError, "checked-out Git objects"):
            handoff.collect(self.root, self.package, self.bundle, self.env,
                            git_identity=("a" * 40, "c" * 40))

    def test_changed_toolchain_inventory_is_rejected(self):
        changed = dict(self.toolchain)
        changed["npm_version"] = "11.20.1"
        self.write("toolchain.json", changed)
        with self.assertRaisesRegex(ValueError, "build toolchain differs"):
            self.collect()

    def test_symlinked_asset_is_rejected(self):
        target = self.root / "target"
        target.write_bytes(self.bundle_bytes)
        self.bundle.unlink()
        self.bundle.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "cannot be read"):
            self.collect()


if __name__ == "__main__":
    unittest.main()
