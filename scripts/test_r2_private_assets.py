"""Security boundary checks for the held Stage 2a private transport draft."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError


SCRIPT = Path(__file__).with_name("r2-private-assets.py")
spec = importlib.util.spec_from_file_location("r2_private_assets", SCRIPT)
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)


class PrivateTransportTest(unittest.TestCase):
    def setUp(self):
        self.bytes = b"synthetic nonprivate receipt bytes\n"
        self.digest = hashlib.sha256(self.bytes).hexdigest()
        self.uri, self.key = transport.asset_ref("souls-build-bundle", self.digest)
        self.gate = {"evidence_sha256": f"sha256:{self.digest}", "verified_by_ci": False}

    def test_logical_reference_is_exact_and_under_locked_prefix(self):
        self.assertEqual(self.key, f"v1/souls-build-bundle/{self.digest}")
        self.assertEqual(transport.key_for_ref(self.uri, self.digest), self.key)
        for bad in (
            self.uri + "?token=secret", self.uri + "/extra", self.uri.replace("souls-build-bundle", "other"),
            self.uri.replace(self.digest, "0" * 64),
            f"s3://{transport.BUCKET}/{self.key}",
            self.uri.replace("stage2a", "stage2a/%2e%2e"),
        ):
            with self.subTest(bad=bad), self.assertRaises(transport.TransportError):
                transport.key_for_ref(bad, self.digest)

    def test_operator_gate_requires_fresh_evidence_digest_and_utc_time(self):
        now = datetime(2026, 11, 21, 23, 0, tzinfo=timezone.utc)
        valid = {"R2_STAGE_LOCK_ATTESTATION_SHA256": self.digest,
                 "R2_STAGE_LOCK_ATTESTED_AT_UTC": "2026-11-21T22:30:00Z"}
        with patch.dict("os.environ", valid):
            gate = transport.require_operator_lock_gate(now)
        self.assertEqual(gate["evidence_sha256"], f"sha256:{self.digest}")
        self.assertFalse(gate["verified_by_ci"])
        for changed in (
            {**valid, "R2_STAGE_LOCK_ATTESTATION_SHA256": ""},
            {**valid, "R2_STAGE_LOCK_ATTESTED_AT_UTC": ""},
            {**valid, "R2_STAGE_LOCK_ATTESTED_AT_UTC": "2026-11-21T21:59:59Z"},
            {**valid, "R2_STAGE_LOCK_ATTESTED_AT_UTC": "2026-11-21T23:01:00Z"},
            {**valid, "R2_STAGE_LOCK_ATTESTED_AT_UTC": "2026-11-21T22:30:00+00:00"},
        ):
            with self.subTest(changed=changed), patch.dict("os.environ", changed), \
                    self.assertRaises(transport.TransportError):
                transport.require_operator_lock_gate(now)

    def test_request_guard_refuses_redirect_wrong_host_and_path_encoding(self):
        correct = f"{transport.ENDPOINT}/{transport.BUCKET}/{self.key}"
        transport.guard_request(SimpleNamespace(method="GET", url=correct), "GET", self.key)
        for url in (
            correct.replace(transport.S3_HOST, "other.example"),
            correct.replace("/v1/", "/%76%31/"),
            correct + "?token=secret",
            correct.replace("https://", "http://"),
        ):
            with self.subTest(url=url), self.assertRaises(transport.TransportError):
                transport.guard_request(SimpleNamespace(method="GET", url=url), "GET", self.key)
        with self.assertRaises(transport.TransportError):
            transport.guard_request(SimpleNamespace(method="PUT", url=correct), "GET", self.key)
        for status in (301, 302, 307, 308):
            with self.subTest(status=status), self.assertRaises(transport.TransportError):
                transport.reject_redirect((SimpleNamespace(status_code=status), {}))

    def test_sdk_hooks_reject_unpinned_request_and_redirect(self):
        with patch.dict("os.environ", {
            "R2_STAGE_READ_ACCESS_KEY_ID": "reader-test-key",
            "R2_STAGE_READ_SECRET_ACCESS_KEY": "reader-test-secret",
            "R2_STAGE_WRITE_ACCESS_KEY_ID": "writer-test-key",
        }):
            client = transport.s3_client("READ", "GET", self.key)
        correct = f"{transport.ENDPOINT}/{transport.BUCKET}/{self.key}"
        for url in (correct.replace(transport.S3_HOST, "wrong.example"),
                    correct.replace("/v1/", "/%76%31/")):
            with self.subTest(url=url), self.assertRaises(transport.TransportError):
                client.meta.events.emit("before-send.s3.GetObject",
                                        request=SimpleNamespace(method="GET", url=url))
        for status in (301, 302, 307, 308):
            with self.subTest(status=status), self.assertRaises(transport.TransportError):
                client.meta.events.emit("needs-retry.s3.GetObject",
                                        response=(SimpleNamespace(status_code=status), {}))

    def test_s3_put_is_conditional(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.write_bytes(self.bytes)
            client = Mock()
            with patch.object(transport, "s3_client", return_value=client):
                transport.s3_request("PUT", self.key, "WRITE", source=source)
            kwargs = client.put_object.call_args.kwargs
            self.assertEqual((kwargs["Bucket"], kwargs["Key"], kwargs["IfNoneMatch"]),
                             (transport.BUCKET, self.key, "*"))
            self.assertEqual(kwargs["ContentLength"], len(self.bytes))

    def test_bucket_scoped_canary_requires_real_lock_and_writer_mutation(self):
        class FakeBucket:
            def __init__(self, locked=True, can_mutate=True):
                self.objects = {}
                self.locked = locked
                self.can_mutate = can_mutate

            def error(self, status, code, operation):
                raise ClientError({"ResponseMetadata": {"HTTPStatusCode": status},
                                   "Error": {"Code": code, "Message": code}}, operation)

            def get_object(self, Bucket, Key):
                if Bucket != transport.BUCKET:
                    self.error(403, "AccessDenied", "GetObject")
                if Key not in self.objects:
                    self.error(404, "NoSuchKey", "GetObject")
                return {"Body": io.BytesIO(self.objects[Key])}

            def put_object(self, Bucket, Key, Body, ContentLength, IfNoneMatch=None):
                if Bucket != transport.BUCKET:
                    self.error(403, "AccessDenied", "PutObject")
                if Key in self.objects and Key.startswith("v1/") and self.locked:
                    self.error(409, "ObjectLockedByBucketPolicy", "PutObject")
                if Key in self.objects and not self.can_mutate:
                    self.error(403, "AccessDenied", "PutObject")
                if Key in self.objects and IfNoneMatch == "*":
                    self.error(412, "PreconditionFailed", "PutObject")
                self.objects[Key] = Body

            def delete_object(self, Bucket, Key):
                if Bucket != transport.BUCKET:
                    self.error(403, "AccessDenied", "DeleteObject")
                if Key in self.objects and Key.startswith("v1/") and self.locked:
                    self.error(409, "ObjectLockedByBucketPolicy", "DeleteObject")
                if not self.can_mutate:
                    self.error(403, "AccessDenied", "DeleteObject")
                self.objects.pop(Key, None)

        nonce = "1" * 32
        for locked, can_mutate, succeeds in ((True, True, True),
                                              (False, True, False),
                                              (True, False, False)):
            bucket = FakeBucket(locked, can_mutate)
            with self.subTest(locked=locked, can_mutate=can_mutate), \
                    patch.object(transport.secrets, "token_hex", return_value=nonce), \
                    patch.object(transport, "probe_client", return_value=bucket):
                if succeeds:
                    proof = transport.prove_bucket_lock()
                    self.assertTrue(proof["scope_test_cleaned"])
                    self.assertTrue(proof["reader_bytes_unchanged"])
                    refusal = {"http_status": 409, "error_code": "ObjectLockedByBucketPolicy"}
                    self.assertEqual(proof["overwrite_refusal"], refusal)
                    self.assertEqual(proof["delete_refusal"], refusal)
                    self.assertEqual(proof["reader_readback"]["sha256"], proof["sha256"])
                    self.assertEqual(proof["reader_readback"]["byte_length"],
                                     len(bucket.objects[f"v1/canary/{nonce}"]))
                    self.assertEqual(set(bucket.objects), {f"v1/canary/{nonce}"})
                else:
                    with self.assertRaises(transport.TransportError):
                        transport.prove_bucket_lock()

    def test_lock_refusal_must_have_exact_status_and_code(self):
        def refusal(status, code):
            raise ClientError({"ResponseMetadata": {"HTTPStatusCode": status},
                               "Error": {"Code": code, "Message": code}}, "PutObject")

        self.assertEqual(transport.require_lock_rejection(
            lambda: refusal(409, "ObjectLockedByBucketPolicy")),
            {"http_status": 409, "error_code": "ObjectLockedByBucketPolicy"})
        for status, code in ((403, "AccessDenied"), (412, "PreconditionFailed"),
                             (409, "PreconditionFailed"), (200, "ObjectLockedByBucketPolicy")):
            with self.subTest(status=status, code=code), self.assertRaises(transport.TransportError):
                transport.require_lock_rejection(lambda: refusal(status, code))
        with self.assertRaisesRegex(transport.TransportError, "not protected"):
            transport.require_lock_rejection(lambda: None)

    def test_scope_probe_failure_cleans_disposable_before_canary(self):
        nonce = "2" * 32
        disposable = f"scope-test/{nonce}"
        canary = f"v1/canary/{nonce}"
        for failed_step in ("read", "overwrite", "delete"):
            calls = []
            failed = False

            def get(key, expected=None):
                calls.append(("get", key, expected))
                if (failed_step == "read" and key == disposable and expected is not None
                        and not failed):
                    raise transport.TransportError("simulated read failure")

            def put(key, data, conditional):
                calls.append(("put", key, conditional))
                if failed_step == "overwrite" and not conditional:
                    raise transport.TransportError("simulated overwrite failure")

            def delete(key):
                nonlocal failed
                calls.append(("delete", key))
                if failed_step == "delete" and not failed:
                    failed = True
                    raise transport.TransportError("simulated delete failure")

            with self.subTest(failed_step=failed_step), \
                    patch.object(transport.secrets, "token_hex", return_value=nonce), \
                    patch.object(transport, "probe_get", side_effect=get), \
                    patch.object(transport, "probe_put", side_effect=put), \
                    patch.object(transport, "probe_delete", side_effect=delete):
                if failed_step == "delete":
                    with self.assertRaisesRegex(transport.TransportError, "cleanup failed"):
                        transport.prove_bucket_lock()
                else:
                    label = "first read failed" if failed_step == "read" else "overwrite failed"
                    with self.assertRaisesRegex(transport.TransportError, label):
                        transport.prove_bucket_lock()
            self.assertIn(("delete", disposable), calls)
            self.assertNotIn(("delete", canary), calls)
            self.assertFalse(any(call[1] == canary for call in calls))
            if failed_step != "delete":
                self.assertEqual(calls[-1], ("get", disposable, None))

    def test_scope_probe_reports_first_failure_even_when_cleanup_fails(self):
        nonce = "3" * 32
        disposable = f"scope-test/{nonce}"
        calls = []

        def get(key, expected=None):
            calls.append(("get", key, expected))

        def put(key, data, conditional):
            calls.append(("put", key, conditional))
            raise transport.TransportError("private probe create or overwrite failed")

        def delete(key):
            calls.append(("delete", key))
            raise transport.TransportError("private probe delete failed")

        with patch.object(transport.secrets, "token_hex", return_value=nonce), \
                patch.object(transport, "probe_get", side_effect=get), \
                patch.object(transport, "probe_put", side_effect=put), \
                patch.object(transport, "probe_delete", side_effect=delete):
            with self.assertRaisesRegex(transport.TransportError,
                                        r"create failed; private scope-test cleanup failed \(delete\)"):
                transport.prove_bucket_lock()
        self.assertEqual(calls, [("get", disposable, None),
                                 ("put", disposable, True),
                                 ("delete", disposable),
                                 ("get", disposable, None)])

    def test_canary_receipt_is_private_and_does_not_use_release_gate(self):
        proof = {"key": "v1/canary/" + "1" * 32,
                 "overwrite_refusal": {"http_status": 409,
                                       "error_code": "ObjectLockedByBucketPolicy"},
                 "delete_refusal": {"http_status": 409,
                                    "error_code": "ObjectLockedByBucketPolicy"},
                 "reader_readback": {"sha256": f"sha256:{self.digest}",
                                     "byte_length": len(self.bytes)}}
        stored = {}

        def store(method, key, kind, source):
            self.assertEqual((method, kind), ("PUT", "WRITE"))
            self.assertRegex(key, r"\Av1/canary-receipt/[0-9a-f]{64}\Z")
            stored["key"] = key
            stored["bytes"] = source.read_bytes()

        def readback(key, digest, length, destination):
            self.assertEqual(key, stored["key"])
            self.assertEqual(digest, hashlib.sha256(stored["bytes"]).hexdigest())
            self.assertEqual(length, len(stored["bytes"]))
            destination.write_bytes(stored["bytes"])

        with patch.object(transport, "require_operator_lock_gate",
                          side_effect=AssertionError("release gate used")), \
                patch.object(transport, "prove_bucket_lock", return_value=proof), \
                patch.object(transport, "s3_request", side_effect=store), \
                patch.object(transport, "download_verified", side_effect=readback), \
                patch.object(transport, "put", side_effect=AssertionError("release upload used")):
            result = transport.canary()
        receipt = json.loads(stored["bytes"])
        self.assertEqual(receipt["canary"], proof)
        self.assertEqual(result["result"], "pass")
        self.assertFalse(result["lock_duration_verified_by_ci"])
        self.assertEqual(result["receipt_sha256"],
                         f"sha256:{hashlib.sha256(stored['bytes']).hexdigest()}")

    def test_sdk_serializes_pinned_conditional_put_without_network(self):
        class StopBeforeNetwork(Exception):
            pass

        seen = []

        def stop(request):
            seen.append((request.method, request.url, request.headers.get("If-None-Match")))
            raise StopBeforeNetwork()

        with patch.dict("os.environ", {
            "R2_STAGE_WRITE_ACCESS_KEY_ID": "writer-test-key",
            "R2_STAGE_WRITE_SECRET_ACCESS_KEY": "writer-test-secret",
            "R2_STAGE_READ_ACCESS_KEY_ID": "reader-test-key",
        }):
            client = transport.s3_client("WRITE", "PUT", self.key)
            with patch.object(client._endpoint.http_session, "send", side_effect=stop), \
                    self.assertRaises(StopBeforeNetwork):
                client.put_object(Bucket=transport.BUCKET, Key=self.key,
                                  Body=self.bytes, IfNoneMatch="*")
        self.assertEqual(seen, [(
            "PUT", f"{transport.ENDPOINT}/{transport.BUCKET}/{self.key}", b"*",
        )])

    def test_create_once_then_separate_reader_must_match_exact_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.write_bytes(self.bytes)
            calls = []

            def fake_s3(method, key, kind, **kwargs):
                calls.append((method, key, kind))
                if method == "GET":
                    kwargs["destination"].write_bytes(self.bytes)

            with patch.object(transport, "require_operator_lock_gate", return_value=self.gate), \
                    patch.object(transport, "prove_bucket_lock", return_value={"locked": True}), \
                    patch.object(transport, "s3_request", side_effect=fake_s3):
                receipt = transport.put("souls-build-bundle", source, f"sha256:{self.digest}")
            self.assertEqual(receipt["uri"], self.uri)
            self.assertEqual(receipt["sha256"], f"sha256:{self.digest}")
            self.assertEqual(receipt["byte_length"], len(self.bytes))
            self.assertEqual(calls, [("PUT", self.key, "WRITE"), ("GET", self.key, "READ")])

    def test_wrong_readback_and_absent_lock_stop_release(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.write_bytes(self.bytes)

            def wrong_readback(method, key, kind, **kwargs):
                if method == "GET":
                    kwargs["destination"].write_bytes(b"wrong object\n")

            with patch.object(transport, "require_operator_lock_gate", return_value=self.gate), \
                    patch.object(transport, "prove_bucket_lock", return_value={"locked": True}), \
                    patch.object(transport, "s3_request", side_effect=wrong_readback), \
                    self.assertRaisesRegex(transport.TransportError, "read-back byte length or SHA-256 mismatch"):
                transport.put("souls-build-bundle", source, f"sha256:{self.digest}")
            with patch.object(transport, "require_operator_lock_gate", side_effect=transport.TransportError("missing attestation")), \
                    patch.object(transport, "s3_request") as s3, \
                    self.assertRaises(transport.TransportError):
                transport.put("souls-build-bundle", source, f"sha256:{self.digest}")
            s3.assert_not_called()

    def test_failed_canary_refuses_release_object_upload(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.write_bytes(self.bytes)

            with patch.object(transport, "require_operator_lock_gate", return_value=self.gate), \
                    patch.object(transport, "prove_bucket_lock", side_effect=transport.TransportError("canary not locked")), \
                    patch.object(transport, "s3_request") as s3, \
                    self.assertRaisesRegex(transport.TransportError, "canary not locked"):
                transport.put("souls-build-bundle", source, f"sha256:{self.digest}")
            s3.assert_not_called()

    def test_read_rejects_existing_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "already-there"
            destination.write_bytes(b"keep")
            with patch.object(transport, "require_operator_lock_gate", return_value=self.gate), \
                    patch.object(transport, "s3_request") as s3, \
                    self.assertRaises(transport.TransportError):
                transport.read(self.uri, f"sha256:{self.digest}", len(self.bytes), destination)
            s3.assert_not_called()
            self.assertEqual(destination.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
