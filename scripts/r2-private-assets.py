#!/usr/bin/env python3
"""Fail-closed Stage 2a R2 transport proposal; never prints credentials or bytes.

Release asset upload remains unreachable behind the release workflow's first
hard hold. A separate protected canary workflow may call only the canary
subcommand. The protected environment supplies separate bucket-scoped S3 writer
and reader credentials. The canary tests current enforcement independently;
an owner-controlled dashboard read-back supplies the rule duration outside CI.
Release asset upload still requires a fresh external attestation digest and time.
"""

import argparse
import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import tempfile
from urllib.parse import urlsplit


ACCOUNT = "383d29f5221f39800b73e1c59d63ee73"
BUCKET = "agent-bot-stage2a-evidence"
ENDPOINT = f"https://{ACCOUNT}.r2.cloudflarestorage.com"
S3_HOST = f"{ACCOUNT}.r2.cloudflarestorage.com"
LOCK_ID = "stage2a-v1-365d"
LOCK_PREFIX = "v1/"
MIN_LOCK_SECONDS = 365 * 24 * 60 * 60
MAX_ATTESTATION_AGE = timedelta(hours=1)
ROLES = frozenset({
    "qualification", "policy-envelope", "protected-envelope",
    "cooperative-envelope", "souls-package", "souls-build-bundle",
    "canary-receipt",
})
URI_PATTERN = re.compile(r"\Aqualification://stage2a/([a-z-]+)/([0-9a-f]{64})\Z")
SHA_PATTERN = re.compile(r"\A[0-9a-f]{64}\Z")
PREFIXED_SHA_PATTERN = re.compile(r"\Asha256:([0-9a-f]{64})\Z")


class TransportError(Exception):
    pass


def asset_ref(role, digest):
    if role not in ROLES or not SHA_PATTERN.fullmatch(digest):
        raise TransportError("invalid private asset role or digest")
    return f"qualification://stage2a/{role}/{digest}", f"v1/{role}/{digest}"


def key_for_ref(uri, expected_sha256):
    match = URI_PATTERN.fullmatch(uri)
    if not match or match.group(1) not in ROLES or match.group(2) != expected_sha256:
        raise TransportError("logical URI does not exactly match role and digest")
    return asset_ref(match.group(1), match.group(2))[1]


def require_operator_lock_gate(now=None):
    """Require a recent external attestation; do not claim CI verified R2 lock."""
    digest = os.environ.get("R2_STAGE_LOCK_ATTESTATION_SHA256", "")
    checked = os.environ.get("R2_STAGE_LOCK_ATTESTED_AT_UTC", "")
    if not SHA_PATTERN.fullmatch(digest):
        raise TransportError("owner-controlled R2 lock attestation digest is missing")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", checked):
        raise TransportError("owner-controlled R2 lock attestation time is missing")
    try:
        observed = datetime.strptime(checked, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise TransportError("owner-controlled R2 lock attestation time is invalid") from None
    now = now or datetime.now(timezone.utc)
    if observed > now or now - observed > MAX_ATTESTATION_AGE:
        raise TransportError("owner-controlled R2 lock attestation is stale or future dated")
    return {"evidence_sha256": f"sha256:{digest}", "checked_at_utc": checked,
            "expected_rule": LOCK_ID, "expected_prefix": LOCK_PREFIX,
            "expected_min_age_seconds": MIN_LOCK_SECONDS,
            "verified_by_ci": False}


def s3_credentials(kind):
    prefix = f"R2_STAGE_{kind}_"
    access = os.environ.get(prefix + "ACCESS_KEY_ID", "")
    secret = os.environ.get(prefix + "SECRET_ACCESS_KEY", "")
    if not access or not secret:
        raise TransportError(f"separate {kind.lower()} R2 credential is missing")
    other = "READ" if kind == "WRITE" else "WRITE"
    if access == os.environ.get(f"R2_STAGE_{other}_ACCESS_KEY_ID", ""):
        raise TransportError("R2 writer and reader must use separate access keys")
    return access, secret


def guard_request(request, method, key):
    parsed = urlsplit(request.url)
    if (request.method != method or parsed.scheme != "https" or parsed.hostname != S3_HOST or
            parsed.port is not None or parsed.username is not None or parsed.password is not None or
            parsed.path != f"/{BUCKET}/{key}" or parsed.query or parsed.fragment):
        raise TransportError("private S3 request left pinned method, host, or key")


def reject_redirect(response=None, **_kwargs):
    if response is not None and response[0] is not None and 300 <= response[0].status_code < 400:
        raise TransportError("private object request redirected")


def s3_client(kind, method, key):
    access, secret = s3_credentials(kind)
    config = Config(
        region_name="auto", signature_version="s3v4", s3={"addressing_style": "path"},
        retries={"total_max_attempts": 1}, connect_timeout=10, read_timeout=30,
        proxies={}, request_checksum_calculation="when_required",
        response_checksum_validation="when_required",
    )
    session = boto3.session.Session(aws_access_key_id=access, aws_secret_access_key=secret,
                                   region_name="auto")
    client = session.client("s3", endpoint_url=ENDPOINT, config=config, use_ssl=True, verify=True)
    operation = {"PUT": "PutObject", "GET": "GetObject", "DELETE": "DeleteObject"}.get(method)
    if operation is None:
        raise TransportError("unsupported private object operation")
    client.meta.events.register_first(f"before-send.s3.{operation}",
                                      lambda request, **kwargs: guard_request(request, method, key))
    client.meta.events.register_first(f"needs-retry.s3.{operation}", reject_redirect)
    return client


def probe_error(error, status, code):
    response = error.response
    return (response.get("ResponseMetadata", {}).get("HTTPStatusCode") == status and
            response.get("Error", {}).get("Code") == code)


def probe_client(method, key, kind):
    if not re.fullmatch(r"(?:v1/canary|scope-test)/[0-9a-f]{32}", key):
        raise TransportError("invalid private probe key")
    return s3_client(kind, method, key)


def probe_get(key, expected=None):
    try:
        response = probe_client("GET", key, "READ").get_object(Bucket=BUCKET, Key=key)
    except ClientError as error:
        if expected is None and (probe_error(error, 404, "NoSuchKey") or
                                 probe_error(error, 404, "404")):
            return
        raise TransportError("private probe read failed") from None
    except (BotoCoreError, OSError):
        raise TransportError("private probe read failed") from None
    with response["Body"] as body:
        data = body.read(65)
    if expected is None or data != expected:
        raise TransportError("private probe bytes or absence differ")
    return {"sha256": f"sha256:{hashlib.sha256(data).hexdigest()}",
            "byte_length": len(data)}


def probe_put(key, data, conditional):
    kwargs = {"Bucket": BUCKET, "Key": key, "Body": data, "ContentLength": len(data)}
    if conditional:
        kwargs["IfNoneMatch"] = "*"
    try:
        probe_client("PUT", key, "WRITE").put_object(**kwargs)
    except (ClientError, BotoCoreError, OSError):
        raise TransportError("private probe create or overwrite failed") from None


def probe_delete(key):
    try:
        probe_client("DELETE", key, "WRITE").delete_object(Bucket=BUCKET, Key=key)
    except (ClientError, BotoCoreError, OSError):
        raise TransportError("private probe delete failed") from None


def require_lock_rejection(operation):
    try:
        operation()
    except ClientError as error:
        if probe_error(error, 409, "ObjectLockedByBucketPolicy"):
            return {"http_status": 409, "error_code": "ObjectLockedByBucketPolicy"}
        raise TransportError("private canary got wrong lock refusal") from None
    except (BotoCoreError, OSError):
        raise TransportError("private canary lock probe failed") from None
    raise TransportError("private canary was not protected by bucket lock")


def prove_bucket_lock():
    """Prove writer scope separately, then exact lock enforcement on a canary."""
    nonce = secrets.token_hex(16)
    disposable = f"scope-test/{nonce}"
    canary = f"v1/canary/{nonce}"
    first = b"stage2a-canary-original-" + nonce.encode("ascii")
    second = b"stage2a-canary-changed-" + nonce.encode("ascii")
    probe_get(disposable, None)
    # A failed PUT may have reached R2 even if its response was lost. Always
    # try to remove this unlocked probe key, including after a read or write
    # failure. The retained locked canary below is never part of cleanup.
    try:
        probe_put(disposable, first, conditional=True)
        probe_get(disposable, first)
        probe_put(disposable, second, conditional=False)
        probe_get(disposable, second)
    finally:
        try:
            probe_delete(disposable)
            probe_get(disposable, None)
        except TransportError:
            raise TransportError("private scope-test cleanup failed; check for disposable residue") from None
    probe_get(canary, None)
    probe_put(canary, first, conditional=True)
    probe_get(canary, first)
    overwrite_refusal = require_lock_rejection(lambda: probe_client("PUT", canary, "WRITE").put_object(
        Bucket=BUCKET, Key=canary, Body=second, ContentLength=len(second)))
    delete_refusal = require_lock_rejection(lambda: probe_client("DELETE", canary, "WRITE").delete_object(
        Bucket=BUCKET, Key=canary))
    readback = probe_get(canary, first)
    return {"key": canary, "sha256": f"sha256:{hashlib.sha256(first).hexdigest()}",
            "scope_test_cleaned": True, "locked_overwrite_denied": True,
            "locked_delete_denied": True, "reader_bytes_unchanged": True,
            "overwrite_refusal": overwrite_refusal, "delete_refusal": delete_refusal,
            "reader_readback": readback}


def s3_request(method, key, kind, source=None, destination=None, expected_length=None):
    if not re.fullmatch(r"v1/[a-z-]+/[0-9a-f]{64}", key):
        raise TransportError("private object key is outside locked role/digest layout")
    client = s3_client(kind, method, key)
    try:
        if method == "PUT":
            with open(source, "rb") as stream:
                client.put_object(Bucket=BUCKET, Key=key, Body=stream,
                                  ContentLength=source.stat().st_size, IfNoneMatch="*")
            return
        if method != "GET":
            raise TransportError("unsupported private object operation")
        response = client.get_object(Bucket=BUCKET, Key=key)
        count = 0
        with response["Body"] as body, open(destination, "xb") as stream:
            while block := body.read(1024 * 1024):
                count += len(block)
                if count > expected_length:
                    raise TransportError("private read-back exceeds expected length")
                stream.write(block)
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code")
        if method == "PUT" and code in {"PreconditionFailed", "ConditionalRequestConflict",
                                        "ObjectLockedByBucketPolicy"}:
            return  # Existing bytes are accepted only after separate reader verifies them.
        raise TransportError("private S3 request failed") from None
    except (BotoCoreError, OSError):
        raise TransportError("private S3 request failed") from None


def hash_file(path):
    digest = hashlib.sha256()
    count = 0
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
            count += len(block)
    if count < 1:
        raise TransportError("private asset is empty")
    return digest.hexdigest(), count


def download_verified(key, digest, length, target):
    s3_request("GET", key, "READ", destination=target, expected_length=length)
    actual_digest, actual_length = hash_file(target)
    if actual_digest != digest or actual_length != length:
        raise TransportError("private read-back byte length or SHA-256 mismatch")


def snapshot_regular_file(source, target):
    try:
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise TransportError("private source is not a regular file") from None
    with os.fdopen(descriptor, "rb") as original, open(target, "xb") as snapshot:
        before = os.fstat(original.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise TransportError("private source is not a regular file")
        shutil.copyfileobj(original, snapshot)
        after = os.fstat(original.fileno())
        if (before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns or
                before.st_ctime_ns != after.st_ctime_ns):
            raise TransportError("private source changed during snapshot")
    return hash_file(target)


def put(role, source, expected_sha256):
    gate = require_operator_lock_gate()
    with tempfile.TemporaryDirectory(prefix="stage2a-r2-") as directory:
        snapshot = Path(directory) / "upload"
        digest, length = snapshot_regular_file(source, snapshot)
        if f"sha256:{digest}" != expected_sha256:
            raise TransportError("private source differs from pinned build digest")
        uri, key = asset_ref(role, digest)
        canary = prove_bucket_lock()
        s3_request("PUT", key, "WRITE", source=snapshot)
        readback = Path(directory) / "readback"
        download_verified(key, digest, length, readback)
    return {"uri": uri, "sha256": f"sha256:{digest}", "byte_length": length,
            "operator_lock_gate": gate, "canary": canary,
            "bucket": BUCKET, "account": ACCOUNT}


def read(uri, expected_sha256, length, destination):
    match = PREFIXED_SHA_PATTERN.fullmatch(expected_sha256)
    if not isinstance(length, int) or length < 1 or not match:
        raise TransportError("invalid expected asset length or digest")
    digest = match.group(1)
    key = key_for_ref(uri, digest)
    gate = require_operator_lock_gate()
    if destination.exists() or destination.is_symlink():
        raise TransportError("private destination already exists")
    with tempfile.TemporaryDirectory(prefix="stage2a-r2-") as directory:
        temp = Path(directory) / "download"
        download_verified(key, digest, length, temp)
        with open(temp, "rb") as source, open(destination, "xb") as output:
            shutil.copyfileobj(source, output)
    actual_digest, actual_length = hash_file(destination)
    if actual_digest != digest or actual_length != length:
        destination.unlink(missing_ok=True)
        raise TransportError("private destination changed during copy")
    return {"uri": uri, "sha256": f"sha256:{actual_digest}", "byte_length": actual_length,
            "operator_lock_gate": gate, "bucket": BUCKET, "account": ACCOUNT}


def canary():
    """Persist a private canary receipt without uploading a release asset."""
    proof = prove_bucket_lock()
    receipt = {"schema": "stage2a-r2-canary-v1", "observed_at_utc":
               datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "github_run_id": os.environ.get("GITHUB_RUN_ID", ""),
               "github_sha": os.environ.get("GITHUB_SHA", ""),
               "canary": proof,
               "bucket": BUCKET, "account": ACCOUNT}
    encoded = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
    digest = hashlib.sha256(encoded).hexdigest()
    uri, key = asset_ref("canary-receipt", digest)
    with tempfile.TemporaryDirectory(prefix="stage2a-canary-receipt-") as directory:
        source = Path(directory) / "receipt.json"
        descriptor = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
        s3_request("PUT", key, "WRITE", source=source)
        download_verified(key, digest, len(encoded), Path(directory) / "readback.json")
    return {"result": "pass", "receipt_uri": uri, "receipt_sha256": f"sha256:{digest}",
            "receipt_byte_length": len(encoded), "observed_at_utc": receipt["observed_at_utc"],
            "lock_duration_verified_by_ci": False}


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    put_parser = sub.add_parser("put")
    put_parser.add_argument("--role", required=True, choices=sorted(ROLES))
    put_parser.add_argument("--file", required=True, type=Path)
    put_parser.add_argument("--sha256", required=True)
    read_parser = sub.add_parser("read")
    read_parser.add_argument("--uri", required=True)
    read_parser.add_argument("--sha256", required=True)
    read_parser.add_argument("--byte-length", required=True, type=int)
    read_parser.add_argument("--dest", required=True, type=Path)
    sub.add_parser("canary")
    sub.add_parser("check-operator-gate")
    args = parser.parse_args()
    try:
        if args.command == "put":
            result = put(args.role, args.file, args.sha256)
        elif args.command == "read":
            result = read(args.uri, args.sha256, args.byte_length, args.dest)
        elif args.command == "canary":
            result = canary()
        else:
            result = {"operator_lock_gate": require_operator_lock_gate(),
                      "bucket": BUCKET, "account": ACCOUNT}
    except TransportError as error:
        parser.exit(1, f"private transport refused: {error}\n")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
