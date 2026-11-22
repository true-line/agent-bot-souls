#!/usr/bin/env python3
"""Emit only nonsecret metadata for independent read-back of private R2 assets.

The workflow's final release hold remains separate. This record is an index,
not signature verification, owner lock attestation, or release approval.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


REPOSITORY = "true-line/agent-bot-souls"
WORKFLOW = ".github/workflows/souls-build-receipt.yml"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
RUN_ID = re.compile(r"[1-9][0-9]{0,19}\Z")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise ValueError("private handoff input is missing or invalid JSON") from None


def file_identity(path):
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        require(stat.S_ISREG(os.fstat(descriptor).st_mode), "private handoff asset must be a regular file")
        length = 0
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                length += len(block)
                digest.update(block)
    except OSError:
        raise ValueError("private handoff asset cannot be read") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    require(length > 0, "private handoff asset is empty")
    return digest.hexdigest(), length


def checked_asset(role, path, receipt):
    require(isinstance(receipt, dict), "private store receipt is invalid")
    digest, length = file_identity(path)
    uri = f"qualification://stage2a/{role}/{digest}"
    require(receipt.get("uri") == uri, "private store URI differs from exact asset")
    require(receipt.get("sha256") == f"sha256:{digest}", "private store digest differs from exact asset")
    require(type(receipt.get("byte_length")) is int and receipt["byte_length"] == length,
            "private store length differs from exact asset")
    gate = receipt.get("operator_lock_gate")
    require(isinstance(gate, dict) and gate.get("verified_by_ci") is False,
            "private store receipt misstates lock attestation")
    canary = receipt.get("canary", {})
    require(isinstance(canary, dict) and all(canary.get(field) is True for field in (
        "scope_test_cleaned", "locked_overwrite_denied", "locked_delete_denied", "reader_bytes_unchanged")),
        "private store receipt lacks successful lock canary")
    return {"uri": uri, "sha256": f"sha256:{digest}", "byte_length": length}


def git_source_identity():
    try:
        output = subprocess.check_output(
            ["git", "rev-parse", "HEAD", "HEAD^{tree}"],
            cwd=Path(__file__).resolve().parents[1], stderr=subprocess.DEVNULL,
            text=True,
        ).splitlines()
    except (OSError, subprocess.CalledProcessError):
        raise ValueError("checked-out Git identity is unavailable") from None
    require(len(output) == 2 and all(COMMIT.fullmatch(value) for value in output),
            "checked-out Git identity is invalid")
    return tuple(output)


def collect(build_dir, package_path, bundle_path, environ, git_identity=None):
    require(environ.get("GITHUB_REPOSITORY") == REPOSITORY, "wrong source repository")
    require(environ.get("GITHUB_REF") == "refs/heads/main", "wrong source ref")
    require(environ.get("GITHUB_WORKFLOW_REF") == f"{REPOSITORY}/{WORKFLOW}@refs/heads/main",
            "wrong workflow identity")
    source_commit = environ.get("GITHUB_SHA", "")
    run_id = environ.get("GITHUB_RUN_ID", "")
    run_attempt = environ.get("GITHUB_RUN_ATTEMPT", "")
    require(COMMIT.fullmatch(source_commit) is not None, "invalid source commit")
    require(RUN_ID.fullmatch(run_id) is not None and RUN_ID.fullmatch(run_attempt) is not None,
            "invalid Actions run identity")

    inputs = read_json(build_dir / "build-inputs.json")
    require(isinstance(inputs, dict) and isinstance(inputs.get("predicate"), dict),
            "build inputs lack predicate")
    predicate = inputs["predicate"]
    source_tree = predicate.get("source_tree", "")
    require(COMMIT.fullmatch(source_tree) is not None, "invalid source tree")
    require((git_identity or git_source_identity()) == (source_commit, source_tree),
            "build source differs from checked-out Git objects")
    require(predicate.get("source_repository") == REPOSITORY and
            predicate.get("source_commit") == source_commit and
            predicate.get("workflow") == WORKFLOW and
            predicate.get("run_id") == run_id and
            predicate.get("run_attempt") == int(run_attempt),
            "build predicate differs from Actions identity")

    package = checked_asset("souls-package", package_path,
                            read_json(build_dir / "package-store-receipt.json"))
    bundle = checked_asset("souls-build-bundle", bundle_path,
                           read_json(build_dir / "bundle-store-receipt.json"))
    require(package_path.name == f"sha256-{package['sha256'][7:]}.tgz",
            "runtime archive name differs from its digest")
    require(bundle_path.name == f"sha256-{bundle['sha256'][7:]}.sigstore.json",
            "bundle name differs from its digest")
    require(inputs.get("subject") == {"name": package_path.name, "sha256": package["sha256"][7:]},
            "build subject differs from runtime archive")
    return {
        "schema": "souls-private-r2-handoff-v1",
        "source_repository": REPOSITORY,
        "source_commit": source_commit,
        "source_tree": source_tree,
        "workflow": WORKFLOW,
        "run_id": run_id,
        "run_attempt": int(run_attempt),
        "runtime_npm_archive": package,
        "souls_build_bundle": bundle,
        "scope": "private object locator only; independent signature, Rekor, lock and release review required",
    }


def emit(record, summary_path):
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":"))
    with open(summary_path, "a", encoding="utf-8") as summary:
        summary.write("## Souls private R2 handoff\n\n```json\n")
        summary.write(json.dumps(record, sort_keys=True, indent=2) + "\n")
        summary.write("```\n\n")
    print("Souls private handoff: " + encoded)


def main():
    if len(sys.argv) != 4:
        raise ValueError("expected build directory, runtime archive and signed bundle")
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")
    require(summary_path, "GitHub job summary path is missing")
    record = collect(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), os.environ)
    emit(record, summary_path)


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        raise SystemExit(f"Souls private handoff refused: {error}") from None
