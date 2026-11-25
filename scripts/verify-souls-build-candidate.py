#!/usr/bin/env python3
"""Check a private Souls runtime candidate using local, owner-pinned inputs.

The caller supplies network isolation and authenticates owner policy. This
command cannot certify a release, adapter, profile, or physical test result.
"""

import argparse
import base64
import binascii
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile


REPO = "true-line/agent-bot-souls"
WORKFLOW = ".github/workflows/souls-build-receipt.yml"
IDENTITY = f"https://github.com/{REPO}/{WORKFLOW}@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
PREDICATE = "https://true-line.ai/soul-contracts/adapter/v2/souls-build"
SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest_file(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "input is not regular")
        digest = hashlib.sha256()
        length = 0
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
            length += len(block)
    require(length > 0, "input is empty")
    return "sha256:" + digest.hexdigest(), length


def strict_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def no_float(_value):
        raise ValueError("noninteger JSON number")

    return json.loads(data, object_pairs_hook=unique, parse_float=no_float,
                      parse_constant=no_float)


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def bounded_json(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "JSON input is not regular")
        data = stream.read(1024 * 1024 + 1)
    require(0 < len(data) <= 1024 * 1024, "JSON input exceeds bound or is empty")
    return strict_json(data)


def asset(record, role, path, suffix):
    require(isinstance(record, dict) and set(record) ==
            {"uri", "sha256", "byte_length"}, "invalid handoff asset")
    claimed = record["sha256"]
    require(isinstance(claimed, str) and SHA.fullmatch(claimed), "invalid asset digest")
    actual, length = digest_file(path)
    require(type(record["byte_length"]) is int and length > 0 and
            actual == claimed and length == record["byte_length"], "asset bytes differ")
    require(record["uri"] == f"qualification://stage2a/{role}/{claimed[7:]}",
            "asset locator differs")
    require(path.name == f"sha256-{claimed[7:]}{suffix}", "asset name differs")
    return actual, length


def verify(args):
    for value in (args.trusted_root_sha256, args.cosign_sha256,
                  args.builder_sha256, args.derivative_builder_sha256,
                  args.toolchain_sha256):
        require(SHA.fullmatch(value) is not None, "invalid approved digest")
    require(COMMIT.fullmatch(args.source_commit) and COMMIT.fullmatch(args.source_tree),
            "invalid approved source identity")
    require(args.cosign.is_absolute(), "Cosign path must be absolute")
    root_sha, _ = digest_file(args.trusted_root)
    cosign_sha, _ = digest_file(args.cosign)
    require(root_sha == args.trusted_root_sha256, "trusted root differs from owner pin")
    require(cosign_sha == args.cosign_sha256, "Cosign differs from owner pin")

    derivative_builder = Path(__file__).with_name("build-souls-r-derivative.py")
    derivative_builder_sha, _ = digest_file(derivative_builder)
    require(derivative_builder_sha == args.derivative_builder_sha256,
            "derivative builder differs from owner pin")
    handoff = bounded_json(args.handoff)
    require(isinstance(handoff, dict) and
            handoff.get("schema") == "souls-private-r2-handoff-v2" and
            handoff.get("source_repository") == REPO and
            handoff.get("source_commit") == args.source_commit and
            handoff.get("source_tree") == args.source_tree and
            handoff.get("workflow") == WORKFLOW, "handoff source differs")
    inputs = handoff.get("build_inputs")
    toolchain = handoff.get("toolchain")
    require(isinstance(inputs, dict) and isinstance(toolchain, dict) and
            isinstance(handoff.get("build_inputs_file_sha256"), str) and
            isinstance(handoff.get("toolchain_file_sha256"), str) and
            handoff["build_inputs_file_sha256"] ==
            "sha256:" + hashlib.sha256(canonical_json(inputs) + b"\n").hexdigest() and
            handoff["toolchain_file_sha256"] ==
            "sha256:" + hashlib.sha256(canonical_json(toolchain) + b"\n").hexdigest() and
            "sha256:" + hashlib.sha256(canonical_json(toolchain)).hexdigest() ==
            args.toolchain_sha256,
            "handoff build evidence differs")
    run_id, attempt = handoff.get("run_id"), handoff.get("run_attempt")
    require(isinstance(run_id, str) and re.fullmatch(r"[1-9][0-9]{0,19}", run_id) and
            type(attempt) is int and attempt > 0, "invalid handoff run identity")
    archive_sha, archive_length = asset(handoff.get("runtime_npm_archive"),
                                        "souls-package", args.archive, ".tgz")
    selected_sha, selected_length = asset(handoff.get("machine_r_selected_tar"),
                                          "souls-r-tar", args.selected_tar, ".tar")
    bundle_sha, bundle_length = asset(handoff.get("souls_build_bundle"),
                                      "souls-build-bundle", args.bundle, ".sigstore.json")

    bundle = bounded_json(args.bundle)
    require(isinstance(bundle, dict) and set(bundle) ==
            {"mediaType", "verificationMaterial", "dsseEnvelope"} and
            bundle["mediaType"] == "application/vnd.dev.sigstore.bundle.v0.3+json",
            "invalid Sigstore bundle")
    envelope = bundle["dsseEnvelope"]
    require(isinstance(envelope, dict) and
            envelope.get("payloadType") == "application/vnd.in-toto+json" and
            isinstance(envelope.get("signatures"), list) and
            len(envelope["signatures"]) == 1, "invalid DSSE envelope")
    try:
        payload = base64.b64decode(envelope["payload"], validate=True)
    except (KeyError, TypeError, ValueError, binascii.Error):
        raise ValueError("invalid DSSE payload") from None
    require(len(payload) <= 1024 * 1024, "Statement exceeds bound")
    statement = strict_json(payload)
    require(isinstance(statement, dict) and set(statement) ==
            {"_type", "subject", "predicateType", "predicate"} and
            statement["_type"] == "https://in-toto.io/Statement/v1" and
            statement["predicateType"] == PREDICATE, "wrong Statement type")
    require(statement["subject"] == [{"name": args.selected_tar.name,
                                      "digest": {"sha256": selected_sha[7:]}}],
            "signed subject differs from selected R tar")
    predicate = statement["predicate"]
    require(isinstance(predicate, dict) and set(predicate) == {
        "source_repository", "source_commit", "source_tree", "builder_sha256",
        "derivative_builder_sha256", "source_npm_sha256",
        "selected_manifest_sha256", "excluded_paths", "toolchain_sha256",
        "workflow", "run_id", "run_attempt"},
        "invalid build predicate")
    require(predicate == {
        "source_repository": REPO, "source_commit": args.source_commit,
        "source_tree": args.source_tree, "builder_sha256": args.builder_sha256,
        "derivative_builder_sha256": derivative_builder_sha,
        "source_npm_sha256": archive_sha,
        "selected_manifest_sha256": predicate["selected_manifest_sha256"],
        "excluded_paths": predicate["excluded_paths"],
        "toolchain_sha256": args.toolchain_sha256, "workflow": WORKFLOW,
        "run_id": run_id, "run_attempt": attempt,
    }, "signed predicate differs from approved selectors")
    require(inputs == {"predicate_type": PREDICATE,
                       "subject": {"name": args.selected_tar.name,
                                   "sha256": selected_sha[7:]},
                       "predicate": predicate},
            "handoff build inputs differ from signed Statement")
    spec = importlib.util.spec_from_file_location("reviewed_souls_derivative", derivative_builder)
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    with tempfile.TemporaryDirectory(prefix="souls-derivative-check-") as directory:
        rebuilt = Path(directory) / "selected.tar"
        selection = builder.build(args.archive, rebuilt)
        rebuilt_sha, _ = digest_file(rebuilt)
    require(rebuilt_sha == selected_sha and
            selection["selected_manifest_sha256"] == predicate["selected_manifest_sha256"] and
            selection["excluded_paths"] == predicate["excluded_paths"],
            "selected R tar differs from source npm archive")
    material = bundle["verificationMaterial"]
    require(isinstance(material, dict) and "certificate" in material and
            isinstance(material.get("tlogEntries"), list) and
            len(material["tlogEntries"]) == 1 and
            isinstance(material["tlogEntries"][0], dict) and
            isinstance(material["tlogEntries"][0].get("inclusionProof"), dict) and
            material["tlogEntries"][0]["inclusionProof"].get("checkpoint"),
            "bundle lacks certificate or inclusion checkpoint")

    with tempfile.TemporaryDirectory(prefix="souls-offline-verify-") as directory:
        command = [str(args.cosign), "verify-blob-attestation", "--bundle", str(args.bundle),
                   "--trusted-root", str(args.trusted_root),
                   "--check-claims=true", "--type", PREDICATE,
                   "--certificate-identity", IDENTITY,
                   "--certificate-oidc-issuer", ISSUER,
                   "--certificate-github-workflow-repository", REPO,
                   "--certificate-github-workflow-ref", "refs/heads/main",
                   "--certificate-github-workflow-sha", args.source_commit,
                   str(args.selected_tar)]
        environment = {"PATH": "/usr/bin:/bin", "HOME": directory,
                       "XDG_CACHE_HOME": directory, "LANG": "C"}
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=120, env=environment, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise ValueError("pinned Cosign could not complete") from None
        require(result.returncode == 0, "pinned Cosign refused signature or identity")

    return {
        "schema": "souls-build-candidate-verification-v1", "outcome": "pass",
        "source_repository": REPO, "source_commit": args.source_commit,
        "source_tree": args.source_tree, "workflow": WORKFLOW,
        "run_id": run_id, "run_attempt": attempt,
        "archive_sha256": archive_sha, "archive_byte_length": archive_length,
        "selected_tar_sha256": selected_sha, "selected_tar_byte_length": selected_length,
        "bundle_sha256": bundle_sha, "bundle_byte_length": bundle_length,
        "builder_sha256": args.builder_sha256,
        "derivative_builder_sha256": derivative_builder_sha,
        "selected_manifest_sha256": predicate["selected_manifest_sha256"],
        "toolchain_sha256": args.toolchain_sha256,
        "trusted_root_sha256": root_sha, "cosign_sha256": cosign_sha,
        "certificate_identity": IDENTITY, "oidc_issuer": ISSUER,
        "verification": "local bundle and trusted root; pinned Cosign verify-blob-attestation",
        "network_isolation_verified_by_this_command": False,
        "release_certified": False, "physical_qualification": False,
    }


def main():
    parser = argparse.ArgumentParser()
    for name in ("archive", "selected-tar", "bundle", "handoff", "trusted-root", "cosign", "out"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("trusted-root-sha256", "cosign-sha256", "source-commit",
                 "source-tree", "builder-sha256", "derivative-builder-sha256",
                 "toolchain-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        record = verify(args)
        with open(args.out, "x", encoding="utf-8") as output:
            output.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    except (OSError, ValueError, TypeError, KeyError) as error:
        parser.exit(1, f"candidate verification refused: {error}\n")
    print(json.dumps(record, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
