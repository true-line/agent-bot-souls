#!/usr/bin/env python3
"""Check receipt shape and exact build claims; this is not signature verification."""

import base64
import hashlib
import json
from pathlib import Path
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    bundle_path, inputs_path, archive_path = map(Path, sys.argv[1:])
    bundle = json.loads(bundle_path.read_bytes())
    inputs = json.loads(inputs_path.read_bytes())
    require(bundle.get("mediaType") == "application/vnd.dev.sigstore.bundle.v0.3+json", "wrong bundle version")
    content = bundle.get("content", {})
    envelope = content.get("dsseEnvelope", {})
    require(set(content) == {"dsseEnvelope"}, "bundle must contain one DSSE envelope")
    require(envelope.get("payloadType") == "application/vnd.in-toto+json", "wrong DSSE payload type")
    require(len(envelope.get("signatures", [])) == 1, "receipt needs exactly one DSSE signature")
    statement = json.loads(base64.b64decode(envelope["payload"], validate=True))
    require(statement.get("_type") == "https://in-toto.io/Statement/v1", "wrong Statement version")
    require(statement.get("predicateType") == inputs["predicate_type"], "wrong predicate type")
    require(statement.get("predicate") == inputs["predicate"], "wrong predicate")
    subject = statement.get("subject", [])
    require(len(subject) == 1, "receipt needs one subject")
    require(subject[0] == {
        "name": archive_path.name,
        "digest": {"sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest()},
    }, "subject differs from actual archive bytes")
    require(subject[0]["name"] == inputs["subject"]["name"], "subject name differs from build record")
    require(subject[0]["digest"]["sha256"] == inputs["subject"]["sha256"], "subject digest differs from build record")
    material = bundle.get("verificationMaterial", {})
    require("certificate" in material, "missing signing certificate")
    entries = material.get("tlogEntries", [])
    require(len(entries) == 1, "receipt needs one transparency log entry")
    proof = entries[0].get("inclusionProof", {})
    require(proof.get("checkpoint"), "receipt lacks inclusion checkpoint")
    print(json.dumps({
        "package_sha256": subject[0]["digest"]["sha256"],
        "bundle_sha256": hashlib.sha256(bundle_path.read_bytes()).hexdigest(),
        "source_commit": inputs["predicate"]["source_commit"],
        "source_tree": inputs["predicate"]["source_tree"],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
