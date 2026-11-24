#!/usr/bin/env python3
"""Build a Souls archive and custom attestation predicate on a GitHub runner.

Draft for inclusion in the Souls source commit. Signing happens in the
workflow, after this script exits. This script never publishes an artifact.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/souls-build-receipt.yml"
PREDICATE_TYPE = "https://true-line.ai/soul-contracts/adapter/v2/souls-build"


def run(*args, cwd=ROOT):
    return subprocess.check_output(args, cwd=cwd, stderr=subprocess.PIPE, text=True).strip()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def digest_file(path):
    return sha256(path.read_bytes())


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def npm_tree_digest():
    npm_root = Path(run("npm", "root", "-g")) / "npm"
    if not (npm_root / "package.json").is_file():
        raise ValueError("global npm installation not found")
    files = []
    for path in sorted(npm_root.rglob("*")):
        rel = path.relative_to(npm_root).as_posix()
        if path.is_symlink():
            files.append({"path": rel, "kind": "symlink", "target": os.readlink(path)})
        elif path.is_file():
            files.append({
                "path": rel,
                "kind": "file",
                "mode": "100755" if path.stat().st_mode & 0o111 else "100644",
                "size": path.stat().st_size,
                "sha256": digest_file(path),
            })
        elif not path.is_dir():
            raise ValueError(f"nonregular npm toolchain path: {rel}")
    return sha256(canonical(files))


def main():
    repo = os.environ["GITHUB_REPOSITORY"]
    source_commit = os.environ["GITHUB_SHA"]
    run_id = os.environ["GITHUB_RUN_ID"]
    run_attempt = int(os.environ["GITHUB_RUN_ATTEMPT"])
    workflow_ref = os.environ["GITHUB_WORKFLOW_REF"]
    if repo != "true-line/agent-bot-souls":
        raise ValueError("wrong source repository")
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise ValueError("invalid source commit")
    if not re.fullmatch(r"[1-9][0-9]{0,19}", run_id) or run_attempt < 1:
        raise ValueError("invalid Actions run identity")
    if workflow_ref != f"{repo}/{WORKFLOW}@refs/heads/main":
        raise ValueError("wrong workflow identity")
    if run("git", "rev-parse", "HEAD") != source_commit:
        raise ValueError("checkout does not match Actions source commit")
    source_tree = run("git", "rev-parse", "HEAD^{tree}")
    if not re.fullmatch(r"[0-9a-f]{40}", source_tree):
        raise ValueError("invalid source tree")

    node_path = Path(run("node", "-p", "process.execPath")).resolve()
    toolchain = {
        "node_version": run("node", "--version"),
        "node_binary_sha256": digest_file(node_path),
        "npm_version": run("npm", "--version"),
        "npm_tree_sha256": npm_tree_digest(),
        "cosign_version": run("cosign", "version"),
        "cosign_binary_sha256": digest_file(Path(run("which", "cosign")).resolve()),
    }
    if toolchain["node_version"] != "v26.13.1" or toolchain["npm_version"] != "11.20.0":
        raise ValueError("unexpected Node/npm release toolchain")

    out = ROOT / "dist" / "souls-build-receipt" / f"{run_id}-{run_attempt}"
    out.mkdir(parents=True, exist_ok=False)
    pack = json.loads(run("npm", "pack", "--ignore-scripts", "--json", "--pack-destination", str(out)))
    if isinstance(pack, dict):
        pack = list(pack.values())
    if not isinstance(pack, list) or len(pack) != 1:
        raise ValueError(f"npm produced unexpected package metadata: {type(pack).__name__} length {len(pack)}")
    npm_name = pack[0]["filename"]
    if not re.fullmatch(r"[A-Za-z0-9._-]+\.tgz", npm_name):
        raise ValueError("noncanonical package filename")
    archive = out / npm_name
    if not archive.is_file():
        raise ValueError("npm package is missing")
    package_sha256 = digest_file(archive)
    name = f"sha256-{package_sha256}.tgz"
    archive = archive.rename(out / name)
    derivative_builder = ROOT / "scripts/build-souls-r-derivative.py"
    temporary_tar = out / "souls-r-selected.tar"
    selection = json.loads(run("python3", str(derivative_builder), str(archive), str(temporary_tar)))
    selected_sha256 = digest_file(temporary_tar)
    if selection["selected_tar_sha256"] != "sha256:" + selected_sha256 or \
            selection["source_npm_sha256"] != "sha256:" + package_sha256:
        raise ValueError("derivative builder returned inconsistent digests")
    selected_name = f"sha256-{selected_sha256}.tar"
    selected_tar = temporary_tar.rename(out / selected_name)
    predicate = {
        "source_repository": repo,
        "source_commit": source_commit,
        "source_tree": source_tree,
        "builder_sha256": "sha256:" + digest_file(Path(__file__)),
        "derivative_builder_sha256": "sha256:" + digest_file(derivative_builder),
        "source_npm_sha256": "sha256:" + package_sha256,
        "selected_manifest_sha256": selection["selected_manifest_sha256"],
        "excluded_paths": selection["excluded_paths"],
        "toolchain_sha256": "sha256:" + sha256(canonical(toolchain)),
        "workflow": WORKFLOW,
        "run_id": run_id,
        "run_attempt": run_attempt,
    }
    (out / "predicate.json").write_bytes(canonical(predicate) + b"\n")
    (out / "statement.json").write_bytes(canonical({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": selected_name, "digest": {"sha256": selected_sha256}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }) + b"\n")
    (out / "toolchain.json").write_bytes(canonical(toolchain) + b"\n")
    (out / "build-inputs.json").write_bytes(canonical({
        "predicate_type": PREDICATE_TYPE,
        "subject": {"name": selected_name, "sha256": selected_sha256},
        "predicate": predicate,
    }) + b"\n")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
        stream.write(f"directory={out}\n")
        stream.write(f"package={archive}\n")
        stream.write(f"package_sha256={package_sha256}\n")
        stream.write(f"selected_tar={selected_tar}\n")
        stream.write(f"selected_tar_sha256={selected_sha256}\n")


if __name__ == "__main__":
    main()
