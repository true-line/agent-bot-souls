#!/usr/bin/env python3
"""Make the exact macOS Machine R Souls component from an npm archive.

The four omissions are fixed for this release path. All selected file bytes
come from npm pack; no checked-out source file can enter the component.
"""

import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile


EXCLUDED = frozenset({
    "README.md",  # operator documentation
    "scripts/prepare-contracts.mjs",  # network preparation, not runtime
    "lib/vendor/agent-bot-sdk/source.json",  # provenance, not imported
    "lib/helpers/member-peer.py",  # Linux helper; macOS uses .rb
})
REQUIRED = frozenset({"LICENSE", "lib/vendor/agent-bot-sdk/LICENSE",
                      "package.json", "bin/agent-bot-souls.mjs",
                      "lib/helpers/member-peer.rb"})


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source_files(archive_path):
    files = {}
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive:
            if not member.isfile() or not member.name.startswith("package/"):
                raise ValueError("npm archive has an unexpected member")
            name = member.name[len("package/"):]
            if not name or name in files or name.startswith("/") or ".." in Path(name).parts:
                raise ValueError("npm archive has an unsafe or repeated path")
            files[name] = archive.extractfile(member).read()
    if len(files) != 44 or not EXCLUDED <= files.keys() or not REQUIRED <= files.keys():
        raise ValueError("npm archive differs from reviewed 44-file selection")
    return files


def build(source, output):
    files = source_files(source)
    selected = {name: data for name, data in files.items() if name not in EXCLUDED}
    names = set(selected)
    for name in selected:
        parts = Path(name).parts
        names.update("/".join(parts[:i]) + "/" for i in range(1, len(parts)))
    with tarfile.open(output, "w:", format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(names):
            directory = name.endswith("/")
            info = tarfile.TarInfo(name)
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ""
            info.mode = 0o550 if directory else 0o440
            info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
            info.size = 0 if directory else len(selected[name])
            archive.addfile(info, None if directory else io.BytesIO(selected[name]))
    return {
        "source_npm_sha256": "sha256:" + sha(source.read_bytes()),
        "selected_tar_sha256": "sha256:" + sha(output.read_bytes()),
        "source_files": len(files), "selected_files": len(selected),
        "excluded_paths": sorted(EXCLUDED),
        "selected_manifest_sha256": "sha256:" + sha(json.dumps([
            {"path": name, "sha256": "sha256:" + sha(data)}
            for name, data in sorted(selected.items())
        ], sort_keys=True, separators=(",", ":")).encode()),
    }


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: build-souls-r-derivative.py npm.tgz output.tar")
    print(json.dumps(build(Path(sys.argv[1]), Path(sys.argv[2])), sort_keys=True))
