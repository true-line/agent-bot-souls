"""Selected R archive must reproduce the reviewed Machine v3 input exactly."""

import importlib.util
import io
from pathlib import Path
import tarfile
from tempfile import TemporaryDirectory
import unittest


SCRIPT = Path(__file__).with_name("build-souls-r-derivative.py")
SPEC = importlib.util.spec_from_file_location("souls_r_derivative", SCRIPT)
derivative = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(derivative)


def fixture_npm(path):
    names = set(derivative.REQUIRED) | set(derivative.EXCLUDED)
    names.update(f"lib/fixture-{i:02d}.mjs" for i in range(44 - len(names)))
    with tarfile.open(path, "w:gz") as archive:
        for name in sorted(names):
            data = (name + "\n").encode()
            info = tarfile.TarInfo("package/" + name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return names


class DerivativeTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.npm = self.root / "source.tgz"
        self.names = fixture_npm(self.npm)

    def test_exact_selected_files_and_reproducible_tar(self):
        first = self.root / "first.tar"
        second = self.root / "second.tar"
        record = derivative.build(self.npm, first)
        self.assertEqual(derivative.build(self.npm, second), record)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(record["selected_files"], 40)
        self.assertEqual(record["excluded_paths"], sorted(derivative.EXCLUDED))
        with tarfile.open(first, "r:") as archive:
            selected = {member.name: archive.extractfile(member).read()
                        for member in archive if member.isfile()}
        self.assertEqual(set(selected), self.names - derivative.EXCLUDED)
        self.assertEqual(selected["LICENSE"], b"LICENSE\n")

    def test_unreviewed_source_selection_refuses(self):
        self.npm.write_bytes(b"not a package")
        with self.assertRaises(tarfile.ReadError):
            derivative.build(self.npm, self.root / "out.tar")


if __name__ == "__main__":
    unittest.main()
