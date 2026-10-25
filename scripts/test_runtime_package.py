import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('runtime_package', Path(__file__).with_name('runtime_package.py'))
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class RuntimePackageTests(unittest.TestCase):
    def archive(self, name='nono', symlink=False):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            entry = tarfile.TarInfo(name)
            entry.size = 7
            if symlink:
                entry.type = tarfile.SYMTYPE
                entry.linkname = '/outside'
                entry.size = 0
            archive.addfile(entry, io.BytesIO(b'fixture'))
        return stream.getvalue()

    def lock(self, archive):
        return {'member': 'nono', 'archive_sha256': hashlib.sha256(archive).hexdigest(), 'binary_sha256': hashlib.sha256(b'fixture').hexdigest()}

    def test_runtime_matches_both_pins(self):
        archive = self.archive()
        self.assertEqual(package.runtime_bytes(archive, self.lock(archive)), b'fixture')

    def test_runtime_refuses_tampering_and_links(self):
        archive = self.archive()
        for changed, lock in [(archive+b'tampered',self.lock(archive)), (self.archive(symlink=True),self.lock(self.archive(symlink=True))), (self.archive('../nono'),self.lock(self.archive('../nono')))]:
            with self.assertRaises(ValueError):
                package.runtime_bytes(changed, lock)

    def test_lock_pins_both_hosts_to_distinct_runtimes(self):
        lock = json.loads((Path(__file__).resolve().parent.parent/'runtime-lock.json').read_text())
        self.assertEqual(set(lock['runtimes']), set(package.PLATFORMS))
        digests = {entry['binary_sha256'] for entry in lock['runtimes'].values()}
        self.assertEqual(len(digests), 2)
        self.assertIn('darwin-arm64', lock['runtimes']['darwin-arm64']['platform'])
        self.assertIn('apple-darwin', lock['runtimes']['darwin-arm64']['url'])

    def test_package_inventory_and_checksums(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = {'runtimes': {platform: self.lock(self.archive()) for platform in package.PLATFORMS}}
            files = {'manifest.yaml': b'id: fixture', 'server/plugin-linux-amd64': b'plugin', 'server/plugin-darwin-arm64': b'plugin', 'runtime/nono-linux-amd64': b'fixture', 'runtime/nono-darwin-arm64': b'fixture', 'runtime-lock.json': json.dumps(lock).encode(), 'licenses/NONO-APACHE-2.0.txt': b'license', 'LICENSE': b'plugin license'}
            for name, data in files.items():
                target = root/name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            (root/'checksums.txt').write_text(''.join(f'{hashlib.sha256(data).hexdigest()}  {name}\n' for name,data in files.items()))
            package.verify_package(root,lock)
            for platform in package.PLATFORMS:
                (root/f'runtime/nono-{platform}').write_bytes(b'changed')
                with self.assertRaises(ValueError):
                    package.verify_package(root,lock)
                (root/f'runtime/nono-{platform}').write_bytes(b'fixture')
            (root/'unexpected').write_text('extra')
            with self.assertRaises(ValueError):
                package.verify_package(root,lock)


if __name__ == '__main__':
    unittest.main()
