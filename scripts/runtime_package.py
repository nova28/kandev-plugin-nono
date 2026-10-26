"""Pinned runtime packaging. No download occurs during plugin execution."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import urllib.request

MAX_BYTES = 128 << 20
PLATFORMS = ('linux-amd64', 'darwin-arm64')
FILES = {'manifest.yaml', 'runtime-lock.json', 'licenses/NONO-APACHE-2.0.txt', 'LICENSE'} | {
    f'{kind}/{name}-{platform}' for platform in PLATFORMS
    for kind, name in (('server', 'plugin'), ('runtime', 'nono'))}


def runtime_bytes(archive, lock):
    if len(archive) > MAX_BYTES or hashlib.sha256(archive).hexdigest() != lock['archive_sha256']:
        raise ValueError('runtime archive digest mismatch')
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as source:
            members = source.getmembers()
            if len(members) != 1 or members[0].name != lock['member'] or not members[0].isfile():
                raise ValueError('runtime archive inventory mismatch')
            if members[0].size <= 0 or members[0].size > MAX_BYTES:
                raise ValueError('runtime executable exceeds size bound')
            with source.extractfile(members[0]) as executable:
                content = executable.read(MAX_BYTES + 1)
    except (tarfile.TarError, OSError) as error:
        raise ValueError('invalid runtime archive') from error
    if hashlib.sha256(content).hexdigest() != lock['binary_sha256']:
        raise ValueError('runtime executable digest mismatch')
    return content


def verify_package(root, expected_lock):
    root = Path(root)
    entries = list(root.rglob('*'))
    if any(entry.is_symlink() for entry in entries):
        raise ValueError('package contains a symbolic link')
    inventory = {str(entry.relative_to(root)) for entry in entries if entry.is_file()}
    if inventory != FILES | {'checksums.txt'}:
        raise ValueError('package inventory mismatch')
    checksums = {}
    for line in (root/'checksums.txt').read_text().splitlines():
        parts = line.split()
        if len(parts) != 2 or parts[1] in checksums:
            raise ValueError('invalid package checksum manifest')
        checksums[parts[1]] = parts[0]
    if set(checksums) != FILES:
        raise ValueError('package checksum inventory mismatch')
    for name, digest in checksums.items():
        with (root/name).open('rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        if actual != digest:
            raise ValueError('package checksum mismatch')
    if json.loads((root/'runtime-lock.json').read_text()) != expected_lock:
        raise ValueError('package runtime lock mismatch')
    for platform in PLATFORMS:
        with (root/f'runtime/nono-{platform}').open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if digest != expected_lock['runtimes'][platform]['binary_sha256']:
            raise ValueError('packaged runtime digest mismatch')


def prepare_runtime(destination, lock):
    archive_path = os.environ.get('NONO_RUNTIME_ARCHIVE_' + lock['platform'].upper().replace('-', '_'))
    if archive_path:
        with Path(archive_path).open('rb') as source:
            archive = source.read(MAX_BYTES + 1)
    else:
        with urllib.request.urlopen(lock['url'], timeout=60) as response:
            archive = response.read(MAX_BYTES + 1)
    content = runtime_bytes(archive, lock)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('xb') as target:
        target.write(content)
    destination.chmod(0o500)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=['prepare', 'verify'])
    parser.add_argument('path', type=Path)
    parser.add_argument('platform', nargs='?', choices=PLATFORMS)
    args = parser.parse_args()
    lock = json.loads((Path(__file__).resolve().parent.parent/'runtime-lock.json').read_text())
    try:
        if args.operation == 'prepare':
            if args.platform is None:
                parser.error('prepare needs a platform')
            prepare_runtime(args.path, lock['runtimes'][args.platform])
        else:
            verify_package(args.path, lock)
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, f'Runtime package check failed: {type(error).__name__}.\n')


if __name__ == '__main__':
    main()
