#!/usr/bin/env python3
"""Create and restore authenticated encrypted appliance recovery bundles."""
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

SCHEMA = 1
MAX_PAYLOAD = 4 * 1024 * 1024 * 1024


def _derive(passphrase, salt):
    if not isinstance(passphrase, str) or len(passphrase) < 20:
        raise ValueError('Recovery passphrase must contain at least 20 characters.')
    material = hashlib.scrypt(passphrase.encode(), salt=salt, n=32768, r=8, p=1, dklen=64, maxmem=128 * 1024 * 1024)
    return material[:32], material[32:]


def _openssl_crypt(source, target, key, iv, decrypt=False):
    try:
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        source_data = Path(source).read_bytes()
        if decrypt:
            transform = cipher.decryptor()
            padded = transform.update(source_data) + transform.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            Path(target).write_bytes(unpadder.update(padded) + unpadder.finalize())
        else:
            padder = padding.PKCS7(128).padder()
            padded = padder.update(source_data) + padder.finalize()
            transform = cipher.encryptor()
            Path(target).write_bytes(transform.update(padded) + transform.finalize())
        return
    except ImportError:
        pass
    command = ['openssl', 'enc', '-aes-256-cbc']
    if decrypt:
        command.append('-d')
    command += ['-K', key.hex(), '-iv', iv.hex(), '-in', str(source), '-out', str(target)]
    result = subprocess.run(command, capture_output=True, timeout=1800)
    if result.returncode:
        raise ValueError('Recovery payload encryption operation failed.')


def _safe_member(member):
    path = PurePosixPath(member.name)
    return not path.is_absolute() and '..' not in path.parts and not member.issym() and not member.islnk() and not member.isdev()


def create_bundle(paths, output, passphrase):
    sources = [Path(value).resolve() for value in paths]
    if not sources or any(not value.exists() for value in sources):
        raise ValueError('Recovery source is unavailable.')
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    salt, iv = os.urandom(16), os.urandom(16)
    key, mac_key = _derive(passphrase, salt)
    with tempfile.TemporaryDirectory() as folder:
        folder = Path(folder)
        archive_path, encrypted_path = folder / 'payload.tar.gz', folder / 'payload.bin'
        with tarfile.open(archive_path, 'w:gz', format=tarfile.PAX_FORMAT) as archive:
            # Capture the content selected by appliance-owned generation links. Restore
            # rejects all links so a bundle cannot recreate paths outside its target.
            archive.dereference = True
            for source in sources:
                archive.add(source, arcname=source.as_posix().lstrip('/'), recursive=True)
        _openssl_crypt(archive_path, encrypted_path, key, iv)
        payload = encrypted_path.read_bytes()
        if len(payload) > MAX_PAYLOAD:
            raise ValueError('Recovery payload is too large.')
        metadata = {'schemaVersion': SCHEMA, 'cipher': 'AES-256-CBC', 'kdf': 'scrypt-N32768-r8-p1', 'mac': 'HMAC-SHA256', 'salt': salt.hex(), 'iv': iv.hex(), 'sources': [value.as_posix() for value in sources]}
        metadata_raw = json.dumps(metadata, separators=(',', ':'), sort_keys=True).encode()
        mac = hmac.new(mac_key, metadata_raw + payload, hashlib.sha256).hexdigest()
        temporary = output.with_name(output.name + '.new')
        with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_STORED) as bundle:
            bundle.writestr('metadata.json', metadata_raw)
            bundle.writestr('payload.bin', payload)
            bundle.writestr('payload.hmac', mac)
        os.chmod(temporary, 0o600)
        temporary.replace(output)
    return {'created': True, 'sources': len(sources), 'bytes': output.stat().st_size, 'sha256': hashlib.sha256(output.read_bytes()).hexdigest()}


def restore_bundle(bundle, destination, passphrase):
    bundle, destination = Path(bundle), Path(destination)
    if not bundle.is_file() or bundle.stat().st_size > MAX_PAYLOAD:
        raise ValueError('Recovery bundle is unavailable or too large.')
    try:
        with zipfile.ZipFile(bundle) as container:
            names = container.namelist()
            if len(names) != 3 or len(set(names)) != 3 or set(names) != {'metadata.json', 'payload.bin', 'payload.hmac'}:
                raise ValueError('Recovery bundle contains unexpected records.')
            metadata_raw = container.read('metadata.json')
            metadata = json.loads(metadata_raw)
            payload = container.read('payload.bin')
            supplied_mac = container.read('payload.hmac').decode()
    except (zipfile.BadZipFile, KeyError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError('Invalid recovery bundle.') from exc
    if metadata.get('schemaVersion') != SCHEMA or metadata.get('cipher') != 'AES-256-CBC' or metadata.get('mac') != 'HMAC-SHA256':
        raise ValueError('Unsupported recovery bundle.')
    try:
        salt, iv = bytes.fromhex(metadata['salt']), bytes.fromhex(metadata['iv'])
    except (KeyError, ValueError) as exc:
        raise ValueError('Invalid recovery metadata.') from exc
    key, mac_key = _derive(passphrase, salt)
    expected_mac = hmac.new(mac_key, metadata_raw + payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_mac, supplied_mac):
        raise ValueError('Recovery bundle authentication failed.')
    if destination.exists() and any(destination.iterdir()):
        raise ValueError('Recovery destination must be empty.')
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as folder:
        folder = Path(folder)
        encrypted_path, archive_path = folder / 'payload.bin', folder / 'payload.tar.gz'
        encrypted_path.write_bytes(payload)
        _openssl_crypt(encrypted_path, archive_path, key, iv, decrypt=True)
        with tarfile.open(archive_path, 'r:gz') as archive:
            members = archive.getmembers()
            if not members or any(not _safe_member(member) for member in members):
                raise ValueError('Recovery archive contains an unsafe path or file type.')
            archive.extractall(destination, members=members, filter='data')
    return {'restored': True, 'sources': len(metadata.get('sources', [])), 'destination': str(destination)}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=('create', 'restore'))
    parser.add_argument('bundle')
    parser.add_argument('--path', action='append', default=[])
    parser.add_argument('--destination')
    args = parser.parse_args()
    password = os.environ.get('SECURITY_RECOVERY_PASSPHRASE', '')
    if args.operation == 'create':
        result = create_bundle(args.path, args.bundle, password)
    else:
        result = restore_bundle(args.bundle, args.destination, password)
    print(json.dumps(result, separators=(',', ':')))
