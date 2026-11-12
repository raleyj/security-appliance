"""Check the offline image archive, lockfile, and release Compose contract."""
import hashlib
import json
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'build' / 'full-container-bundle'
EXPECTED = {
    'lab-security-management:0.3.0',
    'lab-security-keycloak:0.3.0',
    'lab-security-proxy:1.30.6-alpine-security-20261111',
    'lab-security-postgres:17',
    'lab-security-kmip:5.25.0',
    'lab-security-forward-proxy:6.6-24.04-security-20261111',
    'lab-security-kmip-client:0.2.0',
}
SERVICES = {'management', 'proxy', 'forward-proxy', 'postgres', 'keycloak', 'kmip'}


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def verify():
    manifest = json.loads((OUT / 'manifest.json').read_text())
    archive = OUT / manifest['archive']
    if not archive.is_file() or digest(archive) != manifest['sha256']:
        raise ValueError('Archive checksum mismatch.')
    if archive.stat().st_size != manifest['sizeBytes']:
        raise ValueError('Archive size mismatch.')
    if {row['reference'] for row in manifest['images']} != EXPECTED:
        raise ValueError('Offline image inventory is incomplete.')
    if digest(ROOT / 'build' / 'release-evidence' / 'component-lock.json') != manifest['componentLockSha256']:
        raise ValueError('Source lock differs from the bundle manifest.')
    lock = json.loads((ROOT / 'build' / 'release-evidence' / 'component-lock.json').read_text())
    pinned = lock['containerImages']
    if len(pinned) != 7 or not all('@sha256:' in image for image in pinned):
        raise ValueError('Release source images are not all digest pinned.')
    if not any('cosmian/kms:5.25.0@sha256:' in image for image in pinned):
        raise ValueError('Qualified KMIP backend is absent from the lock.')
    if not any('ubuntu/squid:6.6-24.04_edge@sha256:' in image for image in pinned):
        raise ValueError('Forward proxy is absent from the lock.')
    with tarfile.open(archive) as bundle:
        docker_manifest = json.load(bundle.extractfile('manifest.json'))
    tags = {tag for item in docker_manifest for tag in (item.get('RepoTags') or [])}
    if not EXPECTED.issubset(tags):
        raise ValueError('Docker archive does not contain every required image tag.')
    compose = json.loads((OUT / 'compose.release.json').read_text())
    if set(compose['services']) != SERVICES:
        raise ValueError('Compose service set mismatch.')
    if {spec['image'] for spec in compose['services'].values()} != EXPECTED - {'lab-security-kmip-client:0.2.0'}:
        raise ValueError('Compose image set mismatch.')
    published = {name for name, spec in compose['services'].items() if spec.get('ports')}
    if published != {'proxy'}:
        raise ValueError('Only the reverse proxy may publish ports before first-boot configuration.')
    if any('/var/run/docker.sock' in str(spec) or 'SECURITY_BUILD_AUTH_BYPASS' in str(spec)
           for spec in compose['services'].values()):
        raise ValueError('Build-only or privileged control is present in the release contract.')
    result = {'archiveSha256': manifest['sha256'], 'archiveSizeBytes': manifest['sizeBytes'],
              'runtimeImages': len(SERVICES), 'qualificationImages': len(EXPECTED) - len(SERVICES),
              'composeServices': len(SERVICES), 'onlyProxyPublishesByDefault': True,
              'dockerSocketAbsent': True, 'buildAutoLoginAbsent': True}
    print(json.dumps(result, indent=2))
    return result


if __name__ == '__main__':
    verify()
