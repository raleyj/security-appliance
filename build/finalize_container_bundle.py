"""Record the exact offline archive and a non-secret Compose qualification contract."""
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'build' / 'full-container-bundle'
ARCHIVE = OUT / 'lab-security-appliance-containers.tar'
IMAGES = [
    'lab-security-management:0.3.0',
    'lab-security-keycloak:0.3.0',
    'lab-security-proxy:1.30.6-alpine-security-20261111',
    'lab-security-postgres:17',
    'lab-security-kmip:5.25.0',
    'lab-security-forward-proxy:6.6-24.04-security-20261111',
    'lab-security-kmip-client:0.2.0',
]


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def inspect(reference):
    details = json.loads(subprocess.check_output(['docker', 'image', 'inspect', reference], text=True))[0]
    return {'reference': reference, 'imageId': details['Id'], 'repoDigests': details.get('RepoDigests') or []}


def release_compose():
    """Model the first-boot default; firstboot renders the effective runtime Compose file."""
    common = {'restart': 'no', 'read_only': True, 'security_opt': ['no-new-privileges:true'], 'pull_policy': 'never'}
    networks = {name: {'external': True, 'name': 'security-' + name} for name in
                ('management', 'edge', 'forward-proxy', 'identity', 'database', 'kmip')}
    services = {
        'management': {**common, 'image': IMAGES[0], 'cap_drop': ['ALL'], 'networks': ['management']},
        'proxy': {**common, 'image': IMAGES[2], 'networks': ['edge', 'management', 'identity', 'kmip'],
                  'ports': ['80:80', '443:443'], 'depends_on': ['management']},
        'forward-proxy': {**common, 'image': IMAGES[5], 'cap_drop': ['ALL'], 'user': '13:13',
                          'networks': ['forward-proxy']},
        'postgres': {**common, 'image': IMAGES[3], 'networks': ['database']},
        'keycloak': {**common, 'image': IMAGES[1], 'networks': ['identity', 'database'],
                     'depends_on': {'postgres': {'condition': 'service_healthy'}}},
        'kmip': {**common, 'image': IMAGES[4], 'networks': ['kmip']},
    }
    return {'name': 'security-appliance', 'x-qualification-default': 'forward and KMIP client ports closed until configured',
            'services': services, 'networks': networks}


def main():
    if not ARCHIVE.is_file():
        raise SystemExit('Offline container archive is missing.')
    records = [inspect(reference) for reference in IMAGES]
    manifest = {
        'schemaVersion': 1,
        'authorityVersion': '1.73',
        'scope': 'Six runtime containers and the offline KMIP qualification client',
        'createdUtc': datetime.now(timezone.utc).isoformat(),
        'archive': ARCHIVE.name,
        'sizeBytes': ARCHIVE.stat().st_size,
        'sha256': digest(ARCHIVE),
        'componentLockSha256': digest(ROOT / 'build' / 'release-evidence' / 'component-lock.json'),
        'images': records,
        'offlineLoadCommand': 'docker load --input lab-security-appliance-containers.tar',
    }
    (OUT / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (OUT / 'compose.release.json').write_text(json.dumps(release_compose(), indent=2) + '\n')
    print(json.dumps({'archiveSha256': manifest['sha256'], 'sizeBytes': manifest['sizeBytes'],
                      'images': len(records)}, indent=2))


if __name__ == '__main__':
    main()
