"""Fixed, read-only appliance storage and diagnostic summaries."""
import json
import os
import subprocess
import time
from pathlib import Path

STATE = Path('/etc/security-appliance')
DATA = Path('/var/lib/security-appliance')
SAMPLES = STATE / 'storage-samples.json'
STORAGE_PATHS = (
    ('PostgreSQL', (DATA / 'postgres',)),
    ('Keycloak', (DATA / 'keycloak',)),
    ('KMIP state and certificates', (DATA / 'kmip', STATE / 'kmip')),
    ('Management state', (DATA / 'management',)),
    ('Update staging', (DATA / 'management/update-staging',)),
)
CONTAINERS = ('management', 'proxy', 'forward-proxy', 'postgres', 'keycloak', 'kmip')


def directory_bytes(path):
    if not path.exists():
        return 0
    result = subprocess.run(['du', '-sb', '--', str(path)], capture_output=True, text=True, timeout=12)
    if result.returncode:
        raise ValueError('Storage measurement is unavailable.')
    return max(0, int(result.stdout.split()[0]))


def log_bytes():
    total = 0
    for service in CONTAINERS:
        try:
            result = subprocess.run(['docker', 'inspect', 'security-' + service, '--format', '{{.LogPath}}'], capture_output=True, text=True, timeout=5)
            path = Path(result.stdout.strip())
            if result.returncode == 0 and path.is_file() and '/containers/' in str(path) and path.name.endswith('-json.log'):
                total += path.stat().st_size
        except (OSError, ValueError, subprocess.TimeoutExpired):
            continue
    return total


def samples():
    try:
        rows = json.loads(SAMPLES.read_text())
        return rows[-48:] if isinstance(rows, list) else []
    except (OSError, ValueError):
        return []


def storage_report():
    now = time.time()
    usage = os.statvfs(DATA)
    total = usage.f_blocks * usage.f_frsize
    free = usage.f_bavail * usage.f_frsize
    used = max(0, total - free)
    percent = round(100 * used / total, 1) if total else 0
    status = 'critical' if percent >= 90 else ('warning' if percent >= 85 else 'healthy')
    rows = [{'name': name, 'bytes': sum(directory_bytes(path) for path in paths)} for name, paths in STORAGE_PATHS]
    rows[3]['bytes'] = max(0, rows[3]['bytes'] - rows[4]['bytes'])
    rows.append({'name': 'Container logs', 'bytes': log_bytes()})
    rows.append({'name': 'Support bundles', 'bytes': 0, 'note': 'Generated on download; no retained bundle files.'})
    history = samples()
    current = {'at': now, 'used': used, 'categories': {row['name']: row['bytes'] for row in rows}}
    if not history or now - history[-1].get('at', 0) >= 3600:
        history = (history + [current])[-48:]
        try:
            temp = SAMPLES.with_suffix('.new')
            temp.write_text(json.dumps(history, separators=(',', ':')))
            os.chmod(temp, 0o600)
            temp.replace(SAMPLES)
        except OSError:
            pass
    previous = next((entry for entry in reversed(history) if now - entry.get('at', now) >= 86400), None)
    for row in rows:
        row['growth24h'] = row['bytes'] - previous.get('categories', {}).get(row['name'], 0) if previous and row['name'] in previous.get('categories', {}) else None
    return {'checkedAt': now, 'total': total, 'used': used, 'free': free, 'usedPercent': percent, 'status': status,
            'warningAtPercent': 85, 'criticalAtPercent': 90, 'categories': rows, 'growthAvailable': previous is not None}


def oidc_probe():
    """Check bounded discovery fields on Keycloak's private network."""
    try:
        import service_control
        discovery = service_control.http(service_control.kcbase() + '/realms/master/.well-known/openid-configuration')
        return isinstance(discovery, dict) and all(discovery.get(field) for field in ('issuer', 'authorization_endpoint', 'jwks_uri'))
    except (OSError, ValueError, KeyError, TypeError):
        return False


def diagnostics(health, readiness, url_check):
    now = time.time()
    rows = []
    def add(code, label, passed, detail):
        rows.append({'code': code, 'label': label, 'state': 'pass' if passed else 'attention', 'detail': detail})
    add('dns', 'DNS', health.get('dnsHealthy'), 'Configured appliance names resolve through active DNS.')
    add('ntp', 'NTP', health.get('ntpHealthy'), 'The approved time source has answered and the clock is synchronized.')
    cert = health.get('certificate') or {}
    add('certificate', 'Management certificate', cert.get('enrolled') and (cert.get('daysRemaining') or 0) >= 30, 'An enrolled HTTPS certificate has at least 30 days remaining.')
    add('firewall', 'Firewall', health.get('firewallActive'), 'The appliance host firewall is active.')
    add('containers', 'Containers', health.get('servicesHealthy'), 'Required service containers are ready.')
    add('kmip', 'KMIP mutual TLS', readiness('kmip'), 'A fixed local mutual-TLS readiness check succeeds.')
    add('proxy', 'Reverse proxy', readiness('proxy'), 'Nginx accepts its active configuration.')
    add('oidc', 'OIDC discovery', oidc_probe(), 'Private Keycloak discovery returns issuer, authorization and signing-key endpoints.')
    add('management', 'Management backend', readiness('management'), 'The private management backend responds behind the reverse proxy.')
    return {'checkedAt': now, 'checks': rows, 'attention': sum(row['state'] == 'attention' for row in rows)}
