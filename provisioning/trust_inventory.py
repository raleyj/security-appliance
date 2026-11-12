"""Public certificate metadata for the bounded management trust inventory."""

import hashlib
import re
import subprocess
import time
from pathlib import Path

TLS = Path('/etc/security-appliance/tls/current')
KMIP = Path('/etc/security-appliance/kmip')


def openssl(*args):
    result = subprocess.run(['openssl', *map(str, args)], capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise ValueError('Certificate metadata is unavailable.')
    return result.stdout.strip()


def describe(role, path, ca=None):
    if not path.is_file() or path.stat().st_size > 16384:
        return {'role': role, 'available': False, 'trustStatus': 'unavailable'}
    details = openssl('x509', '-in', path, '-noout', '-subject', '-issuer', '-dates', '-ext', 'subjectAltName')
    der = subprocess.run(['openssl', 'x509', '-in', str(path), '-outform', 'DER'], capture_output=True, timeout=10, check=True).stdout
    match = re.search(r'notAfter=(.+)', details)
    expires = match.group(1).strip() if match else ''
    try:
        from email.utils import parsedate_to_datetime
        remaining = int((parsedate_to_datetime(expires).timestamp() - time.time()) // 86400)
    except (TypeError, ValueError):
        remaining = None
    names = sorted(set(re.findall(r'DNS:([^,\s]+)', details)))[:20]
    trust = 'not checked'
    if ca and ca.is_file():
        result = subprocess.run(['openssl', 'verify', '-CAfile', str(ca), str(path)], capture_output=True, timeout=10)
        trust = 'trusted' if result.returncode == 0 else 'verification failed'
    return {
        'role': role, 'available': True,
        'subject': next((x[8:].strip() for x in details.splitlines() if x.startswith('subject=')), ''),
        'issuer': next((x[7:].strip() for x in details.splitlines() if x.startswith('issuer=')), ''),
        'dnsNames': names, 'sha256': hashlib.sha256(der).hexdigest(),
        'expires': expires, 'daysRemaining': remaining, 'trustStatus': trust,
    }


def inventory():
    management_ca = TLS / 'ca.pem'
    kmip_ca = KMIP / 'ca.pem'
    rows = [
        describe('Management HTTPS', TLS / 'server.crt', management_ca),
        describe('Keycloak HTTPS', TLS / 'server.crt', management_ca),
        describe('Management issuing CA', management_ca, management_ca),
        describe('KMIP server', KMIP / 'server.pem', kmip_ca),
        describe('KMIP issuing CA', KMIP / 'intermediate-ca.pem', KMIP / 'root-ca.pem'),
        describe('KMIP root CA', KMIP / 'root-ca.pem', KMIP / 'root-ca.pem'),
    ]
    clients = sorted((KMIP / 'enrolled-clients').glob('*.pem'))[:20]
    rows.extend(describe('KMIP client', path, kmip_ca) for path in clients)
    return {'checkedAt': time.time(), 'certificates': rows, 'clientInventoryTruncated': len(list((KMIP / 'enrolled-clients').glob('*.pem'))) > 20,
            'revocationNote': 'Management certificates are revoked through their issuing CA. The KMIP lab profile removes client trust rather than enforcing individual CRLs.'}


def public_chain(kind):
    if kind == 'management':
        path = TLS / 'ca.pem'
    elif kind == 'kmip':
        path = KMIP / 'ca.pem'
    else:
        raise ValueError('Unsupported public chain.')
    content = path.read_text()
    if len(content) > 32768 or '-----BEGIN CERTIFICATE-----' not in content or 'PRIVATE KEY' in content:
        raise ValueError('Public chain is unavailable.')
    return {'kind': kind, 'pem': content}
