"""Bounded KMIP client enrollment using the appliance-owned issuing CA."""

import json
import os
import re
import secrets
import subprocess
import tempfile
from pathlib import Path

KMIP = Path('/etc/security-appliance/kmip')
NAME = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+')
CSR = re.compile(r'\A-----BEGIN CERTIFICATE REQUEST-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE REQUEST-----\s*\Z')


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise ValueError('KMIP client certificate validation or signing failed.')
    return result.stdout.strip()


def public():
    for name in ('root-ca.pem', 'intermediate-ca.pem', 'server.pem'):
        if not (KMIP / name).is_file():
            raise ValueError('KMIP trust material is unavailable.')
    return {
        'rootCa': (KMIP / 'root-ca.pem').read_text(),
        'issuingCa': (KMIP / 'intermediate-ca.pem').read_text(),
        'serverCertificate': (KMIP / 'server.pem').read_text(),
    }


def sign_client(csr_text, expected_name):
    if not isinstance(expected_name, str) or not NAME.fullmatch(expected_name) or len(expected_name) > 253:
        raise ValueError('A valid client DNS name is required.')
    if not isinstance(csr_text, str) or len(csr_text) > 8192 or not CSR.fullmatch(csr_text):
        raise ValueError('Supply one PEM certificate signing request.')
    public()
    with tempfile.TemporaryDirectory(prefix='client-enroll-', dir=KMIP) as folder:
        folder = Path(folder)
        csr_path = folder / 'client.csr'
        csr_path.write_text(csr_text)
        os.chmod(csr_path, 0o600)
        run('openssl', 'req', '-in', str(csr_path), '-verify', '-noout')
        subject = run('openssl', 'req', '-in', str(csr_path), '-noout', '-subject', '-nameopt', 'RFC2253')
        if not re.search(r'(?:^|,)CN=' + re.escape(expected_name) + r'(?:,|$)', subject.split('=', 1)[-1]):
            raise ValueError('CSR common name does not match the expected client.')
        extensions = folder / 'client.ext'
        extensions.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n')
        os.chmod(extensions, 0o600)
        cert_path = folder / 'client.pem'
        run('openssl', 'x509', '-req', '-in', str(csr_path), '-CA', str(KMIP / 'intermediate-ca.pem'), '-CAkey', str(KMIP / 'intermediate-ca.key'), '-CAcreateserial', '-days', '397', '-sha256', '-extfile', str(extensions), '-out', str(cert_path))
        run('openssl', 'verify', '-CAfile', str(KMIP / 'ca.pem'), '-purpose', 'sslclient', str(cert_path))
        certificate = cert_path.read_text()
        serial = run('openssl', 'x509', '-in', str(cert_path), '-noout', '-serial').split('=', 1)[-1]
        expires = run('openssl', 'x509', '-in', str(cert_path), '-noout', '-enddate').split('=', 1)[-1]
        store = KMIP / 'enrolled-clients'
        store.mkdir(mode=0o700, exist_ok=True)
        record = store / (secrets.token_hex(12) + '.pem')
        record.write_text(certificate)
        os.chmod(record, 0o600)
    return {'clientName': expected_name, 'certificate': certificate, 'serial': serial, 'expires': expires, **public()}


def perform(data):
    if data['action'] == 'kmip-trust-public':
        return public()
    if data['action'] == 'kmip-sign-client':
        return sign_client(data.get('csr'), data.get('clientName'))
    raise ValueError('Unsupported KMIP enrollment operation.')
