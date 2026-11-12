#!/usr/bin/env python3
"""Create the appliance-managed KMIP root, issuing CA, and service identities."""
import json
import os
import secrets
import shutil
import subprocess
from pathlib import Path


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=300).stdout.strip()


def write(path, value, mode=0o600):
    path.write_text(value)
    os.chmod(path, mode)


def extensions(path, values):
    write(path, '\n'.join(values) + '\n')


def initialize(directory, kmip_fqdn):
    directory = Path(directory)
    if (directory / 'kms.toml').exists():
        return
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    root_key = directory / 'root-ca.key'
    root_cert = directory / 'root-ca.pem'
    issuing_key = directory / 'intermediate-ca.key'
    issuing_csr = directory / 'intermediate-ca.csr'
    issuing_cert = directory / 'intermediate-ca.pem'
    run('openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:4096','-out',str(root_key))
    run('openssl','req','-x509','-new','-sha256','-days','3650','-key',str(root_key),
        '-subj','/CN=Example Lab Security Appliance KMIP Root CA/O=Example Lab',
        '-addext','basicConstraints=critical,CA:TRUE,pathlen:1','-addext','keyUsage=critical,keyCertSign,cRLSign','-out',str(root_cert))
    run('openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:3072','-out',str(issuing_key))
    run('openssl','req','-new','-sha256','-key',str(issuing_key),
        '-subj','/CN=Example Lab Security Appliance KMIP Issuing CA/O=Example Lab','-out',str(issuing_csr))
    issuing_ext = directory / 'intermediate.ext'
    extensions(issuing_ext,['basicConstraints=critical,CA:TRUE,pathlen:0','keyUsage=critical,keyCertSign,cRLSign','subjectKeyIdentifier=hash','authorityKeyIdentifier=keyid,issuer'])
    run('openssl','x509','-req','-in',str(issuing_csr),'-CA',str(root_cert),'-CAkey',str(root_key),'-CAcreateserial','-days','1825','-sha256','-extfile',str(issuing_ext),'-out',str(issuing_cert))
    run('openssl','verify','-CAfile',str(root_cert),str(issuing_cert))
    shutil.copy2(issuing_key,directory/'ca.key')
    (directory/'ca.pem').write_bytes(issuing_cert.read_bytes()+root_cert.read_bytes())

    leaf_ext = directory / 'leaf.ext'
    for identity in ('server','client','other-client'):
        key=directory/(identity+'.key');csr=directory/(identity+'.csr');cert=directory/(identity+'.pem')
        run('openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:3072','-out',str(key))
        subject='/CN='+kmip_fqdn+'/O=Example Lab/OU=Security Appliance KMIP' if identity=='server' else '/CN='+identity
        run('openssl','req','-new','-sha256','-key',str(key),'-subj',subject,'-out',str(csr))
        if identity=='server':
            values=['basicConstraints=critical,CA:FALSE','keyUsage=critical,digitalSignature,keyEncipherment','extendedKeyUsage=serverAuth','subjectAltName=DNS:'+kmip_fqdn+',DNS:security-kmip,DNS:security-proxy,DNS:localhost','subjectKeyIdentifier=hash','authorityKeyIdentifier=keyid,issuer']
            days='825'
        else:
            values=['basicConstraints=critical,CA:FALSE','keyUsage=critical,digitalSignature,keyEncipherment','extendedKeyUsage=clientAuth','subjectKeyIdentifier=hash','authorityKeyIdentifier=keyid,issuer']
            days='397'
        extensions(leaf_ext,values)
        run('openssl','x509','-req','-in',str(csr),'-CA',str(issuing_cert),'-CAkey',str(issuing_key),'-CAcreateserial','-days',days,'-sha256','-extfile',str(leaf_ext),'-out',str(cert))
    password=secrets.token_urlsafe(32);write(directory/'p12-password',password)
    run('openssl','pkcs12','-export','-inkey',str(directory/'server.key'),'-in',str(directory/'server.pem'),'-certfile',str(directory/'ca.pem'),'-name','security-kmip','-out',str(directory/'server.p12'),'-passout','file:'+str(directory/'p12-password'))
    write(directory/'kms.toml','[tls]\ntls_p12_file="/qualification/server.p12"\ntls_p12_password="'+password+'"\nclients_ca_cert_file="/qualification/ca.pem"\n[socket_server]\nsocket_server_start=true\nsocket_server_port=5696\nsocket_server_hostname="0.0.0.0"\n[http]\nhostname="127.0.0.1"\nport=9998\n[db]\ndatabase_type="sqlite"\nsqlite_path="/data"\n')
    write(directory/'trust-metadata.json',json.dumps({'profile':'durable appliance-managed root and issuing CA','rootValidityDays':3650,'issuingValidityDays':1825,'serverValidityDays':825,'clientValidityDays':397,'revocationModel':'replace client trust bundle or issuing CA; individual CRL enforcement is not provided by this lab profile'},indent=2)+'\n')
    for item in directory.glob('*.key'):os.chmod(item,0o600)
    for item in directory.glob('*.pem'):os.chmod(item,0o644)
    for item in (issuing_csr,issuing_ext,leaf_ext):item.unlink(missing_ok=True)
