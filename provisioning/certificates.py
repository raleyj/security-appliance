"""Bounded management TLS operations; private keys never leave the host.

Caller must serialize operations with the host transaction lock.
"""
import json, os, re, secrets, shutil, subprocess
from pathlib import Path
ROOT = Path('/etc/security-appliance')

def run(*args):
    try:
        return subprocess.run(args, check=True, capture_output=True, text=True, timeout=30).stdout
    except (subprocess.SubprocessError, OSError):
        raise ValueError('Certificate validation or activation failed.') from None

def write(path, data):
    tmp=path.with_suffix('.new');tmp.write_text(data);os.chmod(tmp,0o600);tmp.replace(path)

def fqdn():
    cfg=json.loads((ROOT/'config.json').read_text())
    name=cfg['hostname']+'.'+cfg['domain']
    if len(name)>253 or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',v) for v in name.split('.')):
        raise ValueError('Invalid applied hostname.')
    return name.lower()

def dns_names():
    cfg=json.loads((ROOT/'config.json').read_text())
    return list(dict.fromkeys([fqdn(),cfg['sso_fqdn'].lower(),cfg['kmip_fqdn'].lower()]))

def migrate():
    tls=ROOT/'tls';current=tls/'current'
    if not current.exists():
        initial=tls/'initial';initial.mkdir(exist_ok=True,mode=0o700)
        for name in ('server.key','server.crt'):
            shutil.copyfile(tls/name,initial/name);os.chmod(initial/name,0o600)
        current.symlink_to('initial',target_is_directory=True)
    conf=ROOT/'nginx.conf'
    conf.write_text(conf.read_text().replace('/certs/server.','/certs/current/server.'))

def switch(target):
    tls=ROOT/'tls'
    if not re.fullmatch(r'(initial|generation-[0-9a-f]{16})',target):raise ValueError('Invalid certificate generation.')
    link=tls/'next';link.unlink(missing_ok=True);link.symlink_to(target,target_is_directory=True);link.replace(tls/'current')

def recover():
    journal=ROOT/'tls-transaction.json'
    if journal.exists():
        switch(json.loads(journal.read_text())['previous']);journal.unlink()

def status():
    tls=ROOT/'tls';cert=tls/'current/server.crt'
    if not cert.exists():cert=tls/'server.crt'
    details=run('openssl','x509','-in',str(cert),'-noout','-subject','-issuer','-dates','-fingerprint','-sha256')
    return {'fqdn':fqdn(),'details':details,'csrPending':(tls/'request/server.csr').exists(),
            'enrolled':(tls/'current/ca.pem').exists()}

def csr():
    tls=ROOT/'tls';pending=tls/'request';name=fqdn();names=dns_names()
    if pending.exists():
        meta=json.loads((pending/'metadata.json').read_text())
        if meta['fqdn']!=name or meta.get('dnsNames',[name])!=names:raise ValueError('Applied service identities changed. Finish or discard the pending certificate request first.')
        return {'fqdn':name,'dnsNames':names,'csr':(pending/'server.csr').read_text()}
    temp=tls/('request-'+secrets.token_hex(8));temp.mkdir(mode=0o700)
    try:
        run('openssl','req','-new','-newkey','rsa:3072','-nodes','-sha256','-keyout',str(temp/'server.key'),'-out',str(temp/'server.csr'),'-subj','/CN='+name,'-addext','subjectAltName='+','.join('DNS:'+value for value in names))
        os.chmod(temp/'server.key',0o600)
        write(temp/'metadata.json',json.dumps({'fqdn':name,'dnsNames':names}))
        temp.rename(pending)
    finally:
        if temp.exists():shutil.rmtree(temp)
    return {'fqdn':name,'dnsNames':names,'csr':(pending/'server.csr').read_text()}

def pem(value, multiple=False):
    if not isinstance(value,str) or len(value)>18000:raise ValueError('Invalid certificate size.')
    blocks=re.findall(r'-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----',value)
    residue=value
    for block in blocks:residue=residue.replace(block,'',1)
    if residue.strip() or not blocks or (not multiple and len(blocks)!=1):raise ValueError('Supply PEM certificates only; never upload private keys.')
    return '\n'.join(blocks)+'\n'

def validate(directory):
    name=fqdn();names=dns_names();request=ROOT/'tls/request'
    if json.loads((request/'metadata.json').read_text())['fqdn']!=name:raise ValueError('CSR hostname does not match applied settings.')
    leaf=directory/'leaf.pem';ca=directory/'ca.pem'
    certkey=run('openssl','x509','-in',str(leaf),'-pubkey','-noout')
    key=run('openssl','pkey','-in',str(request/'server.key'),'-pubout')
    if certkey!=key:raise ValueError('Certificate does not match the appliance CSR.')
    constraints=run('openssl','x509','-in',str(leaf),'-noout','-ext','basicConstraints')
    sans=run('openssl','x509','-in',str(leaf),'-noout','-ext','subjectAltName')
    certificate_names=[v.strip().removeprefix('DNS:') for v in sans.splitlines()[-1].split(',') if v.strip().startswith('DNS:')]
    if 'CA:TRUE' in constraints or any(required not in certificate_names for required in names):raise ValueError('Certificate requires every configured appliance service DNS SAN and must not be a CA.')
    anchors=re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',ca.read_text(),re.S)
    for block in anchors:
        anchor=directory/'anchor.pem';write(anchor,block+'\n')
        if 'CA:TRUE' not in run('openssl','x509','-in',str(anchor),'-noout','-ext','basicConstraints'):
            raise ValueError('Trust anchors must be CA certificates.')
    (directory/'anchor.pem').unlink(missing_ok=True)
    run('openssl','x509','-in',str(leaf),'-checkend','86400','-noout')
    args=['openssl','verify','-trusted',str(ca),'-purpose','sslserver','-verify_hostname',name,'-auth_level','2']
    if (directory/'intermediates.pem').stat().st_size:args+=['-untrusted',str(directory/'intermediates.pem')]
    run(*args,str(leaf))

def reload_proxy():
    run('docker','exec','security-proxy','nginx','-t')
    run('docker','exec','security-proxy','nginx','-s','reload')

def activate(data, reload=reload_proxy):
    if (ROOT/'pending-network.json').exists():raise ValueError('Confirm or roll back network changes first.')
    tls=ROOT/'tls';request=tls/'request'
    if not request.exists():raise ValueError('Generate an appliance CSR first.')
    generation=tls/('generation-'+secrets.token_hex(8));generation.mkdir(mode=0o700)
    committed=False
    try:
        write(generation/'leaf.pem',pem(data.get('certificate')))
        write(generation/'ca.pem',pem(data.get('ca'),True))
        chain=data.get('intermediates','')
        write(generation/'intermediates.pem',pem(chain,True) if chain else '')
        validate(generation)
        write(generation/'server.crt',(generation/'leaf.pem').read_text()+(generation/'intermediates.pem').read_text())
        shutil.copyfile(request/'server.key',generation/'server.key');os.chmod(generation/'server.key',0o600)
        previous=os.readlink(tls/'current')
        journal=ROOT/'tls-transaction.json';write(journal,json.dumps({'previous':previous}))
        try:
            switch(generation.name);reload()
            journal.unlink();committed=True
        except Exception:
            switch(previous);reload();journal.unlink();raise
        shutil.rmtree(request)
        return status()
    finally:
        if not committed and generation.exists() and os.readlink(tls/'current')!=generation.name:shutil.rmtree(generation)

def perform(data):
    action=data['action']
    if action=='certificate-status':return status()
    if action=='certificate-csr':return csr()
    if action=='certificate-import':return activate(data)
    if action=='certificate-discard':
        pending=ROOT/'tls/request'
        if pending.exists():shutil.rmtree(pending)
        return {'discarded':True}
    raise ValueError('Unsupported certificate operation.')

if __name__=='__main__':migrate();recover()
