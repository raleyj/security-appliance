"""Verify a sanitized OVF and write a SHA-256 manifest for OVA packaging."""
import hashlib,re,sys
from pathlib import Path
from xml.etree import ElementTree as ET

NS='http://schemas.dmtf.org/ovf/envelope/1'
Q='{'+NS+'}'

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):
            h.update(block)
    return h.hexdigest()

def main(path):
    root=ET.parse(path).getroot()
    vm=root.find(Q+'VirtualSystem')
    if vm is None or vm.get(Q+'id')!='Lab-Security-Appliance' or vm.findtext(Q+'Name')!='Lab Security Appliance':
        raise ValueError('The release OVF identity was not generalized.')
    network=root.find(Q+'NetworkSection/'+Q+'Network')
    if network is None or network.get(Q+'name')!='Appliance Network':
        raise ValueError('The release OVF network was not generalized.')
    properties=vm.findall(Q+'ProductSection/'+Q+'Property')
    keys={item.get(Q+'key') for item in properties}
    required={'guestinfo.security.hostname','guestinfo.security.domain','guestinfo.security.network_mode','guestinfo.security.ip','guestinfo.security.prefix','guestinfo.security.gateway','guestinfo.security.dns','guestinfo.security.ntp','guestinfo.security.admin_cidrs','guestinfo.security.web_admin_username','guestinfo.security.web_admin_password','guestinfo.security.console_recovery_password','guestinfo.security.identity_admin_username','guestinfo.security.identity_admin_password','guestinfo.security.sso_fqdn','guestinfo.security.kmip_fqdn','guestinfo.security.kmip_client_cidrs'}
    if keys!=required or any(item.get(Q+'value') for item in properties if item.get(Q+'password')=='true'):
        raise ValueError('Deployment property set or password defaults are unsafe.')
    content=path.read_text()
    if any(marker in content for marker in ('user-data','instance-id','build-auth-bypass','192.0.2.73')) or re.search(r'security-release-seal-v\d+',content):
        raise ValueError('Build or lab staging content remains in the OVF.')
    files=[path]
    for item in root.findall(Q+'References/'+Q+'File'):
        href=item.get(Q+'href')
        if not href or Path(href).name!=href:raise ValueError('Unsafe referenced filename.')
        referenced=path.parent/href
        if not referenced.is_file() or referenced.stat().st_size!=int(item.get(Q+'size')):
            raise ValueError(f'Missing or size-mismatched OVF reference: {href}')
        files.append(referenced)
    if len(files)!=4:raise ValueError('Expected OVF, two disks and NVRAM.')
    manifest=path.with_suffix('.mf')
    manifest.write_text(''.join(f'SHA256({item.name})= {digest(item)}\n' for item in files))
    print(f'Wrote {manifest.name} with {len(files)} SHA-256 entries.')

if __name__=='__main__':main(Path(sys.argv[1]))
