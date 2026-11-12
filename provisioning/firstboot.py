#!/usr/bin/python3
"""Bounded release first boot from the validated OVF deployment contract."""
import hashlib,json,os,subprocess,sys,time
from pathlib import Path
ROOT=Path('/etc/security-appliance');DATA=Path('/var/lib/security-appliance')
sys.path.insert(0,'/opt/security-appliance/provisioning')
from ovf_input import parse
def run(*args,timeout=600):
 p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
 if p.returncode:raise RuntimeError(args[0]+' failed: '+(p.stderr or p.stdout)[-800:].strip())
 return p.stdout.strip()
def verifier(value):
 salt=os.urandom(16);digest=hashlib.scrypt(value.encode(),salt=salt,n=16384,r=8,p=1,dklen=64)
 return {'salt':salt.hex(),'hash':digest.hex()}
def write(path,value):path.write_text(value);os.chmod(path,0o600)
if (ROOT/'installed').exists():raise SystemExit(0)
try:
 (ROOT/'build-auth-bypass').unlink(missing_ok=True);(DATA/'management/build-auth-bypass.json').unlink(missing_ok=True)
 cfg,values=parse(run('vmtoolsd','--cmd','info-get guestinfo.ovfEnv',timeout=30))
 interfaces=[p.name for p in Path('/sys/class/net').iterdir() if p.name!='lo' and (p/'device').exists()]
 if len(interfaces)!=1:raise ValueError('Exactly one appliance network adapter is required.')
 nic={'dhcp4':cfg['network_mode']=='dhcp','dhcp6':False,'accept-ra':False}
 if cfg['dns']:nic['nameservers']={'addresses':cfg['dns'],'search':[cfg['domain']]}
 if cfg['network_mode']=='dhcp':nic['dhcp4-overrides']={'use-dns':not bool(cfg['dns']),'use-ntp':False}
 if cfg['network_mode']=='static':nic.update(addresses=[f"{cfg['ip']}/{cfg['prefix']}"],routes=[{'to':'default','via':cfg['gateway']}])
 for old in Path('/etc/netplan').glob('*.yaml'):old.unlink()
 Path('/etc/netplan/60-security.yaml').write_text(json.dumps({'network':{'version':2,'renderer':'networkd','ethernets':{interfaces[0]:nic}}}))
 run('netplan','generate');run('hostnamectl','set-hostname',cfg['hostname']);run('netplan','apply')
 ntp=Path('/etc/systemd/timesyncd.conf.d');ntp.mkdir(exist_ok=True);ntp.chmod(0o755);(ntp/'security.conf').unlink(missing_ok=True);ntp_file=ntp/'99-security.conf';ntp_file.write_text('[Time]\nNTP='+' '.join(cfg['ntp'])+'\nFallbackNTP='+' '.join(cfg['ntp'])+'\n');ntp_file.chmod(0o644);run('systemctl','restart','systemd-timesyncd')
 if run('lsblk','-bdno','SIZE','/dev/sdb')!='68719476736':raise ValueError('The required 64 GiB data disk is unavailable.')
 label=subprocess.run(['blkid','-s','LABEL','-o','value','/dev/sdb'],capture_output=True,text=True).stdout.strip()
 if not label:
  if len(run('lsblk','-n','/dev/sdb').splitlines())!=1:raise ValueError('The data disk contains an unsupported layout.')
  run('mkfs.ext4','-L','security-data','/dev/sdb')
 elif label!='security-data':raise ValueError('The data disk has an unexpected filesystem label.')
 if 'LABEL=security-data /var/lib/security-appliance' not in Path('/etc/fstab').read_text():
  with open('/etc/fstab','a') as f:f.write('LABEL=security-data /var/lib/security-appliance ext4 defaults 0 2\n')
 DATA.mkdir(mode=0o700,exist_ok=True)
 if subprocess.run(['mountpoint','-q',str(DATA)]).returncode:run('mount',str(DATA))
 (DATA/'management').mkdir(mode=0o700,exist_ok=True)
 ROOT.mkdir(mode=0o700,exist_ok=True);(ROOT/'tls').mkdir(mode=0o700,exist_ok=True)
 write(ROOT/'config.json',json.dumps(cfg));write(ROOT/'network-confirmed.json',json.dumps({'digest':hashlib.sha256(json.dumps(cfg,sort_keys=True).encode()).hexdigest(),'at':time.time(),'source':'OVA deployment'}));write(ROOT/'recovery.json',json.dumps(verifier(values['console_recovery_password'])))
 write(ROOT/'deployment-secrets.json',json.dumps({'identity_username':values['identity_admin_username'],'identity_password':values['identity_admin_password']}))
 write(ROOT/'auth.json',json.dumps({'username':values['web_admin_username'],'config':cfg,'web':verifier(values['web_admin_password'])}))
 run('python3','/opt/security-appliance/provisioning/firewall.py','--build')
 for attempt in range(60):
  if subprocess.run(['docker','info'],capture_output=True).returncode==0:break
  time.sleep(2)
 else:raise RuntimeError('Docker did not become ready during the bounded first-boot interval.')
 if not (DATA/'management/management.sqlite').exists():run('docker','run','--rm','--network','none','--user','0','-v',str(DATA/'management')+':/var/lib/security-appliance/management','-v',str(ROOT)+':/bootstrap:ro','-v','/opt/security-appliance/provisioning/bootstrap_state.py:/bootstrap_state.py:ro','lab-security-management:0.3.0','python','/bootstrap_state.py')
 run('chown','-R','10001:10001',str(DATA/'management'))
 run('python3','/opt/security-appliance/provisioning/prepare_services.py')
 tls=ROOT/'tls'
 if not (tls/'server.crt').exists():
  fqdn=cfg['hostname']+'.'+cfg['domain'];run('openssl','req','-x509','-newkey','rsa:3072','-nodes','-keyout',str(tls/'server.key'),'-out',str(tls/'server.crt'),'-days','30','-subj','/CN='+fqdn,'-addext','subjectAltName=DNS:'+fqdn);os.chmod(tls/'server.key',0o600)
 run('python3','/opt/security-appliance/provisioning/render_proxy.py');run('python3','/opt/security-appliance/provisioning/certificates.py')
 for net in ['security-management','security-edge']:
  if subprocess.run(['docker','network','inspect',net],capture_output=True).returncode:run('docker','network','create',*(['--internal'] if net.endswith('management') else []),net)
 run('python3','/opt/security-appliance/provisioning/compose_runtime.py')
 (ROOT/'installed').touch(mode=0o600);(ROOT/'auth.json').unlink(missing_ok=True)
 run('systemctl','daemon-reload');run('systemctl','enable','security-host-control','security-appliance','security-console');run('systemctl','start','security-host-control','security-appliance')
 run('python3','/opt/security-appliance/provisioning/service_control.py','--initialize');(ROOT/'deployment-secrets.json').unlink(missing_ok=True)
 run('docker','compose','-f',str(ROOT/'compose.json'),'up','-d','--no-deps','--force-recreate','--pull','never','keycloak')
 run('systemctl','start','security-console');run('python3','/opt/security-appliance/provisioning/report.py')
except Exception as exc:
 status={'state':'failed','reason':str(exc)[:500],'time':time.time()};write(ROOT/'firstboot-status.json',json.dumps(status));subprocess.run(['vmtoolsd','--cmd','info-set guestinfo.security.firstboot '+json.dumps(status)]);raise
else:
 status={'state':'complete','time':time.time()};write(ROOT/'firstboot-status.json',json.dumps(status));subprocess.run(['vmtoolsd','--cmd','info-set guestinfo.security.firstboot '+json.dumps(status)])
