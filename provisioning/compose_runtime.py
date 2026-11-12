"""Build the prototype Compose contract from locally verified image identities."""
import json, subprocess
from pathlib import Path
ROOT=Path('/etc/security-appliance')
FORWARD='lab-security-forward-proxy:6.6-24.04-security-20261111'
def run(*args):return subprocess.run(args,check=True,capture_output=True,text=True,timeout=30).stdout.strip()
def configure():
 proxy=json.loads(run('docker','image','inspect','lab-security-proxy:1.30.6-alpine-security-20261111'))[0]
 # The signed bundle locks the image ID. This label also prevents a same-name
 # local image built from an unapproved upstream base from entering runtime.
 labels=proxy.get('Config',{}).get('Labels') or {}
 if labels.get('com.jtec.security-appliance.component')!='reverse-proxy' or labels.get('com.jtec.security-appliance.base-digest')!='sha256:583b7f2fce1cdb8da5ad5c39ebd3c33b98b87d493190e548bdee1fa8c619c311':raise ValueError('Proxy image does not match the selected base digest.')
 images={name:run('docker','image','inspect',name,'--format','{{.Id}}') for name in ['lab-security-management:0.3.0','lab-security-proxy:1.30.6-alpine-security-20261111',FORWARD]}
 common={'restart':'no','read_only':True,'security_opt':['no-new-privileges:true'],'pull_policy':'never'}
 cfg=json.loads((ROOT/'config.json').read_text())
 config={'name':'security-appliance','services':{
  'management':{**common,'image':'lab-security-management:0.3.0','container_name':'security-management','networks':['management'],'cap_drop':['ALL'],'tmpfs':['/tmp'],'volumes':['/run/security-appliance:/run/security-appliance','/var/lib/security-appliance/management:/var/lib/security-appliance/management']},
  'proxy':{**common,'image':'lab-security-proxy:1.30.6-alpine-security-20261111','container_name':'security-proxy','networks':['edge','management'],'tmpfs':['/var/cache/nginx','/var/run','/tmp'],'ports':['80:80','443:443']+(['0.0.0.0:5696:5696'] if cfg.get('kmip_client_cidrs') else []),'volumes':['/etc/security-appliance/nginx.conf:/etc/nginx/nginx.conf:ro','/etc/security-appliance/tls:/certs:ro'],'depends_on':['management']}},
  'networks':{'management':{'external':True,'name':'security-management'},'edge':{'external':True,'name':'security-edge'},'forward-proxy':{'external':True,'name':'security-forward-proxy'}}}
 if (ROOT/'build-auth-bypass').exists():config['services']['management']['environment']=['SECURITY_BUILD_AUTH_BYPASS=1']
 import forward_proxy
 forward=forward_proxy.load()
 config['services']['forward-proxy']={**common,'image':FORWARD,'container_name':'security-forward-proxy','networks':['forward-proxy'],'cap_drop':['ALL'],'user':'13:13','tmpfs':['/tmp:uid=13,gid=13,mode=0700','/var/log/squid:uid=13,gid=13,mode=0750','/var/spool/squid:uid=13,gid=13,mode=0750'],'volumes':['/etc/security-appliance/squid.conf:/etc/squid/squid.conf:ro'],'mem_limit':'512m'}
 if forward['enabled']:config['services']['forward-proxy']['ports']=['0.0.0.0:3128:3128']
 if (ROOT/'service-credentials.json').exists():
  from prepare_services import PG,KMS
  for name in ['lab-security-keycloak:0.3.0',PG,KMS,'lab-security-kmip-client:0.2.0']:images[name]=run('docker','image','inspect',name,'--format','{{.Id}}')
  config['networks'].update({n:{'external':True,'name':'security-'+n} for n in ['identity','database','kmip']})
  config['services']['postgres']={**common,'image':PG,'container_name':'security-postgres','env_file':[str(ROOT/'postgres.env')],'networks':['database'],'tmpfs':['/tmp','/var/run/postgresql'],'volumes':['/var/lib/security-appliance/postgres:/var/lib/postgresql/data'],'healthcheck':{'test':['CMD-SHELL','pg_isready -U keycloak -d keycloak'],'interval':'5s','timeout':'3s','retries':20},'mem_limit':'1g'}
  # Keycloak keeps its private application and database paths while sharing the
  # edge bridge only for outbound OIDC discovery, token and JWKS requests.
  # No Keycloak ports are published on the host.
  keycloak_volumes=['/var/lib/security-appliance/keycloak:/opt/keycloak/data']
  keycloak_environment=[]
  enrolled_ca=ROOT/'tls/current/ca.pem'
  anchor_dir=ROOT/'trust/anchors';anchor_dir.mkdir(parents=True,exist_ok=True,mode=0o755)
  bootstrap_anchor=Path(__file__).resolve().with_name('bootstrap-trust-anchor.pem')
  if bootstrap_anchor.is_file():
   installed_anchor=anchor_dir/bootstrap_anchor.name
   temporary_anchor=installed_anchor.with_suffix('.new');temporary_anchor.write_bytes(bootstrap_anchor.read_bytes());temporary_anchor.chmod(0o444);temporary_anchor.replace(installed_anchor)
   bootstrap_anchor.unlink()
  trust_dir=ROOT/'keycloak-trust';trust_dir.mkdir(exist_ok=True,mode=0o755)
  trust_file=trust_dir/'ca.pem'
  trust_sources=([enrolled_ca] if enrolled_ca.is_file() else [])+sorted(p for p in anchor_dir.iterdir() if p.is_file() and p.suffix.lower() in {'.pem','.crt','.cer'})
  if trust_sources:
   bundle=b''.join(p.read_bytes().rstrip()+b'\n' for p in trust_sources)
   temporary=trust_file.with_suffix('.new');temporary.write_bytes(bundle);temporary.chmod(0o444);temporary.replace(trust_file)
   keycloak_volumes.append(str(trust_file)+':/opt/keycloak/conf/appliance-ca.pem:ro')
   keycloak_environment.append('KC_TRUSTSTORE_PATHS=/opt/keycloak/conf/appliance-ca.pem')
  else:trust_file.unlink(missing_ok=True)
  config['services']['keycloak']={**common,'image':'lab-security-keycloak:0.3.0','container_name':'security-keycloak','command':['start','--optimized'],'env_file':[str(ROOT/'keycloak.env')],'environment':keycloak_environment,'networks':['identity','database','edge'],'tmpfs':['/tmp'],'volumes':keycloak_volumes,'depends_on':{'postgres':{'condition':'service_healthy'}},'mem_limit':'2g'}
  kmip_volumes=['/etc/security-appliance/kmip/kms.toml:/qualification/kms.toml:ro','/etc/security-appliance/kmip/server.p12:/qualification/server.p12:ro','/etc/security-appliance/kmip/ca.pem:/qualification/ca.pem:ro','/var/lib/security-appliance/kmip:/data']
  config['services']['kmip']={**common,'image':KMS,'container_name':'security-kmip','working_dir':'/data','command':['-c','/qualification/kms.toml'],'networks':['kmip'],'tmpfs':['/tmp'],'volumes':kmip_volumes,'mem_limit':'1g','cpus':2}
  config['services']['proxy']['networks']+=['identity','kmip']
 (ROOT/'compose.json').write_text(json.dumps(config,indent=2))
 (ROOT/'image-lock.json').write_text(json.dumps(images,indent=2))
 run('docker','compose','-f',str(ROOT/'compose.json'),'config','--quiet')
 # Reconcile the HTTPS source policy with the applied configuration.
 run('python3',str(Path(__file__).with_name('render_proxy.py')))
 # A sealed appliance has no runtime containers on its first boot.  Treat a
 # missing proxy as stopped; only validate and reload an existing container
 # during Day-2 reconfiguration.
 proxy_state=subprocess.run(
  ['docker','inspect','-f','{{.State.Running}}','security-proxy'],
  capture_output=True,text=True,timeout=30,
 )
 if proxy_state.returncode==0 and proxy_state.stdout.strip()=='true':
  run('docker','exec','security-proxy','nginx','-t')
  run('docker','exec','security-proxy','nginx','-s','reload')
def verify():
 for name,identity in json.loads((ROOT/'image-lock.json').read_text()).items():
  if run('docker','image','inspect',name,'--format','{{.Id}}')!=identity:raise ValueError('Container image differs from the recorded build lock.')
if __name__=='__main__':
 import sys
 if '--verify' in sys.argv:verify()
 else:configure()
