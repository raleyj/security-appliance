"""Provision isolated lab service state once; never replace existing databases or keys."""
import json,os,secrets,subprocess
from pathlib import Path
ROOT=Path('/etc/security-appliance');DATA=Path('/var/lib/security-appliance')
KC='lab-security-keycloak:0.3.0'
PG='lab-security-postgres:17'
KMS='lab-security-kmip:5.25.0'
def run(*args):return subprocess.run(args,check=True,capture_output=True,text=True,timeout=600).stdout.strip()
def write(path,value):path.write_text(value);os.chmod(path,0o600)
def prepare():
 os.umask(0o077)
 for image in (KC,PG,KMS,'lab-security-kmip-client:0.2.0','lab-security-forward-proxy:6.6-24.04-security-20261111'):run('docker','image','inspect',image)
 credentials=ROOT/'service-credentials.json'
 if not credentials.exists():
  if (DATA/'postgres/PG_VERSION').exists():raise ValueError('Existing database without its credential state.')
  supplied=json.loads((ROOT/'deployment-secrets.json').read_text()) if (ROOT/'deployment-secrets.json').exists() else {}
  write(credentials,json.dumps({'database':secrets.token_urlsafe(32),'bootstrap':secrets.token_urlsafe(32),'identity':supplied.get('identity_password',secrets.token_urlsafe(32)),'identity_username':supplied.get('identity_username','identity-admin')}))
 s=json.loads(credentials.read_text())
 for name,uid in [('postgres',999),('keycloak',1000),('kmip',0),('kmip-test',0)]:
  p=DATA/name;p.mkdir(exist_ok=True,mode=0o700);os.chown(p,uid,uid)
 for net in ['security-identity','security-database','security-kmip']:
  if subprocess.run(['docker','network','inspect',net],capture_output=True).returncode:run('docker','network','create','--internal',net)
 if subprocess.run(['docker','network','inspect','security-forward-proxy'],capture_output=True).returncode:run('docker','network','create','security-forward-proxy')
 import forward_proxy;forward_proxy.initialize()
 write(ROOT/'postgres.env','POSTGRES_DB=keycloak\nPOSTGRES_USER=keycloak\nPOSTGRES_PASSWORD='+s['database']+'\n')
 cfg=json.loads((ROOT/'config.json').read_text())
 endpoint='https://'+cfg['sso_fqdn']+'/identity'
 env={'KC_DB':'postgres','KC_DB_URL':'jdbc:postgresql://security-postgres:5432/keycloak','KC_DB_USERNAME':'keycloak','KC_DB_PASSWORD':s['database'],'KC_HTTP_ENABLED':'true','KC_HTTP_RELATIVE_PATH':'/identity','KC_HOSTNAME':endpoint,'KC_PROXY_HEADERS':'xforwarded','KC_HTTP_MANAGEMENT_RELATIVE_PATH':'/','KC_HEALTH_ENABLED':'true'}
 if not (ROOT/'identity-initialized').exists():env.update(KC_BOOTSTRAP_ADMIN_USERNAME='temporary-bootstrap',KC_BOOTSTRAP_ADMIN_PASSWORD=s['bootstrap'])
 write(ROOT/'keycloak.env',''.join(k+'='+v+'\n' for k,v in env.items()))
 write(ROOT/'service-endpoints.json',json.dumps({'identity':endpoint,'identityAdmin':endpoint+'/admin/master/console/','identityUsername':s.get('identity_username','identity-admin'),'profile':'configured service identity; temporary certificate; no production relying parties'}))
 km=ROOT/'kmip';km.mkdir(exist_ok=True,mode=0o700)
 if not (km/'kms.toml').exists():
  if any((DATA/'kmip').iterdir()):raise ValueError('Existing KMIP data without its TLS configuration.')
  from kmip_trust import initialize
  initialize(km,cfg['kmip_fqdn'])
 print('Lab service images and persistent state prepared; secrets withheld.')
if __name__=='__main__':prepare()
