"""Fixed service lifecycle operations; no user-supplied commands or container names."""
import ipaddress,json,os,secrets,socket,ssl,subprocess,time,urllib.request,urllib.parse,fcntl
from pathlib import Path
ROOT=Path('/etc/security-appliance')
SERVICES={x:'security-'+x for x in ['management','proxy','forward-proxy','postgres','keycloak','kmip']}
def run(*args):return subprocess.run(args,check=True,capture_output=True,text=True,timeout=100).stdout.strip()
def write(path,value):
 tmp=path.with_suffix('.new');tmp.write_text(json.dumps(value));os.chmod(tmp,0o600);tmp.replace(path)
def inspect(service):return json.loads(run('docker','inspect',SERVICES[service],'--format','{{json .State}}'))
def address(service,network):
 value=json.loads(run('docker','network','inspect',network))[0]
 matches=[container.get('IPv4Address','').split('/')[0] for container in value.get('Containers',{}).values() if container.get('Name')==SERVICES[service]]
 if len(matches)!=1:raise ValueError('Service network membership is unavailable.')
 return str(ipaddress.IPv4Address(matches[0]))
def http(url,data=None,token=None,method=None):
 headers={}
 if token:headers['Authorization']='Bearer '+token
 if isinstance(data,dict):data=json.dumps(data).encode();headers['Content-Type']='application/json'
 req=urllib.request.Request(url,data=data,headers=headers,method=method)
 if isinstance(data,bytes) and 'Content-Type' not in headers:req.add_header('Content-Type','application/x-www-form-urlencoded')
 with urllib.request.urlopen(req,timeout=8) as r:
  raw=r.read(200000)
  return json.loads(raw) if raw else None
def kcbase():return 'http://'+address('keycloak','security-identity')+':8080/identity'
def token(username,password):return http(kcbase()+'/realms/master/protocol/openid-connect/token',urllib.parse.urlencode({'grant_type':'password','client_id':'admin-cli','username':username,'password':password}).encode())['access_token']
def initialize_identity():
 if (ROOT/'identity-initialized').exists():return
 s=json.loads((ROOT/'service-credentials.json').read_text());access=token('temporary-bootstrap',s['bootstrap']);base=kcbase()+'/admin/realms/master'
 users=http(base+'/users?username=identity-admin&exact=true',token=access)
 if not users:
  username=s.get('identity_username','identity-admin')
  http(base+'/users',{'username':username,'enabled':True,'firstName':'Appliance','lastName':'Administrator','email':'identity-admin@example.invalid','emailVerified':True,'credentials':[{'type':'password','value':s['identity'],'temporary':False}]},access)
  users=http(base+'/users?username='+urllib.parse.quote(username)+'&exact=true',token=access)
 role=http(base+'/roles/admin',token=access)
 req=urllib.request.Request(base+'/users/'+users[0]['id']+'/role-mappings/realm',data=json.dumps([role]).encode(),headers={'Authorization':'Bearer '+access,'Content-Type':'application/json'},method='POST')
 with urllib.request.urlopen(req,timeout=8):pass
 permanent=token(s.get('identity_username','identity-admin'),s['identity'])
 bootstrap=http(base+'/users?username=temporary-bootstrap&exact=true',token=permanent)
 for user in bootstrap:http(base+'/users/'+user['id'],token=permanent,method='DELETE')
 (ROOT/'identity-initialized').touch(mode=0o600)
 # Remove bootstrap secret from the runtime environment file; recreated container uses only permanent state.
 env=ROOT/'keycloak.env';env.write_text(''.join(x+'\n' for x in env.read_text().splitlines() if not x.startswith('KC_BOOTSTRAP_ADMIN_')))
def readiness(service):
 try:
  if service=='postgres':run('docker','exec','security-postgres','pg_isready','-U','keycloak','-d','keycloak')
  elif service=='keycloak':
   value=http('http://'+address(service,'security-identity')+':9000/health/ready')
   if value['status']!='UP':return False
  elif service=='kmip':
   ctx=ssl.create_default_context(cafile=str(ROOT/'kmip/ca.pem'));ctx.load_cert_chain(str(ROOT/'kmip/client.pem'),str(ROOT/'kmip/client.key'))
   with socket.create_connection((address(service,'security-kmip'),5696),timeout=3) as sock:
    with ctx.wrap_socket(sock,server_hostname='security-kmip'):pass
  elif service=='proxy':run('docker','exec','security-proxy','nginx','-t')
  elif service=='forward-proxy':run('docker','exec','security-forward-proxy','squid','-k','parse')
  elif service=='management':
   with urllib.request.urlopen('http://'+address(service,'security-management')+':8080/admin/',timeout=3) as r:
    if r.status!=200:return False
  return True
 except Exception:return False
def status():
 rows=[]
 for service in SERVICES:
  try:
   state=inspect(service);running=state['Running'];rows.append({'service':service,'state':state['Status'],'ready':running and readiness(service),'startedAt':state['StartedAt']})
  except Exception:rows.append({'service':service,'state':'unavailable','ready':False})
 job=json.loads((ROOT/'service-job.json').read_text()) if (ROOT/'service-job.json').exists() else None
 tested=json.loads((ROOT/'services-tested.json').read_text()) if (ROOT/'services-tested.json').exists() else {'services':[]}
 try:oidc=json.loads((ROOT/'oidc-qualification.json').read_text())
 except (OSError,ValueError):oidc={}
 oidc_passed=all(oidc.get(key) is True for key in ('login','pkceInvalidVerifierRejected','roleClaimEnforced','logoutRevokedRefreshToken','temporaryRealmRemoved'))
 return {'services':rows,'job':job,'testHistory':test_history(),'endpoints':json.loads((ROOT/'service-endpoints.json').read_text()) if (ROOT/'service-endpoints.json').exists() else {},'identityInitialized':(ROOT/'identity-initialized').exists(),'testedServices':tested.get('services',[]),'oidcQualificationPassed':oidc_passed,'oidcQualifiedAt':oidc.get('testedAt') if oidc_passed else None}
def test_history():
 try:items=json.loads((ROOT/'service-test-history.json').read_text())
 except (OSError,ValueError):return []
 return [row for row in items[-48:] if isinstance(row,dict) and row.get('service') in SERVICES and row.get('result') in ('passed','failed')] if isinstance(items,list) else []
def record_test(task):
 try:version=json.loads((ROOT/'release.json').read_text()).get('version','build-candidate')
 except (OSError,ValueError):version='build-candidate'
 reason='Functional check passed.' if task['state']=='success' else 'Functional check failed.'
 if task['state']!='success':
  detail=str(task.get('result',''))
  for prefix in ('Database query failed.','Keycloak private network is not ready','OIDC qualification failed.','OIDC qualification client failed:','Service health check failed.','Service did not become ready.','PostgreSQL must be ready first.'):
   if detail.startswith(prefix):reason=prefix.rstrip(':');break
 row={'service':task['service'],'testedAt':task['finishedAt'],'result':'passed' if task['state']=='success' else 'failed','version':str(version)[:64],'reason':reason}
 write(ROOT/'service-test-history.json',(test_history()+[row])[-48:])
def connection_logs(service):
 import re
 if service not in SERVICES:raise ValueError('Unsupported connection-log service.')
 lines=[]
 p=subprocess.run(['docker','logs','--tail','200',SERVICES[service]],capture_output=True,text=True,timeout=15)
 for line in (p.stdout+'\n'+p.stderr).splitlines():
  if not line.strip():continue
  if service=='proxy' and not ('HTTP/' in line or 'client:' in line or ' TCP ' in line):continue
  line=re.sub(r'([A-Z]+\s+[^ ?\"]+)\?[^ \"]*',r'\1?[query removed]',line)
  if any(word in line.lower() for word in ('authorization:','proxy-authorization:','password=','token=','secret=','cookie:')):line='[credential-related service event redacted]'
  lines.append(line[:980])
 return {'service':service,'lines':lines[-100:]}
def validate(service,operation):
 if service not in SERVICES or operation not in ['start','stop','restart','test']:raise ValueError('Unsupported service operation.')
 if service in ['management','proxy','forward-proxy'] and operation not in ['restart','test']:raise ValueError('Management and proxy services can only be restarted or tested.')
 if service=='postgres' and operation in ['stop','restart'] and inspect('keycloak')['Running']:raise ValueError('Stop Keycloak before stopping or restarting PostgreSQL.')
 if service=='keycloak' and operation in ['start','restart'] and not readiness('postgres'):raise ValueError('PostgreSQL must be ready first.')
def stage(service,operation):
 validate(service,operation)
 if (ROOT/'pending-network.json').exists():raise ValueError('Finish the pending network change first.')
 if (ROOT/'service-job.json').exists():
  old=json.loads((ROOT/'service-job.json').read_text())
  if old['state'] in ['queued','running'] and time.time()-old['at']<240:raise ValueError('A service operation is already in progress.')
 job={'id':secrets.token_hex(8),'service':service,'operation':operation,'state':'queued','at':time.time()};write(ROOT/'service-job.json',job)
 run('systemd-run','--unit=security-service-'+job['id'],'--on-active=3s','--timer-property=AccuracySec=1s','/usr/bin/python3','/opt/security-appliance/provisioning/service_control.py','--job',job['id'])
 return job
def test_service(service):
 if service=='postgres':
  if run('docker','exec','security-postgres','psql','-U','keycloak','-d','keycloak','-Atc','SELECT 1')!='1':raise ValueError('Database query failed.')
 elif service=='keycloak':
  initialize_identity()
  for attempt in range(30):
   try:
    if readiness('keycloak'):
     keycloak_address=address('keycloak','security-identity');break
   except Exception:pass
   time.sleep(2)
  else:raise ValueError('Keycloak private network is not ready for OIDC qualification.')
  keycloak='http://'+keycloak_address+':8080/identity'
  command=['docker','run','--rm','--network','security-identity','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--user','0:0','--env','KEYCLOAK_BASE='+keycloak,'-v',str(ROOT/'service-credentials.json')+':/qualification/credentials.json:ro','-v','/opt/security-appliance/provisioning/oidc_qualification.py:/qualification/oidc_qualification.py:ro','lab-security-management:0.3.0','python','/qualification/oidc_qualification.py']
  process=subprocess.run(command,capture_output=True,text=True,timeout=100)
  if process.returncode:
   detail=(process.stderr.strip().splitlines() or ['unspecified client failure'])[-1]
   raise ValueError('OIDC qualification client failed: '+detail[:300])
  raw=process.stdout.strip()
  result=json.loads(raw)
  if not all(result.get(key) is True for key in ('login','pkceInvalidVerifierRejected','roleClaimEnforced','logoutRevokedRefreshToken','temporaryRealmRemoved')):raise ValueError('OIDC qualification failed.')
  result['testedAt']=time.time();write(ROOT/'oidc-qualification.json',result)
 elif service=='kmip':run('docker','run','--rm','--network','security-kmip','-v','/etc/security-appliance/kmip:/qualification:ro','-v','/var/lib/security-appliance/kmip-test:/results','lab-security-kmip-client:0.2.0')
 elif not readiness(service):raise ValueError('Service health check failed.')
 return 'Functional check passed.'
def job(identifier):
 with open(ROOT/'transaction.lock','a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  path=ROOT/'service-job.json';task=json.loads(path.read_text())
  if task['id']!=identifier or task['state']!='queued':return
  try:
   service=task['service'];operation=task['operation'];validate(service,operation);task['state']='running';write(path,task)
   if operation=='test':
    task['result']=test_service(service)
    review_path=ROOT/'services-tested.json';tested=json.loads(review_path.read_text()) if review_path.exists() else {'services':[]}
    tested['services']=sorted(set(tested.get('services',[])+[service]));tested['updatedAt']=time.time();write(review_path,tested)
   else:
    if operation in ['start','restart']:
     import compose_runtime;compose_runtime.verify()
    run('docker',operation,SERVICES[service])
    if operation!='stop':
     for _ in range(35):
      if readiness(service):break
      time.sleep(2)
     else:raise ValueError('Service did not become ready.')
   task['state']='success'
  except Exception as error:
   task['state']='failed';task['result']=str(error)[:400] if isinstance(error,ValueError) else 'Service operation failed; inspect service health.'
  task['finishedAt']=time.time()
  if task.get('operation')=='test':
   try:record_test(task)
   except OSError:pass
  write(path,task)
def perform(data):
 if data['action']=='services-status':return status()
 if data['action']=='services-action':return stage(data.get('service'),data.get('operation'))
 raise ValueError('Unsupported service operation.')
if __name__=='__main__':
 import sys
 if '--job' in sys.argv:job(sys.argv[2])
 elif '--initialize' in sys.argv:
  for attempt in range(60):
   try:initialize_identity();print('Permanent identity administrator initialized; temporary bootstrap account removed.');break
   except Exception:
    if attempt==59:raise SystemExit('Identity initialization failed; no credentials printed.')
    time.sleep(3)
