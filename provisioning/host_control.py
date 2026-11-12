#!/usr/bin/python3
"""Restricted Unix socket network transactions. Never accepts a command string."""
import hashlib,ipaddress,json,os,re,secrets,shutil,socket,socketserver,subprocess,sys,threading,time,ssl,urllib.request
import fcntl
from contextlib import contextmanager
from email.utils import parsedate_to_datetime
from pathlib import Path
sys.path.insert(0,'/opt/security-appliance/app')
from configuration import validate_config,validate_timezone
ROOT=Path('/etc/security-appliance');PENDING=ROOT/'pending-network.json'
LOCK=threading.Lock()
@contextmanager
def transaction_lock():
 with LOCK,open(ROOT/'transaction.lock','a') as f:
  fcntl.flock(f,fcntl.LOCK_EX)
  try:yield
  finally:fcntl.flock(f,fcntl.LOCK_UN)
def run(*args):return subprocess.run(args,check=True,capture_output=True,text=True,timeout=45).stdout
def optional(*args):
 try:return run(*args).strip()
 except Exception:return ''
def public_probe(kind):
 try:
  cfg=json.loads((ROOT/'config.json').read_text())
  name=cfg['sso_fqdn'] if kind=='oidc' else cfg['hostname']+'.'+cfg['domain']
  path='/identity/realms/master/.well-known/openid-configuration' if kind=='oidc' else '/admin/'
  context=ssl.create_default_context(cafile=str(ROOT/'tls/current/ca.pem'))
  opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))
  with opener.open('https://'+name+path,timeout=6) as response:
   if response.status!=200:return False
   if kind=='oidc':return json.loads(response.read(20000)).get('issuer')=='https://'+name+'/identity/realms/master'
   return response.headers.get('Content-Type','').startswith('text/html')
 except (OSError,ValueError,KeyError,ssl.SSLError):return False
def write(path,value):
 tmp=path.with_suffix('.new');tmp.write_text(json.dumps(value));os.chmod(tmp,0o600);tmp.replace(path)
def reconcile_https_policy(old,new):
 if old.get('admin_cidrs',[])!=new.get('admin_cidrs',[]):
  run('python3','/opt/security-appliance/provisioning/render_proxy.py')
  run('docker','exec','security-proxy','nginx','-t')
  run('docker','exec','security-proxy','nginx','-s','reload')

def rollback(expected=None):
 if not PENDING.exists():return
 d=json.loads(PENDING.read_text())
 if expected and d.get('transactionId')!=expected:return
 for f in Path('/etc/netplan').glob('*.yaml'):f.unlink()
 for name,text in d['netplan'].items():(Path('/etc/netplan')/name).write_text(text)
 write(ROOT/'config.json',d['old'])
 run('netplan','generate');run('netplan','apply');run('python3','/opt/security-appliance/provisioning/firewall.py')
 reconcile_https_policy(d['candidate'],d['old'])
 if d['old'].get('kmip_client_cidrs',[])!=d['candidate'].get('kmip_client_cidrs',[]):
  run('python3','/opt/security-appliance/provisioning/compose_runtime.py')
  run('docker','compose','-f',str(ROOT/'compose.json'),'up','-d','--no-deps','--force-recreate','--pull','never','proxy')
 PENDING.unlink();run('logger','-t','security-network','network-transaction-rolled-back')
def commit_network(expected=None):
 if not PENDING.exists():return
 p=json.loads(PENDING.read_text())
 if expected and p.get('transactionId')!=expected:return
 if time.time()>p['expires']:rollback();return
 try:
  for f in Path('/etc/netplan').glob('*.yaml'):f.unlink()
  write(Path('/etc/netplan/60-security.yaml'),p['candidate_netplan'])
  run('netplan','generate');write(ROOT/'config.json',p['candidate'])
  run('netplan','apply');run('python3','/opt/security-appliance/provisioning/firewall.py')
  reconcile_https_policy(p['old'],p['candidate'])
  if p['old'].get('kmip_client_cidrs',[])!=p['candidate'].get('kmip_client_cidrs',[]):
   run('python3','/opt/security-appliance/provisioning/compose_runtime.py')
   run('docker','compose','-f',str(ROOT/'compose.json'),'up','-d','--no-deps','--force-recreate','--pull','never','proxy')
  p['applied']=True;write(PENDING,p)
 except Exception:rollback();raise
def perform(d):
 action=d.get('action')
 if action=='storage-report':
  import operations_insights
  return operations_insights.storage_report()
 if action=='diagnostics':
  import operations_insights,service_control
  return operations_insights.diagnostics(perform({'action':'appliance-status'}),service_control.readiness,public_probe)
 if action=='update-status':
  import update_bundle
  return update_bundle.status()
 if action=='update-install':
  import update_bundle
  name=d.get('name','')
  if not re.fullmatch(r'[0-9a-f]{32}\.sau',name):raise ValueError('Invalid update staging name.')
  staging=Path('/var/lib/security-appliance/management/update-staging')/name
  try:return update_bundle.install_bundle(staging)
  except Exception:
   try:
    import alert_delivery
    alert_delivery.deliver(['A signed appliance update failed and was rolled back.'],force=True)
   except Exception:pass
   raise
  finally:staging.unlink(missing_ok=True)
 if action=='update-restore':
  import update_bundle
  return update_bundle.restore_previous()
 if action=='timezone-status':return {'timezone':run('timedatectl','show','--property=Timezone','--value').strip() or 'Etc/UTC'}
 if action=='timezone-apply':
  zone=validate_timezone(d.get('timezone'));run('timedatectl','set-timezone',zone)
  run('logger','-t','security-time','appliance-timezone-updated')
  return {'timezone':zone,'notice':'Appliance timezone updated.'}
 if action=='appliance-status':
  firewall=run('ufw','status').splitlines()
  cfg=json.loads((ROOT/'config.json').read_text())
  route=json.loads(run('ip','-j','route','show','default'))
  default_route=route[0] if len(route)==1 else None
  interface=default_route.get('dev','') if default_route else ''
  addresses=[]
  if interface:
   try:
    for link in json.loads(run('ip','-j','address','show','dev',interface)):
     addresses += [row['local']+'/'+str(row['prefixlen']) for row in link.get('addr_info',[]) if row.get('family')=='inet' and row.get('scope')=='global']
   except Exception:pass
  dns={name:False for name in [cfg['hostname']+'.'+cfg['domain'],cfg['sso_fqdn'],cfg['kmip_fqdn']]}
  for name in dns:
   try:
    answers=socket.getaddrinfo(name,None,socket.AF_INET)
    dns[name]=cfg.get('ip') in {row[4][0] for row in answers} if cfg.get('ip') else bool(answers)
   except OSError:pass
  active_resolvers=[]
  resolver_text=optional('resolvectl','dns')
  for candidate in re.findall(r'(?<![0-9A-Fa-f:.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9A-Fa-f:.])',resolver_text):
   try:
    value=ipaddress.ip_address(candidate)
    if not value.is_loopback and candidate not in active_resolvers:active_resolvers.append(candidate)
   except ValueError:pass
  if not active_resolvers:
   try:
    for line in Path('/etc/resolv.conf').read_text().splitlines():
     fields=line.split()
     if len(fields)==2 and fields[0]=='nameserver' and fields[1] not in active_resolvers:active_resolvers.append(fields[1])
   except OSError:pass
  ntp_enabled=run('timedatectl','show','--property=NTP','--value').strip().lower()=='yes'
  ntp_synced=run('timedatectl','show','--property=NTPSynchronized','--value').strip().lower()=='yes'
  current_ntp_name=optional('timedatectl','show-timesync','--property=ServerName','--value')
  current_ntp_address=optional('timedatectl','show-timesync','--property=ServerAddress','--value')
  ntp_message=optional('timedatectl','show-timesync','--property=NTPMessage','--value')
  packet_count=re.search(r'PacketCount=(\d+)',ntp_message)
  ntp_response_received=bool(packet_count and int(packet_count.group(1))>0)
  ntp_source_approved=current_ntp_name in cfg['ntp'] or current_ntp_address in cfg['ntp']
  ntp_healthy=ntp_enabled and ntp_synced and ntp_source_approved and ntp_response_received
  timezone=optional('timedatectl','show','--property=Timezone','--value') or 'Etc/UTC'
  timesync_service=optional('systemctl','is-active','systemd-timesyncd') or 'unavailable'
  import certificates,forward_proxy,service_control
  try:
   service_rows=service_control.status()['services'];forward_enabled=forward_proxy.load().get('enabled',False)
   if not forward_enabled:
    service_rows=[{**row,'state':'disabled','ready':True} if row.get('service')=='forward-proxy' else row for row in service_rows]
  except Exception:service_rows=[]
  storage=shutil.disk_usage('/var/lib/security-appliance')
  try:
   certificate=certificates.status();match=re.search(r'^notAfter=(.+)$',certificate.get('details',''),re.M)
   expires=match.group(1).strip() if match else ''
   days=max(0,int((parsedate_to_datetime(expires).timestamp()-time.time())//86400)) if expires else None
  except Exception:certificate={'enrolled':False};expires='Unavailable';days=None
  firewall_active=bool(firewall and firewall[0].strip()=='Status: active')
  dns_healthy=bool(active_resolvers) and bool(dns) and all(dns.values())
  services_healthy=bool(service_rows) and all(row.get('ready') for row in service_rows)
  storage_healthy=storage.free/storage.total>=.10
  certificate_healthy=bool(certificate.get('enrolled')) and days is not None and days>=30
  alerts=[]
  if not firewall_active:alerts.append('The appliance firewall is not active.')
  if not dns_healthy:alerts.append('DNS configuration or appliance-name resolution requires attention.')
  if not ntp_healthy:alerts.append('Time synchronization or the selected NTP source requires attention.')
  if not services_healthy:alerts.append('One or more appliance services require attention.')
  if not any(row.get('service')=='kmip' and row.get('ready') for row in service_rows):alerts.append('KMIP mutual-TLS readiness requires attention.')
  if not storage_healthy:alerts.append('Appliance data storage has less than 10 percent free space.')
  if not certificate_healthy:alerts.append('The management HTTPS certificate requires attention.')
  if Path('/var/run/reboot-required').exists():alerts.append('An appliance restart is required to complete installed updates.')
  return {'identity':{'hostname':cfg['hostname'],'fqdn':cfg['hostname']+'.'+cfg['domain']},'network':{'interface':interface or 'Unavailable','addresses':addresses,'gateway':default_route.get('gateway','Unavailable') if default_route else 'Unavailable','source':cfg['network_mode'].upper()},'configuredDns':cfg.get('dns',[]),'activeResolvers':active_resolvers,'dns':dns,'dnsHealthy':dns_healthy,'configuredNtp':cfg.get('ntp',[]),'currentNtp':{'name':current_ntp_name,'address':current_ntp_address},'ntpSourceApproved':ntp_source_approved,'ntpResponseReceived':ntp_response_received,'ntpHealthy':ntp_healthy,'ntpEnabled':ntp_enabled,'ntpSynchronized':ntp_synced,'timesyncService':timesync_service,'timezone':timezone,'services':service_rows,'servicesHealthy':services_healthy,'storage':{'total':storage.total,'used':storage.used,'free':storage.free,'healthy':storage_healthy},'certificate':{'expires':expires,'daysRemaining':days,'enrolled':bool(certificate.get('enrolled'))},'firewallActive':firewall_active,'firewallSummary':firewall[:20],'restartRequired':Path('/var/run/reboot-required').exists(),'uptime':run('uptime','-p').strip(),'defaultRoute':default_route,'alerts':alerts}
 if action=='appliance-reboot':
  if PENDING.exists():raise ValueError('Finish the pending network change before restarting.')
  run('systemd-run','--unit=security-appliance-reboot','--on-active=3s','/usr/bin/systemctl','reboot')
  return {'queued':True,'notice':'Appliance restart queued.'}
 if action=='appliance-shutdown':
  if PENDING.exists():raise ValueError('Finish the pending network change before shutting down.')
  run('systemd-run','--unit=security-appliance-shutdown','--on-active=3s','/usr/bin/systemctl','poweroff')
  return {'queued':True,'notice':'Appliance shutdown queued.'}
 if action=='alert-delivery-status':
  import alert_delivery
  return alert_delivery.status()
 if action=='alert-delivery-apply':
  import alert_delivery
  return alert_delivery.apply(d.get('config'))
 if action=='alert-delivery-test':
  import alert_delivery
  return alert_delivery.deliver(['This is a test alert from the appliance.'],force=True)
 if action=='integration-readiness':
  import certificates,service_control
  cfg=json.loads((ROOT/'config.json').read_text());services=service_control.status();required=set(service_control.SERVICES);tested=set(services.get('testedServices',[]))
  result={'configDigest':hashlib.sha256(json.dumps(cfg,sort_keys=True).encode()).hexdigest(),'trustedManagementTls':certificates.status()['enrolled'],'servicesReviewed':required.issubset(tested) and all(row['ready'] for row in services['services']),'testedServices':sorted(tested)}
  target=Path('/var/lib/security-appliance/management/integration-ready.json');write(target,result);os.chown(target,10001,10001)
  return result
 if action in ('services-status','services-action'):
  import service_control
  return service_control.perform(d)
 if action=='connection-logs':
  import service_control
  return service_control.connection_logs(d.get('service'))
 if action in ('forward-proxy-status','forward-proxy-apply'):
  import forward_proxy
  return forward_proxy.perform(d)
 if action in ('certificate-status','certificate-csr','certificate-import','certificate-discard'):
  import certificates
  return certificates.perform(d)
 if action=='trust-inventory':
  import trust_inventory
  return trust_inventory.inventory()
 if action=='public-certificate-chain':
  import trust_inventory
  return trust_inventory.public_chain(d.get('kind'))
 if action in ('kmip-trust-public','kmip-sign-client'):
  import kmip_enrollment
  return kmip_enrollment.perform(d)
 if action=='status':return {'pending':PENDING.exists(),'confirmed':json.loads((ROOT/'network-confirmed.json').read_text()) if (ROOT/'network-confirmed.json').exists() else None}
 if action=='confirm':
  if not PENDING.exists():raise ValueError('No pending network transaction.')
  p=json.loads(PENDING.read_text())
  if not p.get('applied') or time.time()>p['expires'] or not secrets.compare_digest(d.get('token',''),p['token']):raise ValueError('Network not yet applied, or invalid/expired confirmation.')
  cfg=json.loads((ROOT/'config.json').read_text())
  run('hostnamectl','set-hostname',cfg['hostname'])
  ntp=Path('/etc/systemd/timesyncd.conf.d');ntp.mkdir(exist_ok=True);ntp.chmod(0o755)
  (ntp/'security.conf').unlink(missing_ok=True)
  ntp_file=ntp/'99-security.conf'
  ntp_file.write_text('[Time]\nNTP='+' '.join(cfg['ntp'])+'\nFallbackNTP='+' '.join(cfg['ntp'])+'\n')
  ntp_file.chmod(0o644)
  run('systemctl','restart','systemd-timesyncd')
  write(ROOT/'network-confirmed.json',{'digest':p['digest'],'at':time.time()});PENDING.unlink()
  run('logger','-t','security-network','network-transaction-confirmed');return {'confirmed':True}
 if action!='apply':raise ValueError('Unsupported host operation.')
 if PENDING.exists():raise ValueError('Confirm or wait for the pending transaction to roll back.')
 cfg=validate_config(d['config'])
 old=json.loads((ROOT/'config.json').read_text())
 # The source path must stay explicitly allowed. The backend passes the single trusted proxy header.
 source=ipaddress.IPv4Address(d['source'])
 if not any(source in ipaddress.IPv4Network(c) for c in cfg['admin_cidrs']):raise ValueError('The current administrator address must remain allowed.')
 route=json.loads(run('ip','-j','route','show','default'))
 if len(route)!=1:raise ValueError('A single management interface is required.')
 interface=route[0]['dev']
 if not interface.replace('_','').replace('-','').isalnum():raise ValueError('Unsupported interface name.')
 nic={'dhcp4':cfg['network_mode']=='dhcp','dhcp6':False,'accept-ra':False}
 if cfg['dns']:nic['nameservers']={'addresses':cfg['dns'],'search':[cfg['domain']]}
 if cfg['network_mode']=='dhcp':nic['dhcp4-overrides']={'use-dns':not bool(cfg['dns']),'use-ntp':False}
 if cfg['network_mode']=='static':nic.update(addresses=[f"{cfg['ip']}/{cfg['prefix']}"],routes=[{'to':'default','via':cfg['gateway']}])
 token=secrets.token_urlsafe(32);digest=hashlib.sha256(json.dumps(cfg,sort_keys=True).encode()).hexdigest()
 transaction_id=secrets.token_hex(8)
 pending={'transactionId':transaction_id,'old':old,'netplan':{f.name:f.read_text() for f in Path('/etc/netplan').glob('*.yaml')},'expires':time.time()+120,'token':token,'digest':digest,'candidate':cfg,'candidate_netplan':{'network':{'version':2,'renderer':'networkd','ethernets':{interface:nic}}},'applied':False}
 write(PENDING,pending)
 try:
  # Independent timer survives a web process failure; boot also restores pending transactions.
  run('systemd-run','--unit=security-network-rollback-'+transaction_id,'--on-active=120s','--timer-property=AccuracySec=1s','/usr/bin/python3','/opt/security-appliance/provisioning/host_control.py','--rollback',transaction_id)
  run('systemd-run','--unit=security-network-apply-'+transaction_id,'--on-active=3s','--timer-property=AccuracySec=1s','/usr/bin/python3','/opt/security-appliance/provisioning/host_control.py','--commit',transaction_id)
  # Hostname and NTP apply at confirmation, after the operator reconnects.
  return {'token':token,'expires':pending['expires'],'address':cfg['ip'] if cfg['network_mode']=='static' else 'current DHCP address','pending':True}
 except Exception:
  rollback();raise
class Handler(socketserver.StreamRequestHandler):
 def handle(self):
  self.connection.settimeout(10)
  try:
   raw=self.rfile.readline(32769)
   if len(raw)>32768:raise ValueError('Oversized request.')
   data=json.loads(raw)
   if data.get('action') in ('services-status','connection-logs','appliance-status','forward-proxy-status','timezone-status','update-status','trust-inventory','public-certificate-chain','alert-delivery-status','storage-report','diagnostics'):result=perform(data)
   else:
    with transaction_lock():result=perform(data)
   response={'ok':True,'result':result}
  except Exception:response={'ok':False,'error':'Host operation rejected or failed; inspect appliance status.'}
  self.wfile.write((json.dumps(response)+'\n').encode())
if __name__=='__main__':
 if '--rollback' in sys.argv:
  with transaction_lock():rollback(sys.argv[2] if len(sys.argv)>2 else None)
 elif '--commit' in sys.argv:
  with transaction_lock():commit_network(sys.argv[2] if len(sys.argv)>2 else None)
 else:
  with transaction_lock():
   rollback()
   import certificates
   certificates.recover()
  p=Path('/run/security-appliance');p.mkdir(exist_ok=True,mode=0o750);os.chown(p,0,10001);os.chmod(p,0o750)
  sock=p/'control.sock';sock.unlink(missing_ok=True)
  def alert_worker():
   import alert_delivery
   while True:
    try:alert_delivery.deliver(perform({'action':'appliance-status'}).get('alerts',[]))
    except Exception:pass
    time.sleep(300)
  threading.Thread(target=alert_worker,daemon=True,name='security-alert-delivery').start()
  with socketserver.UnixStreamServer(str(sock),Handler) as s:
   os.chown(sock,0,10001);os.chmod(sock,0o660);s.serve_forever()
