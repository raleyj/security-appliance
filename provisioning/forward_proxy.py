#!/usr/bin/python3
"""Validate and render the explicit outbound proxy policy."""
import ipaddress,json,os,re,subprocess
from pathlib import Path

ROOT=Path('/etc/security-appliance')
STATE=ROOT/'forward-proxy.json'
CONF=ROOT/'squid.conf'
IMAGE='lab-security-forward-proxy:6.6-24.04-security-20261111'
BLOCKED=['0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','192.0.2.0/12','192.168.0.0/16','224.0.0.0/4','240.0.0.0/4']

def run(*args):return subprocess.run(args,check=True,capture_output=True,text=True,timeout=90).stdout.strip()
def write(path,value,mode=0o600):
 tmp=path.with_suffix(path.suffix+'.new');tmp.write_text(value);os.chmod(tmp,mode);tmp.replace(path)
def validate(value):
 if not isinstance(value,dict):raise ValueError('Forward proxy settings must be an object.')
 enabled=value.get('enabled',False)
 if not isinstance(enabled,bool):raise ValueError('Forward proxy enabled must be true or false.')
 cidrs=value.get('client_cidrs',[])
 if not isinstance(cidrs,list) or len(cidrs)>16:raise ValueError('Provide no more than 16 client networks.')
 clean=[]
 for item in cidrs:
  try:network=ipaddress.IPv4Network(item,strict=True)
  except (TypeError,ValueError):raise ValueError('Client networks must be canonical IPv4 CIDRs.')
  if network.prefixlen==0:raise ValueError('A global client network is not permitted.')
  clean.append(str(network))
 domains=value.get('allowed_domains',[])
 if not isinstance(domains,list) or len(domains)>64:raise ValueError('Provide no more than 64 allowed domain suffixes.')
 names=[]
 for item in domains:
  if not isinstance(item,str):raise ValueError('Allowed domains must be DNS names.')
  name=item.strip().lower().lstrip('.')
  if len(name)>253 or not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',name):raise ValueError('Allowed domains must be valid DNS suffixes.')
  names.append(name)
 if enabled and not clean:raise ValueError('At least one explicit client network is required before enabling the forward proxy.')
 return {'enabled':enabled,'client_cidrs':sorted(set(clean)),'allowed_domains':sorted(set(names))}
def load():
 try:return validate(json.loads(STATE.read_text()))
 except FileNotFoundError:return {'enabled':False,'client_cidrs':[],'allowed_domains':[]}
def render(value):
 value=validate(value)
 lines=['http_port 0.0.0.0:3128','visible_hostname security-forward-proxy','pid_filename /tmp/squid.pid','coredump_dir /tmp','shutdown_lifetime 2 seconds','pinger_enable off','cache deny all','access_log stdio:/dev/stdout squid','cache_log stdio:/dev/stderr','acl SSL_ports port 443','acl Safe_ports port 80 443','acl CONNECT method CONNECT','acl blocked_destination dst '+' '.join(BLOCKED),'http_access deny !Safe_ports','http_access deny CONNECT !SSL_ports','http_access deny blocked_destination']
 if value['client_cidrs']:lines.append('acl allowed_clients src '+' '.join(value['client_cidrs']))
 if value['allowed_domains']:
  lines+=['acl allowed_domains dstdomain '+' '.join('.'+x for x in value['allowed_domains']),'http_access deny !allowed_domains']
 if value['enabled']:lines.append('http_access allow allowed_clients')
 lines+=['http_access deny all','forwarded_for delete','request_header_access X-Forwarded-For deny all']
 return '\n'.join(lines)+'\n'
def initialize():
 ROOT.mkdir(exist_ok=True,mode=0o700)
 value=load();write(STATE,json.dumps(value,indent=2)+'\n');write(CONF,render(value),0o644)
 return value
def apply(value):
 value=validate(value);candidate=ROOT/'squid.conf.candidate';write(candidate,render(value),0o644)
 try:run('docker','run','--rm','--network','none','--user','13:13','--read-only','--tmpfs','/tmp:uid=13,gid=13,mode=0700','-v',str(candidate)+':/etc/squid/squid.conf:ro',IMAGE,'-k','parse')
 finally:candidate.unlink(missing_ok=True)
 write(STATE,json.dumps(value,indent=2)+'\n');write(CONF,render(value),0o644)
 import compose_runtime;compose_runtime.configure()
 run('python3','/opt/security-appliance/provisioning/firewall.py')
 run('docker','compose','-f',str(ROOT/'compose.json'),'up','-d','--no-deps','--force-recreate','--pull','never','forward-proxy')
 return {**value,'port':3128 if value['enabled'] else None,'notice':'Forward proxy policy applied.'}
def perform(data):
 if data.get('action')=='forward-proxy-status':return {**load(),'port':3128 if load()['enabled'] else None}
 if data.get('action')=='forward-proxy-apply':return apply(data.get('config'))
 raise ValueError('Unsupported forward proxy operation.')
if __name__=='__main__':initialize()
