#!/usr/bin/python3
"""Reconcile only the Security Appliance firewall on its fresh guest."""
import json,subprocess,sys,ipaddress
from pathlib import Path
def run(*a,check=True):return subprocess.run(a,check=check,capture_output=True,text=True,timeout=30)
config=Path('/etc/security-appliance/config.json')
if not config.exists():
 run('ufw','--force','reset');run('ufw','default','deny','incoming');run('ufw','default','deny','routed');run('ufw','default','deny','outgoing');run('ufw','--force','enable')
 raise SystemExit(0)
cfg=json.loads(config.read_text())
cidrs=[str(ipaddress.IPv4Network(x)) for x in cfg['admin_cidrs']]
kmip_cidrs=[str(ipaddress.IPv4Network(x,strict=True)) for x in cfg.get('kmip_client_cidrs',[])]
if not cidrs or '0.0.0.0/0' in cidrs:raise SystemExit('An explicit management allowlist is required.')
if '0.0.0.0/0' in kmip_cidrs:raise SystemExit('Unrestricted KMIP access is not allowed.')
interfaces=[p.name for p in Path('/sys/class/net').iterdir() if (p/'device').exists()]
if len(interfaces)!=1:raise SystemExit('Expected exactly one physical management NIC.')
interface=interfaces[0]
forward={'enabled':False,'client_cidrs':[]}
forward_path=Path('/etc/security-appliance/forward-proxy.json')
if forward_path.exists():
 forward=json.loads(forward_path.read_text())
 forward['client_cidrs']=[str(ipaddress.IPv4Network(x,strict=True)) for x in forward.get('client_cidrs',[])]
 if forward.get('enabled') and (not forward['client_cidrs'] or '0.0.0.0/0' in forward['client_cidrs']):raise SystemExit('An explicit forward proxy client allowlist is required.')
run('ufw','--force','reset');run('ufw','default','deny','incoming');run('ufw','default','deny','routed');run('ufw','default','deny','outgoing')
run('ufw','allow','out','53');run('ufw','allow','out','123/udp');run('ufw','allow','out','443/tcp')
# Permit only the host helper's health/admin calls to dedicated private bridges.
for network,ports in [('security-management',[8080]),('security-identity',[8080,9000]),('security-kmip',[5696])]:
 result=run('docker','network','inspect',network,check=False)
 if result.returncode==0:
  net=json.loads(result.stdout)[0];bridge=net.get('Options',{}).get('com.docker.network.bridge.name') or 'br-'+net['Id'][:12]
  for port in ports:run('ufw','allow','out','on',bridge,'to','any','port',str(port),'proto','tcp')
# HTTP is used only by Ubuntu package mirrors during the candidate build.
if '--build' in sys.argv:run('ufw','allow','out','80/tcp')
run('ufw','allow','out','67/udp');run('ufw','allow','in','on',interface,'proto','udp','from','any','port','67','to','any','port','68')
for cidr in cidrs:
 for port in ('80','443'):run('ufw','allow','from',cidr,'to','any','port',port,'proto','tcp')
for cidr in kmip_cidrs:run('ufw','allow','from',cidr,'to','any','port','5696','proto','tcp')
if forward.get('enabled'):
 for cidr in forward['client_cidrs']:run('ufw','allow','from',cidr,'to','any','port','3128','proto','tcp')
run('ufw','--force','enable')
# Construct a replacement chain before switching ingress to avoid a permissive rebuild window.
for tool in ['iptables','ip6tables']:
 run(tool,'-w','-N','DOCKER-USER',check=False)
 chain='SECURITY-'+str(__import__('os').getpid())
 run(tool,'-w','-N',chain)
 run(tool,'-w','-A',chain,'-m','conntrack','--ctstate','RELATED,ESTABLISHED','-j','RETURN')
 if tool=='iptables':
  for cidr in cidrs:
   for port in ('80','443'):run(tool,'-w','-A',chain,'-i',interface,'-s',cidr,'-p','tcp','-m','conntrack','--ctorigdstport',port,'-j','ACCEPT')
  for cidr in kmip_cidrs:run(tool,'-w','-A',chain,'-i',interface,'-s',cidr,'-p','tcp','-m','conntrack','--ctorigdstport','5696','-j','ACCEPT')
  if forward.get('enabled'):
   for cidr in forward['client_cidrs']:run(tool,'-w','-A',chain,'-i',interface,'-s',cidr,'-p','tcp','-m','conntrack','--ctorigdstport','3128','-j','ACCEPT')
 run(tool,'-w','-A',chain,'-i',interface,'-j','DROP')
 if tool=='iptables':
  result=run('docker','network','inspect','security-forward-proxy',check=False)
  if result.returncode==0:
   net=json.loads(result.stdout)[0];forward_bridge=net.get('Options',{}).get('com.docker.network.bridge.name') or 'br-'+net['Id'][:12]
   for destination in ('0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','192.0.2.0/12','192.168.0.0/16','224.0.0.0/4','240.0.0.0/4'):
    run(tool,'-w','-A',chain,'-i',forward_bridge,'-o',interface,'-d',destination,'-j','DROP')
   for port in ('80','443'):run(tool,'-w','-A',chain,'-i',forward_bridge,'-o',interface,'-p','tcp','--dport',port,'-j','RETURN')
 for proto,port in [('udp','53'),('tcp','53'),('udp','123'),('tcp','443')]:
  run(tool,'-w','-A',chain,'-i','br+','-o',interface,'-p',proto,'--dport',port,'-j','RETURN')
 run(tool,'-w','-A',chain,'-i','br+','-o',interface,'-j','DROP')
 run(tool,'-w','-A',chain,'-j','RETURN')
 run(tool,'-w','-I','DOCKER-USER','1','-j',chain)
 if run(tool,'-w','-C','FORWARD','-j','DOCKER-USER',check=False).returncode:run(tool,'-w','-I','FORWARD','1','-j','DOCKER-USER')
 # Delete only obsolete chains owned by this appliance after the new chain is active.
 for line in run(tool,'-w','-S','DOCKER-USER').stdout.splitlines():
  parts=line.split()
  if len(parts)==4 and parts[:3]==['-A','DOCKER-USER','-j'] and parts[3].startswith('SECURITY-') and parts[3]!=chain:
   run(tool,'-w','-D','DOCKER-USER','-j',parts[3]);run(tool,'-w','-F',parts[3]);run(tool,'-w','-X',parts[3])
print('Host and Docker ingress policy installed.')
