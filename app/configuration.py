"""Deployment contract validation. No commands or network mutations."""
import ipaddress
import re

TIMEZONES=(
    'Etc/UTC','America/New_York','America/Chicago','America/Denver',
    'America/Phoenix','America/Los_Angeles','America/Anchorage',
    'Pacific/Honolulu','Europe/London','Europe/Berlin','Asia/Tokyo',
    'Australia/Sydney',
)

def validate_timezone(value):
    if value not in TIMEZONES: raise ValueError('Choose a supported appliance timezone.')
    return value

def dns_name(value):
    if not isinstance(value,str) or len(value)>253 or not value or any(not re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?',p) for p in value.split('.')):
        raise ValueError('Enter a valid DNS name.')
    return value.lower()

def validate_config(data):
    allowed={'hostname','domain','network_mode','ip','prefix','gateway','dns','ntp','admin_cidrs','kmip_client_cidrs','sso_fqdn','kmip_fqdn'}
    if set(data)-allowed: raise ValueError('Unknown configuration field.')
    out={k:data.get(k,'') for k in allowed}
    if 'kmip_client_cidrs' not in data:out['kmip_client_cidrs']=[]
    out['hostname']=dns_name(out['hostname'])
    if '.' in out['hostname']: raise ValueError('Hostname must be one label.')
    out['domain']=dns_name(out['domain']); dns_name(out['hostname']+'.'+out['domain'])
    if out['network_mode'] not in ('static','dhcp'): raise ValueError('Choose static IPv4 or reserved DHCP.')
    for key in ['dns','ntp','admin_cidrs','kmip_client_cidrs']:
        if not isinstance(out[key],list) or not all(isinstance(x,str) for x in out[key]): raise ValueError(key+' must be a list.')
    if len(out['dns'])>3: raise ValueError('At most three DNS servers.')
    out['dns']=[str(ipaddress.IPv4Address(x)) for x in out['dns']]
    if not 1<=len(out['ntp'])<=5: raise ValueError('One to five NTP servers are required.')
    out['ntp']=[dns_name(x) for x in out['ntp']]
    if not 1<=len(out['admin_cidrs'])<=16: raise ValueError('An administrator source network is required.')
    out['admin_cidrs']=[str(ipaddress.IPv4Network(x,strict=False)) for x in out['admin_cidrs']]
    if '0.0.0.0/0' in out['admin_cidrs']: raise ValueError('Unrestricted administrator access is not allowed.')
    if len(out['kmip_client_cidrs'])>16: raise ValueError('At most sixteen KMIP client networks are allowed.')
    out['kmip_client_cidrs']=[str(ipaddress.IPv4Network(x,strict=True)) for x in out['kmip_client_cidrs']]
    if '0.0.0.0/0' in out['kmip_client_cidrs']: raise ValueError('Unrestricted KMIP client access is not allowed.')
    for k,default in [('sso_fqdn','sso.'),('kmip_fqdn','kmip.')]:out[k]=dns_name(out[k] or default+out['domain'])
    if out['network_mode']=='static':
        prefix=int(out['prefix'])
        if not 1<=prefix<=30: raise ValueError('Prefix must be 1–30.')
        ip=ipaddress.IPv4Address(out['ip']); net=ipaddress.IPv4Network(f'{ip}/{prefix}',strict=False); gw=ipaddress.IPv4Address(out['gateway'])
        if ip in (net.network_address,net.broadcast_address) or ip.is_multicast or ip.is_unspecified or ip.is_loopback or gw not in net or gw in (ip,net.network_address,net.broadcast_address): raise ValueError('Invalid static address or gateway.')
        if not out['dns']:raise ValueError('Static networking requires DNS.')
        out.update(ip=str(ip),prefix=prefix,gateway=str(gw))
    elif any(out[k] not in ('',None) for k in ['ip','prefix','gateway']): raise ValueError('Clear static fields in reserved DHCP mode.')
    return out
