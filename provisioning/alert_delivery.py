"""Opt-in, sanitized appliance alerts to approved external receivers."""

import hashlib
import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path('/etc/security-appliance')
CONFIG = ROOT / 'alert-delivery.json'
STATE = ROOT / 'alert-delivery-state.json'
SAFE_ALERTS = {
    'The appliance firewall is not active.',
    'DNS configuration or appliance-name resolution requires attention.',
    'Time synchronization or the selected NTP source requires attention.',
    'One or more appliance services require attention.',
    'Appliance data storage has less than 10 percent free space.',
    'The management HTTPS certificate requires attention.',
    'An appliance restart is required to complete installed updates.',
    'KMIP mutual-TLS readiness requires attention.',
    'A signed appliance update failed and was rolled back.',
    'This is a test alert from the appliance.',
}


def write(path, value):
    temp = path.with_suffix('.new')
    temp.write_text(json.dumps(value, sort_keys=True) + '\n')
    temp.chmod(0o600)
    temp.replace(path)


def load():
    try:return json.loads(CONFIG.read_text())
    except (OSError,ValueError):return {'enabled':False,'kind':'none','destination':''}


def state():
    try:return json.loads(STATE.read_text())
    except (OSError,ValueError):return {'lastAttemptAt':None,'lastResult':'not sent','lastFingerprint':None}


def public_config(config):
    result=dict(config)
    destination=result.get('destination','')
    if result.get('kind') in ('https','mattermost') and destination:
        parsed=urllib.parse.urlsplit(destination)
        path='/hooks/[secret]' if result.get('kind')=='mattermost' else '/[secret]'
        result['destination']=''
        result['destinationDisplay']=urllib.parse.urlunsplit((parsed.scheme,parsed.netloc,path,'',''))
        result['configured']=True
    else:
        result['destinationDisplay']=destination
        result['configured']=bool(destination)
    return result


def status():
    return {'config':public_config(load()),'delivery':state()}


def validate(config):
    if not isinstance(config,dict) or type(config.get('enabled')) is not bool:raise ValueError('Invalid alert delivery configuration.')
    enabled=config['enabled'];kind=config.get('kind','none');destination=config.get('destination','')
    if not enabled:return {'enabled':False,'kind':'none','destination':''}
    if not isinstance(destination,str) or len(destination)>512:raise ValueError('Invalid alert destination.')
    if kind=='syslog':
        match=re.fullmatch(r'([A-Za-z0-9][A-Za-z0-9.-]{0,252}):(\d{1,5})',destination)
        if not match or not 1<=int(match.group(2))<=65535:raise ValueError('Use a syslog host and UDP port.')
        host=match.group(1).lower()
        if host in ('localhost','0.0.0.0'):raise ValueError('A remote syslog host is required.')
        return {'enabled':True,'kind':'syslog','destination':host+':'+str(int(match.group(2)))}
    if kind in ('https','mattermost'):
        parsed=urllib.parse.urlsplit(destination)
        if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.port not in (None,443):
            raise ValueError('Use an HTTPS webhook without embedded credentials or a custom port.')
        if parsed.hostname.lower()=='localhost':raise ValueError('A remote webhook is required.')
        if kind=='mattermost' and (parsed.query or not re.fullmatch(r'/hooks/[A-Za-z0-9_-]{8,256}/?',parsed.path)):
            raise ValueError('Use a Mattermost incoming webhook URL.')
        try:
            address=ipaddress.ip_address(parsed.hostname)
            if address.is_loopback or address.is_link_local or address.is_unspecified:raise ValueError('A remote webhook is required.')
        except ValueError as exc:
            if str(exc)=='A remote webhook is required.':raise
        return {'enabled':True,'kind':kind,'destination':destination}
    raise ValueError('Choose syslog, HTTPS webhook or Mattermost delivery.')


def remote_addresses(host):
    addresses={ipaddress.ip_address(row[4][0]) for row in socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)}
    if not addresses or any(value.is_loopback or value.is_link_local or value.is_unspecified or value.is_multicast for value in addresses):
        raise ValueError('Alert destination resolves to an unsupported address.')
    return addresses


def apply(config):
    if isinstance(config,dict) and config.get('enabled') and config.get('kind') in ('https','mattermost') and not config.get('destination'):
        existing=load()
        if existing.get('enabled') and existing.get('kind')==config.get('kind') and existing.get('destination'):
            config={**config,'destination':existing['destination']}
    clean=validate(config)
    write(CONFIG,clean)
    write(STATE,{'lastAttemptAt':None,'lastResult':'not sent','lastFingerprint':None})
    return status()


def https_context():
    context=ssl.create_default_context()
    appliance_ca=ROOT/'tls/current/ca.pem'
    if appliance_ca.exists():context.load_verify_locations(cafile=str(appliance_ca))
    return context


def mattermost_payload(messages,now):
    observed=datetime.fromtimestamp(now,timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    title='**Lab Security Appliance test alert**' if messages==['This is a test alert from the appliance.'] else '**Lab Security Appliance health alert**'
    details='\n'.join('- '+message for message in messages) if messages else '- All monitored appliance health checks are clear.'
    return {'text':title+'\n\nObserved: '+observed+'\n'+details}


def deliver(alerts,force=False):
    config=load();current=state()
    if not config['enabled']:return current
    messages=sorted(set(alerts)&SAFE_ALERTS)
    digest=hashlib.sha256(json.dumps(messages).encode()).hexdigest()
    now=time.time()
    if not force and digest==current.get('lastFingerprint') and now-current.get('lastAttemptAt',0)<86400:return current
    payload={'appliance':'Lab Security Appliance','event':'health-alerts','at':now,'alerts':messages}
    outcome='delivered'
    try:
        if config['kind']=='syslog':
            host,port=config['destination'].rsplit(':',1)
            remote_addresses(host)
            message='<134>security-appliance '+json.dumps(payload,separators=(',',':'))
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                client.settimeout(5)
                client.sendto(message.encode(),(host,int(port)))
            outcome='sent via UDP; receiver acknowledgment unavailable'
        else:
            remote_addresses(urllib.parse.urlsplit(config['destination']).hostname)
            body=mattermost_payload(messages,now) if config['kind']=='mattermost' else payload
            request=urllib.request.Request(config['destination'],data=json.dumps(body,separators=(',',':')).encode(),
                                           headers={'Content-Type':'application/json','User-Agent':'SecurityAppliance/1'},method='POST')
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self,*args,**kwargs):raise ValueError('Webhook redirects are not followed.')
            opener=urllib.request.build_opener(NoRedirect(),urllib.request.HTTPSHandler(context=https_context()))
            with opener.open(request,timeout=8) as response:
                if not 200<=response.status<300:raise ValueError('Webhook rejected the alert.')
    except Exception:
        outcome='delivery failed'
    result={'lastAttemptAt':now,'lastResult':outcome,'lastFingerprint':digest if outcome!='delivery failed' else current.get('lastFingerprint')}
    write(STATE,result)
    return result
