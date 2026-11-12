"""Parse the deployment property contract without logging raw OVF environment."""
import json,sys,hashlib,secrets
from xml.etree import ElementTree as ET
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from configuration import validate_config
def parse(xml):
 if len(xml)>131072 or '<!DOCTYPE' in xml.upper() or '<!ENTITY' in xml.upper():raise ValueError('Invalid OVF environment.')
 values={}
 for p in ET.fromstring(xml).iter():
  if p.tag.rsplit('}',1)[-1]!='Property':continue
  attrs={k.rsplit('}',1)[-1]:v for k,v in p.attrib.items()}
  key=attrs.get('key','')
  if key.startswith('guestinfo.security.'):
   key=key.removeprefix('guestinfo.security.')
   if key in values:raise ValueError('Duplicate deployment property.')
   values[key]=attrs.get('value','')
 cfg={k:values.get(k,'') for k in ['hostname','domain','network_mode','ip','prefix','gateway','dns','ntp','admin_cidrs','kmip_client_cidrs','sso_fqdn','kmip_fqdn']}
 for k in ['dns','ntp','admin_cidrs','kmip_client_cidrs']:cfg[k]=[x.strip() for x in cfg[k].split(',') if x.strip()]
 cfg=validate_config(cfg)
 web_password=values.get('web_admin_password','')
 recovery_password=values.get('console_recovery_password','')
 identity_password=values.get('identity_admin_password','')
 passwords=[web_password,recovery_password,identity_password]
 invalid_control=lambda p:any(ord(c)<32 or ord(c)==127 for c in p)
 if not 15<=len(web_password)<=256 or invalid_control(web_password):raise ValueError('Provide a 15–256 character web administrator password without control characters.')
 if any(not 16<=len(p)<=256 or invalid_control(p) for p in [recovery_password,identity_password]):raise ValueError('Provide separate 16–256 character console recovery and Keycloak administrator passwords without control characters.')
 if len(set(passwords))!=3:raise ValueError('Provide three distinct deployment passwords.')
 import re
 for k in ['web_admin_username','identity_admin_username']:
  if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',values.get(k,'')):raise ValueError('Invalid administrator username.')
 return cfg,values
