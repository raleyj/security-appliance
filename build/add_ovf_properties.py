"""Add Security Appliance deployment fields to a sanitized OVF; never a live VM."""
import sys
from pathlib import Path
from xml.etree import ElementTree as ET
NS='http://schemas.dmtf.org/ovf/envelope/1';Q='{'+NS+'}'
VSSD='http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData'
RASD='http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData'
VMWARE='http://www.vmware.com/schema/ovf'
FIELDS=[
 ('hostname','Appliance hostname','Short DNS label','',False),
 ('domain','Domain name','DNS suffix; does not join Active Directory','',False),
 ('network_mode','IPv4 network mode','static (supported default) or dhcp (requires a permanent reservation and matching DNS)','static',False),
 ('ip','Static IPv4 address','Required only for static mode','',False),
 ('prefix','Static prefix length','1–30; required only for static mode','',False),
 ('gateway','Static gateway','Required only for static mode','',False),
 ('dns','DNS servers','Comma-separated IPv4 addresses; required for static mode','',False),
 ('ntp','NTP servers','One to five comma-separated approved servers','',False),
 ('admin_cidrs','Management source networks','Explicit comma-separated IPv4 CIDRs','',False),
 ('web_admin_username','Web administrator username','Local /admin/ administrator','admin',False),
 ('web_admin_password','Web administrator password','15–256 characters; unique deployment secret','',True),
 ('console_recovery_password','Console recovery password','Separate 16–256 character secret; no OS shell','',True),
 ('identity_admin_username','Keycloak administrator','Separate identity administrator','identity-admin',False),
 ('identity_admin_password','Keycloak administrator password','Separate 16–256 character secret','',True),
 ('sso_fqdn','SSO hostname','Stable OIDC issuer DNS name','',False),
 ('kmip_fqdn','KMIP hostname','Stable KMIP certificate DNS name','',False),
 ('kmip_client_cidrs','KMIP client networks','Blank keeps listener closed','',False)]
def apply(path):
 ET.register_namespace('ovf',NS)
 ET.register_namespace('vmw',VMWARE)
 ET.register_namespace('vssd',VSSD)
 ET.register_namespace('rasd',RASD)
 tree=ET.parse(path);vm=tree.getroot().find(Q+'VirtualSystem')
 if vm is None:raise ValueError('OVF must contain one VirtualSystem.')
 vm.set(Q+'id','Lab-Security-Appliance')
 vm.find(Q+'Name').text='Lab Security Appliance'
 vm.find(Q+'VirtualHardwareSection/'+Q+'System/{'+VSSD+'}VirtualSystemIdentifier').text='Lab Security Appliance'
 network=tree.getroot().find(Q+'NetworkSection/'+Q+'Network')
 if network is None:raise ValueError('OVF must contain one appliance network.')
 network.set(Q+'name','Appliance Network')
 network.find(Q+'Description').text='Select the appliance deployment port group.'
 for connection in vm.iter('{'+RASD+'}Connection'):connection.text='Appliance Network'
 references=tree.getroot().find(Q+'References')
 if references is None or len(references.findall(Q+'File'))!=3:raise ValueError('Expected two disks and one NVRAM file.')
 for index,entry in enumerate(references.findall(Q+'File'),1):
  original=path.parent/entry.get(Q+'href')
  replacement=path.parent/('Lab-Security-Appliance-disk'+str(index)+'.vmdk' if index<=2 else 'Lab-Security-Appliance.nvram')
  if original!=replacement:
   if replacement.exists():raise ValueError('Generalized disk filename already exists.')
   original.rename(replacement)
  entry.set(Q+'href',replacement.name)
 product=vm.find(Q+'ProductSection')
 if product is None:product=ET.SubElement(vm,Q+'ProductSection');ET.SubElement(product,Q+'Info').text='Security appliance deployment'
 # Remove source-image cloud-init command injection properties from the distributable contract.
 for p in list(product.findall(Q+'Property')):product.remove(p)
 for name,label,desc,default,password in FIELDS:
  attrs={Q+'key':'guestinfo.security.'+name,Q+'type':'string',Q+'userConfigurable':'true',Q+'value':default}
  if password:attrs[Q+'password']='true'
  p=ET.SubElement(product,Q+'Property',attrs);ET.SubElement(p,Q+'Label').text=label;ET.SubElement(p,Q+'Description').text=desc
 hardware=vm.find(Q+'VirtualHardwareSection')
 if hardware is None:raise ValueError('Missing virtual hardware section.')
 hardware.set(Q+'transport','com.vmware.guestInfo')
 tree.write(path,encoding='utf-8',xml_declaration=True)
if __name__=='__main__':apply(Path(sys.argv[1]))
