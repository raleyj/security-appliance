import sys,unittest,tempfile,importlib.util
from pathlib import Path
from xml.etree import ElementTree as ET
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'provisioning'))
from ovf_input import parse
spec=importlib.util.spec_from_file_location('properties',root/'build/add_ovf_properties.py');properties=importlib.util.module_from_spec(spec);spec.loader.exec_module(properties)
class OvfTests(unittest.TestCase):
 def values(self):return dict(hostname='security',domain='example.test',network_mode='dhcp',ntp='ntp.example.test',admin_cidrs='192.0.2.10/32',web_admin_username='web-admin',identity_admin_username='id-admin',web_admin_password='First-Test-Password-012345',console_recovery_password='Second-Test-Password-01234',identity_admin_password='Third-Test-Password-012345')
 def xml(self,d):
  r=ET.Element('Environment');s=ET.SubElement(r,'PropertySection')
  for k,v in d.items():ET.SubElement(s,'Property',key='guestinfo.security.'+k,value=v)
  return ET.tostring(r,encoding='unicode')
 def test_masked_blank_passwords(self):
  q=properties.Q;r=ET.Element(q+'Envelope');references=ET.SubElement(r,q+'References');work=Path(tempfile.mkdtemp())
  for index,name in enumerate(['source-os.vmdk','source-data.vmdk','source.nvram'],1):
   ET.SubElement(references,q+'File',{q+'id':f'file{index}',q+'href':name});(work/name).write_bytes(b'test')
  networks=ET.SubElement(r,q+'NetworkSection');network=ET.SubElement(networks,q+'Network',{q+'name':'source'});ET.SubElement(network,q+'Description').text='source'
  vm=ET.SubElement(r,q+'VirtualSystem');ET.SubElement(vm,q+'Name').text='source';hardware=ET.SubElement(vm,q+'VirtualHardwareSection');system=ET.SubElement(hardware,q+'System');ET.SubElement(system,'{'+properties.VSSD+'}VirtualSystemIdentifier').text='source';p=work/'a.ovf';ET.ElementTree(r).write(p)
  properties.apply(p);fields=ET.parse(p).findall('.//'+q+'Property');secret=[x for x in fields if x.get(q+'password')=='true'];self.assertEqual(len(secret),3);self.assertTrue(all(x.get(q+'value')=='' for x in secret));network=next(x for x in fields if x.get(q+'key')=='guestinfo.security.network_mode');self.assertEqual(network.get(q+'value'),'static')
 def test_valid_deployment(self):self.assertEqual(parse(self.xml(self.values()))[0]['hostname'],'security')
 def test_default_web_administrator_and_fifteen_character_password(self):
  self.assertEqual(next(row[3] for row in properties.FIELDS if row[0]=='web_admin_username'),'admin')
  values={**self.values(),'web_admin_username':'admin','web_admin_password':'Aa1!23456789012'}
  self.assertEqual(len(values['web_admin_password']),15);self.assertEqual(parse(self.xml(values))[1]['web_admin_username'],'admin')
  with self.assertRaises(ValueError):parse(self.xml({**values,'web_admin_password':'Aa1!2345678901'}))
 def test_missing_and_shared_secrets(self):
  for patch in [{'web_admin_password':''},{'identity_admin_password':'First-Test-Password-012345'}]:
   with self.assertRaises(ValueError):parse(self.xml({**self.values(),**patch}))
 def test_xml_entities_rejected(self):
  with self.assertRaises(ValueError):parse('<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><Environment/>')
 def test_static_requires_network(self):
  with self.assertRaises(ValueError):parse(self.xml({**self.values(),'network_mode':'static','ip':'192.0.2.10','prefix':'24','gateway':'198.51.100.1','dns':'192.0.2.1'}))
if __name__=='__main__':unittest.main()
