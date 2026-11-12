import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'provisioning'))
import update_bundle


class UpdateBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.appliance = self.root / 'appliance'; self.state = self.root / 'state'
        (self.appliance / 'app').mkdir(parents=True); self.state.mkdir()
        (self.appliance / 'app/value.txt').write_text('old')
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public = self.root / 'public.pem'; self.public.write_bytes(self.key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

    def make_bundle(self, content=b'new', path='app/value.txt'):
        manifest={'schemaVersion':1,'version':'0.3.1-test','files':[{'path':path,'sha256':hashlib.sha256(content).hexdigest(),'mode':'0644'}]}
        raw=json.dumps(manifest,separators=(',',':'),sort_keys=True).encode()
        signature=self.key.sign(raw,padding.PKCS1v15(),hashes.SHA256())
        bundle=self.root/'update.sau'
        with zipfile.ZipFile(bundle,'w') as archive:
            archive.writestr('manifest.json',raw);archive.writestr('manifest.sig',signature);archive.writestr('payload/'+path,content)
        return bundle

    def test_valid_install(self):
        result=update_bundle.install_bundle(self.make_bundle(),self.public,self.appliance,self.state,lambda changed,root:None)
        self.assertTrue(result['installed']);self.assertEqual((self.appliance/'app/value.txt').read_text(),'new')
        self.assertTrue((self.state/'update-rollback/app/value.txt').exists())

    def test_tampered_and_unsafe_bundles_rejected(self):
        bundle=self.make_bundle();data=bytearray(bundle.read_bytes());data[-20]^=1;bundle.write_bytes(data)
        with self.assertRaises(ValueError):update_bundle.inspect_bundle(bundle,self.public)
        with self.assertRaises(ValueError):update_bundle.inspect_bundle(self.make_bundle(path='../escape'),self.public)

    def test_failed_health_check_rolls_back(self):
        def fail(changed,root):raise RuntimeError('health failed')
        with self.assertRaisesRegex(ValueError,'rolled back'):
            update_bundle.install_bundle(self.make_bundle(),self.public,self.appliance,self.state,fail)
        self.assertEqual((self.appliance/'app/value.txt').read_text(),'old')

    def test_update_history_and_guarded_previous_release_restore(self):
        (self.state/'release.json').write_text(json.dumps({'version':'1.0','manifestSha256':'a'*64}))
        installed=update_bundle.install_bundle(self.make_bundle(),self.public,self.appliance,self.state,lambda changed,root:None)
        self.assertEqual(installed['version'],'0.3.1-test')
        current=update_bundle.status(self.state,self.public)
        self.assertTrue(current['rollbackAvailable'])
        self.assertEqual(current['previousVersion'],'1.0')
        self.assertEqual(current['history'][-1]['healthResult'],'passed')
        restored=update_bundle.restore_previous(self.appliance,self.state,lambda changed,root:None)
        self.assertTrue(restored['restored'])
        self.assertEqual((self.appliance/'app/value.txt').read_text(),'old')
        self.assertEqual(json.loads((self.state/'release.json').read_text())['version'],'1.0')
        self.assertFalse(update_bundle.status(self.state,self.public)['rollbackAvailable'])

    def test_host_control_restart_is_deferred_until_after_health(self):
        (self.appliance/'provisioning').mkdir()
        (self.appliance/'provisioning/compose_runtime.py').write_text('')
        service=SimpleNamespace(SERVICES={'management':'security-management'},status=lambda:{'services':[{'ready':True}]})
        with patch.dict(sys.modules,{'service_control':service}),patch.object(update_bundle.subprocess,'run',return_value=SimpleNamespace(returncode=0)) as run:
            update_bundle._default_post_install(['provisioning/operations_insights.py'],self.appliance)
        commands=[call.args[0] for call in run.call_args_list]
        self.assertEqual(commands[-1][0],'systemd-run')
        self.assertIn('--on-active=30s',commands[-1])
        self.assertNotIn(('systemctl','restart','security-host-control'),commands)

    def test_proxy_hardening_update_uses_pinned_image_and_validates_nginx(self):
        (self.appliance/'provisioning').mkdir()
        (self.appliance/'provisioning/compose_runtime.py').write_text('')
        (self.appliance/'provisioning/render_proxy.py').write_text('')
        (self.appliance/'provisioning/reverse-proxy').mkdir()
        (self.appliance/'provisioning/reverse-proxy/Dockerfile').write_text('FROM nginx:1.30.6-alpine')
        source='nginx:1.30.6-alpine@sha256:'+'5'*64
        (self.appliance/'provisioning/proxy-image.json').write_text(json.dumps({'source':source,'local':'lab-security-proxy:1.30.6-alpine-security-20261111'}))
        service=SimpleNamespace(SERVICES={'management':'security-management'},status=lambda:{'services':[{'ready':True}]})
        changed=['provisioning/proxy-image.json','provisioning/compose_runtime.py','provisioning/render_proxy.py']
        with patch.dict(sys.modules,{'service_control':service}),patch.object(update_bundle.subprocess,'run',return_value=SimpleNamespace(returncode=0)) as run:
            update_bundle._default_post_install(changed,self.appliance)
        commands=[call.args[0] for call in run.call_args_list]
        self.assertIn(('docker','pull',source),commands)
        self.assertIn(('docker','build','--provenance=false','--pull=false','-t','lab-security-proxy:1.30.6-alpine-security-20261111',str(self.appliance/'provisioning/reverse-proxy')),commands)
        self.assertTrue(any(command[:2]==('docker','compose') and '--force-recreate' in command and command[-1]=='proxy' for command in commands))
        self.assertIn(('docker','exec','security-proxy','nginx','-t'),commands)


if __name__ == '__main__': unittest.main()
