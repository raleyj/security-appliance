import json
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'provisioning'))
import alert_delivery


class AlertDeliveryTests(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup)
        root=Path(folder.name)
        self.config=patch.object(alert_delivery,'CONFIG',root/'config.json');self.config.start();self.addCleanup(self.config.stop)
        self.state=patch.object(alert_delivery,'STATE',root/'state.json');self.state.start();self.addCleanup(self.state.stop)

    def test_destination_validation_and_disabled_default(self):
        self.assertFalse(alert_delivery.status()['config']['enabled'])
        for destination in ('http://example.test/hook','https://user:secret@example.test/hook','https://localhost/hook'):
            with self.assertRaises(ValueError):alert_delivery.validate({'enabled':True,'kind':'https','destination':destination})
        self.assertEqual(alert_delivery.apply({'enabled':True,'kind':'syslog','destination':'logs.example.test:514'})['config']['destination'],'logs.example.test:514')
        mattermost='https://chat.example.test/hooks/abcdefghijklmnopqrstuvwxyz'
        status=alert_delivery.apply({'enabled':True,'kind':'mattermost','destination':mattermost})
        self.assertEqual(status['config']['destination'],'')
        self.assertEqual(status['config']['destinationDisplay'],'https://chat.example.test/hooks/[secret]')
        self.assertTrue(status['config']['configured'])
        self.assertEqual(alert_delivery.load()['destination'],mattermost)
        self.assertEqual(alert_delivery.apply({'enabled':True,'kind':'mattermost','destination':''})['config']['kind'],'mattermost')
        with self.assertRaises(ValueError):alert_delivery.validate({'enabled':True,'kind':'mattermost','destination':'https://chat.example.test/not-a-hook'})

    def test_delivery_omits_unapproved_text_and_deduplicates(self):
        alert_delivery.apply({'enabled':True,'kind':'syslog','destination':'logs.example.test:514'})
        with patch.object(alert_delivery,'remote_addresses',return_value={'192.0.2.1'}),patch.object(alert_delivery.socket,'socket') as make_socket:
            client=make_socket.return_value.__enter__.return_value
            first=alert_delivery.deliver(['The appliance firewall is not active.','password=top-secret'])
            self.assertIn('sent via UDP',first['lastResult'])
            payload=client.sendto.call_args.args[0].decode()
            self.assertIn('firewall is not active',payload)
            self.assertNotIn('top-secret',payload)
            alert_delivery.deliver(['The appliance firewall is not active.','password=top-secret'])
            self.assertEqual(client.sendto.call_count,1)

    def test_mattermost_delivery_uses_text_payload_and_appliance_ca(self):
        alert_delivery.apply({'enabled':True,'kind':'mattermost','destination':'https://chat.example.test/hooks/abcdefghijklmnopqrstuvwxyz'})
        response=unittest.mock.MagicMock();response.status=200
        opener=unittest.mock.MagicMock();opener.open.return_value.__enter__.return_value=response
        context=unittest.mock.MagicMock()
        with patch.object(alert_delivery,'remote_addresses',return_value={'192.0.2.2'}),patch.object(alert_delivery.ssl,'create_default_context',return_value=context),patch.object(alert_delivery.urllib.request,'build_opener',return_value=opener):
            result=alert_delivery.deliver(['This is a test alert from the appliance.'],force=True)
        self.assertEqual(result['lastResult'],'delivered')
        request=opener.open.call_args.args[0]
        payload=json.loads(request.data)
        self.assertIn('text',payload);self.assertIn('test alert',payload['text'])
        self.assertNotIn('alerts',payload)


if __name__=='__main__':unittest.main()
