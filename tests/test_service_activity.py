import subprocess,sys,unittest
from unittest.mock import MagicMock,patch

sys.modules.setdefault('fcntl',MagicMock())
from provisioning import service_control


class ServiceActivityTests(unittest.TestCase):
 def test_selected_service_is_the_only_container_read(self):
  result=subprocess.CompletedProcess([],0,'accepted client connection\n','')
  with patch.object(service_control.subprocess,'run',return_value=result) as run:
   activity=service_control.connection_logs('kmip')
  self.assertEqual(activity,{'service':'kmip','lines':['accepted client connection']})
  self.assertEqual(run.call_args.args[0],['docker','logs','--tail','200','security-kmip'])

 def test_invalid_service_is_rejected_before_running_docker(self):
  with patch.object(service_control.subprocess,'run') as run:
   with self.assertRaises(ValueError):service_control.connection_logs('../other')
  run.assert_not_called()

 def test_sensitive_values_and_query_strings_are_removed(self):
  result=subprocess.CompletedProcess([],0,'GET /path?token=value HTTP/1.1\nAuthorization: secret\n','')
  with patch.object(service_control.subprocess,'run',return_value=result):
   lines=service_control.connection_logs('management')['lines']
  self.assertIn('GET /path?[query removed] HTTP/1.1',lines)
  self.assertIn('[credential-related service event redacted]',lines)


if __name__=='__main__':unittest.main()
