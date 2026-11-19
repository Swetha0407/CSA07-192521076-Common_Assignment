import tempfile,unittest
from pathlib import Path
from storage import Store
from firewall_engine import FirewallEngine
class EngineTest(unittest.TestCase):
 def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.s=Store(Path(self.tmp.name));self.e=FirewallEngine(self.s)
 def tearDown(self):self.tmp.cleanup()
 def flow(self,src="192.168.1.10",port=443,proto="TCP"):return {"source_ip":src,"destination_ip":"198.51.100.10","port":port,"protocol":proto,"bytes":128}
 def test_https_allowed(self):self.assertEqual(self.e.evaluate(self.flow())["status"],"ALLOW")
 def test_default_deny(self):self.assertEqual(self.e.evaluate(self.flow(port=9999))["status"],"BLOCK")
 def test_telnet_alert(self):r=self.e.evaluate(self.flow(port=23));self.assertTrue(r["suspicious"]);self.assertEqual(r["status"],"BLOCK")
 def test_cidr(self):self.assertEqual(self.e.evaluate(self.flow("192.168.1.55",80))["status"],"ALLOW")
 def test_bad_ip(self):self.assertIn("error",self.e.evaluate(self.flow("bad")))
 def test_rule_validation(self):
  with self.assertRaises(ValueError):self.e.validate_rule({"source_ip":"bad","destination_ip":"*","port":"80","protocol":"TCP","action":"ALLOW"})
if __name__=="__main__":unittest.main()
