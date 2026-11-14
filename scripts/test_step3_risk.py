import sys
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'agent'))
sys.path.insert(0, str(ROOT / 'ml'))
from securiot_agent.models import Device
from securiot_agent.vulnerabilities import VulnerabilityAssessor

class Tests(unittest.TestCase):
    def score(self, facts, anomaly=0):
        return VulnerabilityAssessor({'vulnerabilities': [
            {'vendorProject': 'Example', 'product': 'Cam', 'cveID': 'CVE-2099-12345'}
        ]}).assess(Device('02:00:00:00:00:01', '10.42.0.2', 'Test', simulated=False, risk_facts=facts), anomaly)
    def test_unknown_guest(self):
        r=self.score({})
        self.assertEqual(r['static_risk'],0)
        self.assertIn('ports',r['coverage']['unknown_inputs'])
        self.assertFalse(r['coverage']['facts_verified_by_agent'])
        self.assertTrue(any('not proof of safety' in s for s in r['reasons']))
    def test_behavior_does_not_modify_static(self):
        r=self.score({'ports':[23]},1)
        self.assertEqual(r['static_risk'],15)
        self.assertEqual(r['risk'],55)
        self.assertEqual(r['behavior_points'],40)
    def test_candidate_not_confirmed(self):
        r=self.score({'vendor':'Example','model':'Cam'})
        self.assertEqual(r['static_risk'],15)
        self.assertEqual(r['confidence'],'possible')
        self.assertFalse(r['coverage']['firmware_applicability_checked'])
    def test_admin_fact_required(self):
        self.assertEqual(self.score({'ports':[80]})['static_risk'],0)
        self.assertEqual(self.score({'ports':[80],'admin_ports':[80]})['static_risk'],15)
    def test_combination_and_cap(self):
        r=self.score({'ports':[23], 'vendor':'Example','model':'Cam',
            'default_creds':True,'eol':True,'cloud_only':True},1)
        self.assertEqual(r['static_risk'],80)
        self.assertEqual(r['risk'],100)
        self.assertEqual(r['behavior_points'],20)
    def test_invalid_boolean_rejected(self):
        with self.assertRaises(ValueError): self.score({'eol':'false'})

if __name__ == '__main__': unittest.main()
