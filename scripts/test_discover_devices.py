import ipaddress
import unittest
from discover_devices import candidates, merge

MAC = '02:00:00:00:00:01'

class Tests(unittest.TestCase):
    def test_expired_and_external_leases_are_ignored(self):
        leases = f'99 {MAC} 10.42.0.2 old *\n200 {MAC} 192.168.1.2 outside *'
        self.assertEqual(candidates([], leases, ipaddress.IPv4Network('10.42.0.0/24'), 100), {})

    def test_new_device_is_protected_and_known_policy_is_preserved(self):
        found = candidates([], f'200 {MAC} 10.42.0.2 camera *', ipaddress.IPv4Network('10.42.0.0/24'), 100)
        new, _ = merge([], found)
        self.assertTrue(new['devices'][0]['protected'])
        base = [{'mac': MAC, 'ip': '10.42.0.3', 'name': 'Reviewed camera', 'simulated': False,
                 'protected': False, 'eol': True}]
        updated, _ = merge(base, found)
        self.assertFalse(updated['devices'][0]['protected'])
        self.assertEqual(updated['devices'][0]['name'], 'Reviewed camera')
        self.assertTrue(updated['devices'][0]['eol'])
        self.assertEqual(updated['devices'][0]['ip'], '10.42.0.2')

    def test_conflicting_address_is_rejected(self):
        base = [{'mac': MAC, 'ip': '10.42.0.2', 'name': 'one', 'simulated': False},
                {'mac': '02:00:00:00:00:02', 'ip': '10.42.0.2', 'name': 'two', 'simulated': False}]
        with self.assertRaises(ValueError):
            merge(base, {})

if __name__ == '__main__':
    unittest.main()
