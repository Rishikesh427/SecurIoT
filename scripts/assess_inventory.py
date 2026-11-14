"""Offline configured-facts report. No network probes or Gemini calls."""
import argparse
import json
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'agent'))
sys.path.insert(0, str(ROOT / 'ml'))
from securiot_agent.replay import load_devices
from securiot_agent.vulnerabilities import VulnerabilityAssessor

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--devices', type=Path, required=True)
    args = p.parse_args()
    inventory = load_devices(args.devices, simulated=False)
    assessor = VulnerabilityAssessor()
    print(json.dumps([{'mac': d.mac, 'name': d.name, **assessor.assess(d, 0)}
                      for d in inventory.devices.values()], indent=2))

if __name__ == '__main__':
    main()
