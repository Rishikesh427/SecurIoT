"""Fixed-window calibration, advisory volume detection and expiring risk."""
import argparse
import json
import math
import os
from pathlib import Path
import tempfile


def atomic(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as f:
            temporary = f.name
            json.dump(data, f, allow_nan=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


class Routine:
    WIDTH = 10
    REQUIRED = 30
    TTL = 300
    MIN_STD_BYTES = 1024

    def __init__(self, directory, mode, now):
        self.path = Path(directory) / 'routine.json'
        self.command = Path(directory) / 'routine-calibrate.json'
        self.mode = mode
        self.state = {'version': 1, 'mode': mode, 'baselines': {}, 'signals': {}, 'calibrating': {}}
        if self.path.exists():
            self.state = json.loads(self.path.read_text())
            self.validate()
        # Incomplete in-memory windows are never counted after a restart.
        self.windows = {}
        self.last_clock = now
        self.last_save = now
        self.dirty = False
        self.expire(now)

    def validate(self):
        s = self.state
        if s.get('version') != 1 or s.get('mode') != self.mode:
            raise ValueError('Routine state version/mode mismatch; use a separate state directory')
        from .models import normalize_mac
        def number(value):
            return type(value) in (float, int) and math.isfinite(value) and value >= 0
        for group in ('baselines', 'signals', 'calibrating'):
            if not isinstance(s.get(group), dict) or len(s[group]) > 1000:
                raise ValueError('Invalid routine state')
            for mac in s[group]:
                if normalize_mac(mac) != mac:
                    raise ValueError('Invalid routine MAC')
        for b in s['baselines'].values():
            if not all(number(b.get(k)) for k in ('mean', 'std', 'trained_at')) or b.get('samples') != 30:
                raise ValueError('Invalid baseline statistics')
        for signal in s['signals'].values():
            if not number(signal.get('at')) or not number(signal.get('score')) or signal['score'] > 1:
                raise ValueError('Invalid signal state')
        for samples in s['calibrating'].values():
            if not isinstance(samples, list) or len(samples) >= self.REQUIRED or not all(number(x) for x in samples):
                raise ValueError('Invalid calibration samples')

    def save(self, now, force=False):
        if self.dirty and (force or now - self.last_save >= 2):
            atomic(self.path, self.state)
            self.dirty = False
            self.last_save = now

    def commands(self, known, now):
        if not self.command.exists():
            return
        from .models import normalize_mac
        # Operator writes commands atomically; single-writer runtime consumes them.
        data = json.loads(self.command.read_text())
        macs = data.get('macs')
        if not isinstance(macs, list) or not macs or len(macs) > 1000:
            raise ValueError('Calibration command needs 1..1000 MACs')
        macs = [normalize_mac(m) for m in macs]
        unknown = set(macs) - set(known)
        if unknown:
            # Guests may not yet have arrived. Leave request pending.
            return
        for mac in macs:
            self.state['baselines'].pop(mac, None)
            self.state['calibrating'][mac] = []
            self.windows.pop(mac, None)
        self.dirty = True
        self.save(now, force=True)
        self.command.unlink()

    def expire(self, now):
        for mac, value in list(self.state['signals'].items()):
            # Future timestamps after clock rollback are discarded conservatively.
            if now < value['at'] or now - value['at'] >= self.TTL:
                del self.state['signals'][mac]
                self.dirty = True

    def signal(self, mac, score, now):
        score = float(score)
        if not math.isfinite(score) or not 0 <= score <= 1:
            raise ValueError('Invalid behavioral signal')
        self.expire(now)
        old = self.state['signals'].get(mac)
        # Preserve the strongest still-active signal; latest detection renews TTL.
        self.state['signals'][mac] = {'score': max(score, old['score'] if old else 0), 'at': now}
        self.dirty = True
        self.save(now, force=True)

    def scores(self, now):
        self.expire(now)
        return {mac: s['score'] for mac, s in self.state['signals'].items()}

    def record(self, observation, now, eligible):
        mac = observation.mac
        bucket = int(now // self.WIDTH)
        if mac not in self.windows:
            # First partial window is discarded, never treated as ten seconds.
            self.windows[mac] = {'bucket': bucket, 'bytes': 0, 'clean': eligible,
                                 'partial': True, 'arp': 0, 'targets': set()}
        w = self.windows[mac]
        w['bytes'] += observation.bytes_in + observation.bytes_out
        w['arp'] += observation.packet_arp_requests
        w['targets'].update(observation.packet_syn_targets)
        w['clean'] = w['clean'] and eligible and not observation.packet_decoy_hits
        if w['arp'] >= 30 or len(w['targets']) >= 20:
            w['clean'] = False

    def flag(self, mac):
        if mac in self.windows:
            self.windows[mac]['clean'] = False

    def advance(self, now, devices, learning):
        if now < self.last_clock:
            self.windows.clear()
        self.last_clock = now
        self.commands(devices, now)
        self.expire(now)
        output = []
        current = int(now // self.WIDTH)
        for mac, w in list(self.windows.items()):
            device = devices.get(mac)
            if device is None:
                del self.windows[mac]
                continue
            # A long scheduling/capture gap is not evidence of zero traffic.
            if current - w['bucket'] > 6:
                del self.windows[mac]
                continue
            w['clean'] = w['clean'] and learning and device.status == 'normal' and mac not in self.state['signals']
            while w['bucket'] < current:
                start = w['bucket'] * self.WIDTH
                restricted = device.status != 'normal'
                recent = mac in self.state['signals']
                clean = w['clean'] and learning and not restricted and not recent
                if not w['partial']:
                    baseline = self.state['baselines'].get(mac)
                    if baseline and not restricted:
                        std = max(baseline['std'], self.MIN_STD_BYTES)
                        z = (w['bytes'] - baseline['mean']) / std
                        if z >= 4 and w['bytes']:
                            output.append((mac, min(1., z / 8), {'z': round(z, 2),
                                'bytes': w['bytes'], 'window_seconds': self.WIDTH,
                                'window_start': start, 'baseline_mean': baseline['mean'],
                                'baseline_std': baseline['std'], 'effective_std': std,
                                'advisory_only': True, 'detector': 'volume_zscore'}))
                            clean = False
                    if mac in self.state['calibrating'] and clean:
                        samples = self.state['calibrating'][mac]
                        samples.append(w['bytes'])
                        if len(samples) == self.REQUIRED:
                            mean = sum(samples) / len(samples)
                            std = math.sqrt(sum((x - mean) ** 2 for x in samples) / (len(samples) - 1))
                            self.state['baselines'][mac] = {'mean': mean, 'std': std,
                                'samples': len(samples), 'trained_at': now, 'window_seconds': self.WIDTH}
                            del self.state['calibrating'][mac]
                        self.dirty = True
                w.update(bucket=w['bucket'] + 1, bytes=0, clean=True, partial=False, arp=0, targets=set())
        self.save(now)
        return output


def main():
    p = argparse.ArgumentParser(description='Request clean calibration or inspect routine state. Run on the agent host.')
    p.add_argument('--state-dir', type=Path, required=True)
    p.add_argument('--calibrate', action='append', metavar='MAC')
    args = p.parse_args()
    if args.calibrate:
        from .models import normalize_mac
        target = args.state_dir / 'routine-calibrate.json'
        if target.exists():
            raise SystemExit('A calibration request is already pending')
        atomic(target, {'macs': [normalize_mac(m) for m in args.calibrate]})
        print('Requested. Keep the agent in learning mode and run normal traffic only.')
    path = args.state_dir / 'routine.json'
    print(path.read_text() if path.exists() else 'No routine state yet. Start the live agent.')

if __name__ == '__main__':
    main()
