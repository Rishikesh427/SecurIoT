import { Button } from './components/ui';
import type { Policy } from './types';

export function quarantineReason(policy: Policy | null, mac: string) {
  if (!policy) return 'Response policy is unavailable.';
  if (policy.protected_macs.includes(mac)) return 'Protected device';
  if (policy.learning_mode) return 'Enable containment to quarantine devices.';
  if (!policy.ladder.quarantine) return 'Quarantine is disabled by policy.';
  return '';
}

export function DeviceControls({ mac, policy, pending, busy, readOnly, onAction }: {
  mac: string; policy: Policy | null; pending?: string; busy: boolean; readOnly: boolean;
  onAction: (action: 'quarantine' | 'restore', mac: string) => void;
}) {
  const reason = quarantineReason(policy, mac);
  return <div className="space-y-2" aria-label="Manual device controls">
    <Button className="w-full" disabled={readOnly || busy || !!pending || !!reason} title={reason || 'Disconnect this device and prevent reconnection'}
      onClick={() => onAction('quarantine', mac)}>Quarantine</Button>
    <Button className="w-full" disabled={readOnly || busy || !!pending} title="Remove quarantine and internet restrictions"
      onClick={() => onAction('restore', mac)}>Restore access</Button>
    <p className="text-[13px] text-ink-2">Manual quarantine overrides automatic timing delays. Restore removes restrictions and gives the device a recovery grace period.</p>
    {pending ? <small role="status">{pending === 'quarantine' ? 'Quarantine' : 'Restore'} queued; awaiting agent acknowledgement.</small>
      : reason && <small>{reason}</small>}
  </div>;
}
