import { Button } from './components/ui';
import type { Policy } from './types';

export function quarantineReason(policy: Policy | null, mac: string) {
  if (!policy) return 'Response policy is unavailable.';
  if (policy.protected_macs.includes(mac)) return 'Protected device';
  if (!policy.ladder.quarantine) return 'Quarantine is disabled by policy.';
  return '';
}

export function DeviceControls({ mac, policy, pending, busy, readOnly, onAction, onWarn, protectedDevice = false }: {
  mac: string; policy: Policy | null; pending?: string; busy: boolean; readOnly: boolean;
  onWarn?: (mac:string)=>void; protectedDevice?: boolean;
  onAction: (action: 'quarantine' | 'restore' | 'block_wan', mac: string) => void;
}) {
  const reason = protectedDevice ? 'Protected device' : quarantineReason(policy, mac);
  return <div className="space-y-2" aria-label="Manual device controls">
    <div className="grid grid-cols-2 gap-2"><Button disabled={readOnly || busy || !onWarn} onClick={()=>onWarn?.(mac)}>Warn</Button><Button disabled={readOnly || busy || !!pending || !policy || protectedDevice || policy.protected_macs.includes(mac) || !policy.ladder.block_wan} onClick={()=>onAction('block_wan',mac)}>Block Internet</Button></div>
    <Button className="w-full" disabled={readOnly || busy || !!pending || !!reason} title={reason || 'Disconnect this device and prevent reconnection'}
      onClick={() => onAction('quarantine', mac)}>Quarantine</Button>
    <Button className="w-full" disabled={readOnly || busy} title="Remove quarantine and internet restrictions"
      onClick={() => onAction('restore', mac)}>Restore access</Button>
    {pending ? <small role="status">Request sent; waiting for the Pi’s result.</small>
      : reason && <small>{reason}</small>}
  </div>;
}
