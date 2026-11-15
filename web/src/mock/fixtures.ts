// Mock data comes straight from the shared contract so it can't drift.
import contractFixtures from "../../../contract/fixtures.json";
import type { Device, Policy, SecurEvent } from "../types";

const fixtures = contractFixtures as unknown as { devices: Device[]; events: SecurEvent[] };

export const CAMERA_MAC = fixtures.devices.find((d) => d.type === "camera")!.mac;
export const PROJECTOR_MAC = fixtures.devices.find((d) => d.type === "projector")!.mac;

/** Fixture devices with timestamps refreshed to now. */
export function fixtureDevices(): Device[] {
  const now = new Date().toISOString();
  const extra: Device[] = [
    { ...fixtures.devices[1], mac: '02:00:00:00:00:60', ip: '10.42.0.60', name: 'plug', label: 'Kitchen smart plug (simulated)', type: 'plug', risk: 35, band: 'medium', reasons: ['Unencrypted service (+35)'], ports: [80] },
    { ...fixtures.devices[1], mac: '02:00:00:00:00:70', ip: '10.42.0.70', name: 'speaker', label: 'Office speaker (simulated)', type: 'speaker' },
  ];
  return [...fixtures.devices, ...extra].map((d) => ({ ...d, last_seen: now }));
}

/**
 * Fixture "device joined" events, moved to ~40 minutes ago. The fixture's
 * learning-mode decoy event is left out so the demo starts calm.
 */
export function fixtureEvents(): SecurEvent[] {
  const base = Date.now() - 40 * 60_000;
  return fixtures.events
    .filter((e) => e.kind === "new_device")
    .map((e, i) => ({ ...e, ts: new Date(base + i * 5000).toISOString() }));
}

// contract/devices.yaml marks the projector as protected.
export const defaultPolicy: Policy = {
  learning_mode: true,
  protected_macs: [PROJECTOR_MAC],
  ladder: { notify: true, block_wan: true, quarantine: true },
};
