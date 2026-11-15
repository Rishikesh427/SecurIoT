import { expect, it } from 'vitest';
import { mockServer } from '../src/mock/mockServer';

it('starts with five devices and completes simulated containment before recording success', async () => {
  const devices = await mockServer.getDevices();
  expect(devices).toHaveLength(5);
  const policy = await mockServer.getPolicy();
  await mockServer.putPolicy({ ...policy, learning_mode: false });
  const target = devices[0];
  const result = await mockServer.postAction({ action: 'quarantine', mac: target.mac });
  expect(result.status).toBe('applied');
  expect((await mockServer.getDevices()).find(d => d.mac === target.mac)?.status).toBe('quarantined');
  expect((await mockServer.getAudit()).find(row => row.command_id === result.id)).toMatchObject({ actor: 'simulator', outcome: 'applied' });
});
