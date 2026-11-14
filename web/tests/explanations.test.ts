import { expect, it } from 'vitest';
import { summarize, cleanupSteps } from '../src/lib/incident';
import { plainOutcome } from '../src/lib/plain';
import type { Device, SecurEvent } from '../src/types';

const event: SecurEvent = { id: 'e', mac: 'm', ts: '2026-11-14T12:00:00Z', kind: 'decoy_touch',
  evidence: {}, actions_taken: [], would_have: [], source: 'agent' };

it('uses the API template while pending and after provider failure without attributing it to Gemini', () => {
  for (const status of ['pending', 'template', 'ready'] as const) {
    const result = summarize({ ...event, explanation_status: status,
      explanation: { plain_language: 'The device contacted a decoy. No action was reported.', recommended_next_step: 'Review its settings.' } }, undefined);
    expect(result.body).toBe('The device contacted a decoy. No action was reported.');
    expect(result.next).toBe('Review its settings.');
    expect(result.source).toBe(status === 'ready' ? 'gemini' : status === 'pending' ? 'pending' : 'local');
  }
});

it('distinguishes internet blocking, quarantine, restore and simulated actions', () => {
  const blocked = { ...event, actions_taken: ['block_wan'] as const };
  expect(plainOutcome({ ...blocked, actions_taken: [...blocked.actions_taken] })).toContain('local access may remain');
  expect(summarize({ ...event, actions_taken: ['block_wan'] }, undefined).headline).toBe('Internet block reported');
  expect(summarize({ ...event, actions_taken: ['quarantine'] }, undefined).headline).toBe('Quarantine reported');
  expect(summarize({ ...event, actions_taken: ['restore'] }, undefined).headline).toBe('Restore reported');
  expect(summarize({ ...event, source: 'simulator', actions_taken: ['quarantine'] }, undefined).body).toContain('no real containment');
});

it('does not infer learning mode, malware infection or containment from a finding', () => {
  const result = summarize({ ...event, would_have: ['quarantine'] }, undefined);
  expect(result.body).toContain('no action was reported as applied');
  expect(result.body).not.toMatch(/learning mode|infected|attacking|isolated/);
});

it('does not prescribe unsupported camera-specific claims or promise malware cleanup', () => {
  const camera = { type: 'camera', default_creds: false, eol: false, ports: [] } as unknown as Device;
  expect(cleanupSteps(camera)).toEqual([]);
  expect(cleanupSteps({ ...camera, default_creds: true, eol: true, ports: [23] })).toHaveLength(3);
});
