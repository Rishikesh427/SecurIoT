import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { AdvisorPriorities, DeviceAdvisor } from '../src/components/Advisor';
import type { AdvisorAnswer, Device } from '../src/types';

const { api } = vi.hoisted(() => ({ api: { advisorChat: vi.fn(), advisorTriage: vi.fn(), researchStatus: vi.fn().mockResolvedValue({status:"unavailable",source:"rules"}) } }));
vi.mock('../src/api/client', () => ({ api, USE_MOCK: false }));
const device = { mac: '02:00:00:00:00:01', label: 'Camera', name: 'camera', type: 'unknown', band: 'high', risk: 70,
  reasons: ['Reported Telnet exposure (+15)'], risk_adjusted: 78, ai: { status: 'ready', source: 'gemini', assessment: 'Review exposed services.',
    likely_type: 'camera', expected_behavior: 'It may stream video.', top_risk: 'Telnet', next_step: 'Disable Telnet.',
    confidence: 'medium', delta: 8, delta_reason: 'Combined exposure.', risk_adjusted: 78 } } as Device;

beforeEach(() => {
  vi.clearAllMocks();
  HTMLDialogElement.prototype.showModal = function () { this.setAttribute('open', ''); };
  HTMLDialogElement.prototype.close = function () { this.removeAttribute('open'); };
});
afterEach(cleanup);

it('keeps the score simple and opens its breakdown on demand', () => {
  render(<DeviceAdvisor device={device} />);
  expect(screen.getByText('This device is high risk.', {exact:false})).toBeTruthy();
  expect(screen.queryByText(/Rules 70 · AI/)).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Why?' }));
  expect(screen.getByRole('dialog', { name: 'Rules Risk Breakdown' })).toBeTruthy();
  expect(screen.getByText('Reported Telnet exposure')).toBeTruthy();
});

it('bounds chat history and labels offline replies', async () => {
  api.advisorChat.mockResolvedValue({ source: 'rules', answer: 'Use local rules to change the password. '.repeat(25) });
  render(<DeviceAdvisor device={device} />);
  for (let i = 0; i < 5; i++) {
    fireEvent.change(screen.getByLabelText('Ask about the next steps'), { target: { value: `Question ${i}` } });
    fireEvent.submit(screen.getByRole('button', { name: 'Ask Advisor' }).closest('form')!);
    await waitFor(() => expect(api.advisorChat).toHaveBeenCalledTimes(i + 1));
    await waitFor(() => expect((screen.getByLabelText('Ask about the next steps') as HTMLInputElement).disabled).toBe(false));
  }
  const [mac, question, history] = api.advisorChat.mock.calls[4];
  expect(mac).toBe(device.mac); expect(question).toBe('Question 4');
  expect(history).toHaveLength(6);
  expect(history.every((t: { text: string }) => t.text.length <= 800)).toBe(true);
  expect(screen.getByText(/Local rules reply/)).toBeTruthy();
});

it('keeps a pending reply with its device when selection changes', async () => {
  let resolve!: (value: AdvisorAnswer) => void;
  api.advisorChat.mockReturnValue(new Promise<AdvisorAnswer>(done => { resolve = done; }));
  const view = render(<DeviceAdvisor key={device.mac} device={device} />);
  fireEvent.click(screen.getByRole('button', { name: 'What should I do first?' }));
  expect(api.advisorChat).toHaveBeenCalledWith(device.mac, 'What should I do first?', []);
  view.rerender(<DeviceAdvisor key="second" device={{ ...device, mac: '02:00:00:00:00:02' }} />);
  resolve({ source: 'gemini', answer: 'Advice for the first camera.' });
  await Promise.resolve();
  expect(screen.queryByText(/Advice for the first camera/)).toBeNull();
  expect(screen.queryByText(/You:/)).toBeNull();
});

it('ranks devices and opens the selected device without performing actions', async () => {
  api.advisorTriage.mockResolvedValue({ source: 'rules', order: [{ mac: device.mac, why: 'Highest risk.' }] });
  const select = vi.fn();
  render(<AdvisorPriorities devices={[device]} onSelect={select} />);
  fireEvent.click(screen.getByRole('button', { name: 'Prioritize devices' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Camera' }));
  expect(select).toHaveBeenCalledWith(device.mac);
  expect(screen.getByText(/Rules-based order/)).toBeTruthy();
});

it('retains a failed question so the user can retry', async () => {
  api.advisorChat.mockRejectedValue(new Error('Advisor is busy'));
  render(<DeviceAdvisor device={device} />);
  fireEvent.click(screen.getByRole('button', { name: 'How do I protect it?' }));
  expect((await screen.findByRole('alert')).textContent).toBe('Advisor is busy');
  expect((screen.getByLabelText('Ask about the next steps') as HTMLInputElement).value).toBe('How do I protect it?');
});

it('adds the question immediately on form submission and accepts the search icon', async () => {
  let resolve!: (value: AdvisorAnswer) => void;
  api.advisorChat.mockReturnValue(new Promise<AdvisorAnswer>(done => { resolve = done; }));
  render(<DeviceAdvisor device={device} />);
  fireEvent.change(screen.getByLabelText('Ask about the next steps'), { target: { value: 'First question' } });
  fireEvent.submit(screen.getByRole('button', { name: 'Ask Advisor' }).closest('form')!);
  expect(screen.getByRole('log').textContent).toContain('First question');
  resolve({ source: 'gemini', answer: 'Review settings.' });
  await screen.findByText('Review settings.', { exact: false });
  api.advisorChat.mockResolvedValue({ source: 'gemini', answer: 'Second answer.' });
  fireEvent.change(screen.getByLabelText('Ask about the next steps'), { target: { value: 'Second question' } });
  fireEvent.click(screen.getByRole('button', { name: 'Ask Advisor' }));
  await waitFor(() => expect(api.advisorChat).toHaveBeenCalledTimes(2));
  expect(screen.getByRole('log').textContent).toContain('Second question');
});
