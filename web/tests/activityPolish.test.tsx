import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { ActivityExplorer } from '../src/components/ActivityExplorer';
import { ActivityView } from '../src/components/ActivityView';
vi.mock('../src/api/client', () => ({ api: { runAudit: vi.fn().mockResolvedValue({ summary: 'No recorded activity.', bullets: ['No recorded activity.', 'No restrictions reported.', 'Review the audit log.'] }) } }));
afterEach(cleanup);
it('hides filters until requested and retains the filter selection when collapsed', () => {
  render(<ActivityExplorer events={[]} devices={[]} onSelect={vi.fn()} />);
  expect(screen.queryByLabelText('Event Type')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Filter Activity' }));
  const time = screen.getByLabelText('Time') as HTMLSelectElement;
  fireEvent.change(time, { target: { value: '60' } });
  fireEvent.click(screen.getByRole('button', { name: 'Filter Activity' }));
  expect(screen.queryByLabelText('Time')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Filter Activity' }));
  expect((screen.getByLabelText('Time') as HTMLSelectElement).value).toBe('60');
});
it('keeps audit buttons together without a placeholder digest container', async () => {
  render(<ActivityView devices={[]} entries={[]} onAction={vi.fn()} canAct canRunAudit />);
  const run = screen.getByRole('button', { name: 'Run Audit' });
  const log = screen.getByRole('button', { name: 'Open Audit Log' });
  expect(run.parentElement).toBe(log.parentElement);
  expect(screen.queryByText(/Run an audit to summarize/)).toBeNull();
  fireEvent.click(run);
  expect(await screen.findByText('No recorded activity.')).toBeTruthy();
});
