import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { DeviceControls } from '../src/DeviceControls';
import type { Policy } from '../src/types';
const mac = '02:00:00:00:00:20';
const policy: Policy = {learning_mode:false,protected_macs:[],ladder:{notify:true,block_wan:true,quarantine:true}};
afterEach(cleanup);

it('allows manual quarantine without a detection and explicit restore', () => {
  const action = vi.fn();
  render(<DeviceControls mac={mac} policy={policy} busy={false} readOnly={false} onAction={action} />);
  fireEvent.click(screen.getByRole('button',{name:'Quarantine'}));
  expect(action).toHaveBeenCalledWith('quarantine',mac);
  fireEvent.click(screen.getByRole('button',{name:'Restore access'}));
  expect(action).toHaveBeenCalledWith('restore',mac);
});

it.each([
  ['protected device', {...policy,protected_macs:[mac]}],
  ['disabled ladder', {...policy,ladder:{...policy.ladder,quarantine:false}}],
  ['unavailable policy', null],
])('blocks quarantine for %s while allowing recovery', (_name, responsePolicy) => {
  render(<DeviceControls mac={mac} policy={responsePolicy} busy={false} readOnly={false} onAction={vi.fn()} />);
  expect((screen.getByRole('button',{name:'Quarantine'}) as HTMLButtonElement).disabled).toBe(true);
  expect((screen.getByRole('button',{name:'Restore access'}) as HTMLButtonElement).disabled).toBe(false);
});

it('shows queued rather than applied state and prevents duplicate submissions', () => {
  const action = vi.fn();
  render(<DeviceControls mac={mac} policy={policy} busy={false} pending="quarantine" readOnly={false} onAction={action} />);
  expect(screen.getByRole('status').textContent).toContain('waiting for the Pi’s result');
  fireEvent.click(screen.getByRole('button',{name:'Quarantine'}));
  expect(action).not.toHaveBeenCalled();
});

it('allows an explicit internet block in learning mode without removing the device',()=>{
  const action=vi.fn();render(<DeviceControls mac={mac} policy={{...policy,learning_mode:true}} busy={false} readOnly={false} onAction={action}/>);
  fireEvent.click(screen.getByRole('button',{name:'Block Internet'}));expect(action).toHaveBeenCalledWith('block_wan',mac);
});
