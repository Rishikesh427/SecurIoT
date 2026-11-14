import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import App from '../src/App';
import type { AuditEntry, Device, Policy } from '../src/types';
const { api } = vi.hoisted(() => ({api:{capabilities:vi.fn(),devices:vi.fn(),events:vi.fn(),policy:vi.fn(),audit:vi.fn(),action:vi.fn(),storage:vi.fn(),hasFeed:vi.fn(),savePolicy:vi.fn()}}));
vi.mock('../src/api/client', () => ({api,USE_MOCK:false,getToken:()=> 'test-token',setToken:vi.fn(),isMissing:()=>false,ApiError:class extends Error {status=0;}}));
const mac = '02:00:00:00:00:20';
const policy: Policy = {learning_mode:false,protected_macs:[],ladder:{notify:true,block_wan:true,quarantine:true}};
const device: Device = {mac,ip:'10.42.0.20',name:'Pi',label:'Demo Pi',type:'camera',vendor:null,ports:[],bytes_in:0,bytes_out:0,dests:[],last_seen:new Date().toISOString(),simulated:false,has_feed:false,eol:false,default_creds:false,cloud_only:false,anomaly:0,risk:0,band:'low',confidence:'low',reasons:[],status:'normal'};
let rows: AuditEntry[] = [];
beforeEach(() => {
  vi.clearAllMocks(); localStorage.clear(); rows=[];
  api.capabilities.mockResolvedValue({actions:true,auditRun:false}); api.devices.mockResolvedValue([device]);
  api.events.mockResolvedValue([]); api.policy.mockResolvedValue(policy); api.audit.mockImplementation(async()=>rows);
  api.storage.mockResolvedValue({mode:'memory'}); api.hasFeed.mockReturnValue(false);
  api.action.mockResolvedValue({id:'command-1',created_at:new Date().toISOString(),action:'quarantine',mac});
});
afterEach(cleanup);

it('queues quarantine, preserves reported status, waits for ack and enables restore', async () => {
  render(<App />);
  fireEvent.click(await screen.findByRole('button',{name:/Demo Pi/}));
  fireEvent.click(await screen.findByRole('button',{name:'Quarantine'}));
  await waitFor(()=>expect(api.action).toHaveBeenCalledWith({action:'quarantine',mac}));
  expect((screen.getByRole('button',{name:'Quarantine'}) as HTMLButtonElement).disabled).toBe(true);
  expect(screen.getByRole('status').textContent).toContain('awaiting agent acknowledgement');
  await expect(api.devices.mock.results[0].value).resolves.toEqual([device]);
  rows=[{id:'audit-1',command_id:'command-1',ts:new Date().toISOString(),actor:'judge',action:'quarantine',mac,outcome:'applied'}];
  await waitFor(()=>expect((screen.getByRole('button',{name:'Restore access'}) as HTMLButtonElement).disabled).toBe(false),{timeout:3500});
  fireEvent.click(screen.getByRole('button',{name:'Restore access'}));
  await waitFor(()=>expect(api.action).toHaveBeenLastCalledWith({action:'restore',mac}));
});

it('surfaces failed acknowledgement and allows another recovery request', async () => {
  render(<App />);
  fireEvent.click(await screen.findByRole('button',{name:/Demo Pi/}));
  fireEvent.click(screen.getByRole('button',{name:'Quarantine'}));
  await waitFor(()=>expect(api.action).toHaveBeenCalled());
  rows=[{id:'audit-1',command_id:'command-1',ts:new Date().toISOString(),actor:'judge',action:'quarantine',mac,outcome:'failed'}];
  await waitFor(()=>expect(screen.getByText(/failed or cancelled/)).toBeTruthy(),{timeout:3500});
  expect((screen.getByRole('button',{name:'Restore access'}) as HTMLButtonElement).disabled).toBe(false);
});
