import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import App from '../src/App';
import type { AuditEntry, Device, Policy } from '../src/types';
const { api } = vi.hoisted(() => ({api:{dashboard:vi.fn(),capabilities:vi.fn(),devices:vi.fn(),events:vi.fn(),policy:vi.fn(),audit:vi.fn(),action:vi.fn(),storage:vi.fn(),hasFeed:vi.fn(),savePolicy:vi.fn()}}));
vi.mock('../src/api/client', () => ({api,USE_MOCK:false,getToken:()=> 'test-token',setToken:vi.fn(),isMissing:()=>false,ApiError:class extends Error {status=0;}}));
vi.mock('../src/components/NetworkMap', () => ({ default: ({devices,onSelect}: {devices: Device[];onSelect:(mac:string)=>void}) => <div>{devices.map(d=><button key={d.mac} onClick={()=>onSelect(d.mac)}>{d.label}</button>)}</div> }));
const mac = '02:00:00:00:00:20';
const policy: Policy = {learning_mode:false,protected_macs:[],ladder:{notify:true,block_wan:true,quarantine:true}};
const device: Device = {mac,ip:'10.42.0.20',name:'Pi',label:'Demo Pi',type:'camera',vendor:null,ports:[],bytes_in:0,bytes_out:0,dests:[],last_seen:new Date().toISOString(),simulated:false,has_feed:false,eol:false,default_creds:false,cloud_only:false,anomaly:0,risk:0,band:'low',confidence:'low',reasons:[],status:'normal'};
let rows: AuditEntry[] = [];
beforeEach(() => {
  vi.clearAllMocks(); api.dashboard.mockResolvedValue(undefined); localStorage.clear(); rows=[];
  api.capabilities.mockResolvedValue({actions:true,auditRun:false}); api.devices.mockResolvedValue([device]);
  api.events.mockResolvedValue([]); api.policy.mockResolvedValue(policy); api.audit.mockImplementation(async()=>rows);
  Object.defineProperty(window, 'matchMedia', { configurable: true, value: vi.fn(() => ({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() })) });
  HTMLDialogElement.prototype.showModal = function () { this.setAttribute('open', ''); };
  HTMLDialogElement.prototype.close = function () { this.removeAttribute('open'); };
  api.savePolicy.mockImplementation(async (value: Policy) => value);
  api.storage.mockResolvedValue({mode:'memory'}); api.hasFeed.mockReturnValue(false);
  api.action.mockResolvedValue({id:'command-1',created_at:new Date().toISOString(),action:'quarantine',mac});
});
afterEach(cleanup);

it('queues quarantine, preserves reported status, waits for ack and enables restore', async () => {
  render(<App />);
  fireEvent.click(await screen.findByRole('button',{name:'Demo Pi'}));
  fireEvent.click(await screen.findByRole('button',{name:'Quarantine'}));
  await waitFor(()=>expect(api.action).toHaveBeenCalledWith({action:'quarantine',mac}));
  expect((screen.getByRole('button',{name:'Quarantine'}) as HTMLButtonElement).disabled).toBe(true);
  expect(screen.getByRole('status').textContent).toContain('waiting for the Pi’s result');
  await expect(api.devices.mock.results[0].value).resolves.toEqual([device]);
  rows=[{id:'audit-1',command_id:'command-1',ts:new Date().toISOString(),actor:'judge',action:'quarantine',mac,outcome:'applied'}];
  await waitFor(()=>expect((screen.getByRole('button',{name:'Restore access'}) as HTMLButtonElement).disabled).toBe(false),{timeout:3500});
  fireEvent.click(screen.getByRole('button',{name:'Restore access'}));
  await waitFor(()=>expect(api.action).toHaveBeenLastCalledWith({action:'restore',mac}));
});

it('surfaces failed acknowledgement and allows another recovery request', async () => {
  render(<App />);
  fireEvent.click(await screen.findByRole('button',{name:'Demo Pi'}));
  fireEvent.click(screen.getByRole('button',{name:'Quarantine'}));
  await waitFor(()=>expect(api.action).toHaveBeenCalled());
  rows=[{id:'audit-1',command_id:'command-1',ts:new Date().toISOString(),actor:'judge',action:'quarantine',mac,outcome:'failed'}];
  await waitFor(()=>expect(screen.getByText(/failed or cancelled/)).toBeTruthy(),{timeout:3500});
  expect((screen.getByRole('button',{name:'Restore access'}) as HTMLButtonElement).disabled).toBe(false);
});

it('keeps three left navigation pages and opens settings/tutorial as dialogs', async () => {
  render(<App />);
  expect(screen.getByRole('navigation',{name:'Main navigation'})).toBeTruthy();
  expect(screen.getByRole('button',{name:'Home',exact:true})).toBeTruthy();
  expect(screen.getByRole('button',{name:'Activity',exact:true})).toBeTruthy();
  expect(screen.getByRole('button',{name:'Prevention',exact:true})).toBeTruthy();
  expect(screen.queryByRole('button',{name:'Overview',exact:true})).toBeNull();
  fireEvent.click(screen.getByRole('button',{name:'Open tutorial'}));
  expect(screen.getByRole('dialog',{name:'CasaWarden Tutorial'})).toBeTruthy();
  fireEvent.click(screen.getByRole('button',{name:'Close CasaWarden Tutorial'}));
  await screen.findByRole('button',{name:'Demo Pi'});
  fireEvent.click(screen.getByRole('button',{name:'Settings',exact:true}));
  expect(screen.getByRole('dialog',{name:'Settings'})).toBeTruthy();
  fireEvent.click(screen.getByRole('button',{name:'Close Settings'}));
  expect(screen.queryByRole('dialog')).toBeNull();
});

it('retains loaded devices when the optional event route times out', async () => {
  api.events.mockRejectedValue(new Error('Activity request timed out'));
  render(<App />);
  expect(await screen.findByRole('button',{name:'Demo Pi'})).toBeTruthy();
  expect(screen.queryByText(/Dashboard updates unavailable/)).toBeNull();
  expect(screen.getByText(/Activity request timed out/)).toBeTruthy();
});

it('removes the Home arm switch while keeping protection controls in Settings', async () => {
  api.policy.mockResolvedValue({...policy,learning_mode:true});
  render(<App/>);
  await screen.findByRole('button',{name:'Demo Pi'});
  expect(screen.queryByRole('switch')).toBeNull();
  expect(screen.getByRole('button',{name:'Open tutorial'})).toBeTruthy();
  fireEvent.click(screen.getByRole('button',{name:'Settings',exact:true}));
  fireEvent.click(await screen.findByRole('switch',{name:'Automatic protection'}));
  fireEvent.click(screen.getByRole('button',{name:'Save',exact:true}));
  await waitFor(()=>expect(api.savePolicy).toHaveBeenCalledWith(expect.objectContaining({learning_mode:false})));
});

it('shows heatmap, recent activity and digest on Activity with a dismissible audit log', async () => {
  render(<App />);
  await screen.findByRole('button',{name:'Demo Pi'});
  fireEvent.click(screen.getByRole('button',{name:'Activity',exact:true}));
  expect(screen.getByRole('heading',{name:'Activity',exact:true})).toBeTruthy();
  expect(screen.getByRole('heading',{name:'Recent Activity'})).toBeTruthy();
  expect(screen.getByRole('heading',{name:'Security Digest'})).toBeTruthy();
  fireEvent.click(screen.getByRole('button',{name:'Open Audit Log'}));
  expect(screen.getByRole('dialog',{name:'Audit Log'})).toBeTruthy();
  fireEvent.click(screen.getByRole('button',{name:'Close Audit Log'}));
  expect(screen.queryByRole('dialog')).toBeNull();
});

it('uses one live snapshot instead of separately polling devices, activity, audit and policy', async () => {
  api.dashboard.mockResolvedValue({devices:[device],events:[],audit:[],policy,agent_connected:true});
  render(<App />);
  await waitFor(()=>expect(screen.getByRole('button',{name:'Demo Pi'})).toBeTruthy());
  expect(api.dashboard).toHaveBeenCalledTimes(1);
  expect(api.devices).not.toHaveBeenCalled();
  expect(api.events).not.toHaveBeenCalled();
  expect(api.audit).not.toHaveBeenCalled();
  expect(api.policy).not.toHaveBeenCalled();
});

it('opens the landing page from the logo and returns without signing out', async () => {
  render(<App/>);
  fireEvent.click(await screen.findByRole('button',{name:'CasaWarden Landing Page'}));
  expect(screen.getByRole('heading',{name:/Security for the devices/})).toBeTruthy();
  expect(screen.queryByRole('navigation',{name:'Main navigation'})).toBeNull();
  fireEvent.click(screen.getByRole('button',{name:'Open Dashboard'}));
  expect(await screen.findByRole('navigation',{name:'Main navigation'})).toBeTruthy();
});
