import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { ActivityList } from '../src/components/ActivityList';
import { DeviceAdvisor } from '../src/components/Advisor';
import { Bandwidth } from '../src/components/Bandwidth';
import type { Device, SecurEvent } from '../src/types';
vi.mock('../src/api/client',()=>({USE_MOCK:false,api:{research:vi.fn(),researchStatus:vi.fn().mockResolvedValue({status:"unavailable",source:"rules"}),advisorChat:vi.fn()}}));
afterEach(cleanup);
const device={mac:'m',name:'camera',label:'A very long complete device name for the living room',type:'camera',risk:75,band:'high',reasons:[]} as Device;
it('displays the complement of risk without changing the stored risk',()=>{
  render(<DeviceAdvisor device={device}/>);
  expect(screen.getByLabelText('Device Score').textContent).toBe('25');
  expect(device.risk).toBe(75);
});
it('caps activity at ten rows and expands full names independently',()=>{
  const events=Array.from({length:11},(_,i)=>({id:String(i),mac:'m',ts:new Date().toISOString(),kind:'new_device',evidence:{},actions_taken:[],would_have:[],source:'agent'})) as SecurEvent[];
  render(<ActivityList devices={[device]} events={events} onSelect={vi.fn()}/>);
  expect(screen.getAllByRole('button',{name:'Show Full Device Name'})).toHaveLength(10);
  fireEvent.click(screen.getAllByRole('button',{name:'Show Full Device Name'})[0]);
  expect(screen.getByRole('button',{name:'Collapse Full Device Name'}).getAttribute('aria-expanded')).toBe('true');
  fireEvent.click(screen.getByRole('button',{name:'Show More'}));
  expect(screen.getAllByText(device.label)).toHaveLength(11);
  expect(screen.queryByRole('button',{name:'Show More'})).toBeNull();
});
it('opens detailed observed bandwidth without treating it as line capacity',()=>{
  HTMLDialogElement.prototype.showModal=function(){this.setAttribute('open','');};
  HTMLDialogElement.prototype.close=function(){this.removeAttribute('open');};
  render(<Bandwidth traffic={{byMac:{},total:[100,200,500]}}/>);
  fireEvent.click(screen.getByRole('button',{name:'Open Bandwidth Details'}));
  expect(screen.getByRole('dialog',{name:'Bandwidth'})).toBeTruthy();
  expect(screen.getByRole('img',{name:'Recent observed traffic in bytes per second'})).toBeTruthy();
});
