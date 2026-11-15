import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { Heatmap } from '../src/components/Heatmap';
import { HomeMap } from '../src/components/HomeMap';
import { ActivityList } from '../src/components/ActivityList';
import type { DashDevice, SecurEvent } from '../src/types';
vi.mock('../src/components/NetworkMap',()=>({default:()=> <div>Network Preview</div>}));
beforeEach(()=>{
  Object.defineProperty(window,'matchMedia',{configurable:true,value:vi.fn(()=>({matches:true}))});
});
afterEach(cleanup);
const device={mac:'02:00:00:00:00:01',name:'Guest phone with a long complete name',label:'Guest phone with a long complete name',status:'normal'} as DashDevice;

it('uses the selected interval caption and displays full heatmap names without plus controls',()=>{
  render(<Heatmap devices={[device]} events={[]} now={Date.now()}/>);
  expect(screen.getByText('Each square is five minutes.')).toBeTruthy();
  expect(screen.getByText(device.label)).toBeTruthy();
  expect(screen.queryByRole('button',{name:/Full Device Name/})).toBeNull();
  fireEvent.click(screen.getByRole('button',{name:'1 min'}));
  expect(screen.getByText('Each square is one minute.')).toBeTruthy();
  fireEvent.click(screen.getByRole('button',{name:'1 hour'}));
  expect(screen.getByText('Each square is one hour.')).toBeTruthy();
});

it('places bandwidth with the map and supports keyboard adjustment and reset',async()=>{
  render(<HomeMap devices={[]} rates={{}} groups={{safe:0,caution:0,danger:0}} issueCounts={{}} theme="light" onSelect={vi.fn()} controls={<button>Arm</button>} status="Connected" bandwidth={<button>Traffic Details</button>}/>);
  const map=await screen.findByText('Network Preview');
  const section=screen.getByRole('region',{name:'Network Map and Bandwidth'});
  expect(section.contains(map)).toBe(true);
  expect(section.contains(screen.getByRole('button',{name:'Traffic Details'}))).toBe(true);
  const divider=screen.getByRole('separator',{name:'Adjust Map and Bandwidth Panels'});
  expect(divider.parentElement).toBe(screen.getByRole('complementary',{name:'Observed Bandwidth'}).parentElement);
  expect(divider.getAttribute('aria-valuenow')).toBe('240');
  fireEvent.keyDown(divider,{key:'ArrowLeft'});
  expect(divider.getAttribute('aria-valuenow')).toBe('260');
  fireEvent.keyDown(divider,{key:'End'});
  expect(divider.getAttribute('aria-valuenow')).toBe('360');
  fireEvent.doubleClick(divider);
  expect(divider.getAttribute('aria-valuenow')).toBe('240');
});

it('keeps actual enforcement outcomes while omitting empty action summaries',()=>{
  const base={mac:device.mac,ts:new Date().toISOString(),kind:'new_device',evidence:{},would_have:[],source:'agent'};
  const events=[{...base,id:'plain',actions_taken:[]},{...base,id:'blocked',actions_taken:['block_wan']} ] as SecurEvent[];
  render(<ActivityList devices={[device]} events={events} onSelect={vi.fn()}/>);
  expect(screen.queryByText('No action recorded')).toBeNull();
  expect(screen.getByText('Reported actions: Block internet')).toBeTruthy();
});

it('coalesces pointer movement into one animation frame before committing width',async()=>{
  render(<HomeMap devices={[]} rates={{}} groups={{safe:0,caution:0,danger:0}} issueCounts={{}} theme="light" onSelect={vi.fn()} controls={null} status="Connected" bandwidth={<span>Traffic</span>}/>);
  await screen.findByText('Network Preview');
  const region=screen.getByRole('region',{name:'Network Map and Bandwidth'});
  vi.spyOn(region,'getBoundingClientRect').mockReturnValue({right:1000} as DOMRect);
  const divider=screen.getByRole('separator',{name:'Adjust Map and Bandwidth Panels'});
  Object.defineProperty(divider,'setPointerCapture',{value:vi.fn(),configurable:true});
  const callbacks: FrameRequestCallback[]=[];
  const raf=vi.spyOn(window,'requestAnimationFrame').mockImplementation(callback=>{callbacks.push(callback);return callbacks.length;});
  const cancel=vi.spyOn(window,'cancelAnimationFrame').mockImplementation(()=>{});
  const dispatch=(type:string,x:number)=>{const event=new Event(type,{bubbles:true});Object.assign(event,{pointerId:1,button:0,clientX:x});fireEvent(divider,event);};
  try {
    dispatch('pointerdown',740);
    dispatch('pointermove',730);
    dispatch('pointermove',690);
    expect(callbacks).toHaveLength(1);
    callbacks[0](0);
    expect(region.style.getPropertyValue('--bandwidth-panel-width')).toBe('290px');
    dispatch('pointerup',690);
    expect(divider.getAttribute('aria-valuenow')).toBe('290');
  } finally {raf.mockRestore();cancel.mockRestore();}
});
