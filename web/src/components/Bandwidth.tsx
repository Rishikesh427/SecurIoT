import { useState } from 'react';
import type { Device } from '../types';
import type { Traffic } from '../hooks/useTraffic';
import { rate } from '../hooks/useTraffic';
import { Sparkline } from './Sparkline';
import { Modal } from './Modal';

function trend(values: number[]) {
  const current=values.at(-1)??0, previous=values.at(-2)??current;
  if(current===previous)return '—';
  if(previous===0)return '↑ New';
  return `${current>previous?'↑':'↓'} ${Math.abs((current-previous)/previous*100).toFixed(0)}%`;
}

export function Bandwidth({ traffic, devices=[] }: { traffic: Traffic; devices?: Device[] }) {
  const [open,setOpen]=useState(false);
  const [selected,setSelected]=useState<string|null>(null);
  const rows=devices.length
    ? devices.filter(d=>!d.simulated&&d.status!=='offline').map(d=>({mac:d.mac,name:d.label||d.name||d.mac,values:traffic.byMac[d.mac]??[]}))
    : Object.entries(traffic.byMac).map(([mac,values])=>({mac,name:mac,values}));
  const device=selected ? rows.find(row=>row.mac===selected) ?? {mac:selected,name:devices.find(d=>d.mac===selected)?.label||devices.find(d=>d.mac===selected)?.name||selected,values:traffic.byMac[selected]??[]} : undefined;
  const values=selected?(traffic.byMac[selected]??[]):traffic.total;
  const current=values.at(-1)??0;
  const peak=Math.max(0,...values);
  const average=values.length?values.reduce((a,b)=>a+b,0)/values.length:0;
  function show(mac: string|null){setSelected(mac);setOpen(true);}
  return <>
    <section aria-label="Observed Traffic by Device" className="overflow-hidden rounded-xl bg-fill">
      <button type="button" aria-label="Open Bandwidth Details" onClick={()=>show(null)} className="flex w-full min-w-0 items-center justify-between gap-3 px-4 py-3 text-left hover:bg-fill-2">
        <span className="text-sm font-medium text-ink-3">Observed Traffic</span><strong className="whitespace-nowrap tabular-nums">{rate(traffic.total.at(-1)??0)}</strong>
      </button>
      <div className="max-h-[340px] overflow-y-auto divide-y divide-hairline">
        {rows.map(row=><button key={row.mac} type="button" aria-label={`Open Traffic for ${row.name}`} onClick={()=>show(row.mac)} className="block w-full px-4 py-3 text-left hover:bg-fill-2">
          <span className="mb-2 block truncate text-sm font-medium" title={row.name}>{row.name}</span>
          <span className="flex items-center justify-between gap-3">
            <span className="min-w-0 flex-1 [&_svg]:w-full"><Sparkline data={row.values} width={120} height={30} color="var(--color-ink)"/></span>
            <span className="shrink-0 text-right"><strong className="block whitespace-nowrap text-sm tabular-nums">{rate(row.values.at(-1)??0)}</strong><span className="block text-xs tabular-nums text-ink-3" aria-label={`Change from previous sample: ${trend(row.values)}`}>{trend(row.values)}</span></span>
          </span>
        </button>)}
        {!rows.length&&<p className="px-4 pb-4 text-sm text-ink-3">Waiting for device traffic.</p>}
      </div>
    </section>
    {open&&<Modal title={device?`${device.name} Traffic`:'Bandwidth'} onClose={()=>setOpen(false)}><div className="space-y-5">
      <div className="flex flex-wrap gap-6"><p>Now <strong>{rate(current)}</strong></p><p>Peak <strong>{rate(peak)}</strong></p><p>Average <strong>{rate(average)}</strong></p></div>
      <svg viewBox="0 0 600 180" role="img" aria-label={device?`Recent observed traffic for ${device.name}`:'Recent observed traffic in bytes per second'} className="w-full overflow-visible">
        <path d="M20 10V155H590" fill="none" stroke="currentColor" opacity=".2"/>
        <polyline points={values.map((v,i)=>`${20+i/Math.max(1,values.length-1)*570},${150-v/Math.max(1,peak)*135}`).join(' ')} fill="none" stroke="currentColor" strokeWidth="3"/>
        <text x="20" y="177" fontSize="12" fill="currentColor">Earlier</text><text x="555" y="177" fontSize="12" fill="currentColor">Now</text>
      </svg>
      {rows.length>0&&<div className="flex flex-wrap gap-2" aria-label="Choose Traffic Chart">
        <button type="button" aria-pressed={selected===null} onClick={()=>setSelected(null)} className="rounded-lg border border-hairline px-3 py-2 text-sm">All Devices</button>
        {rows.map(row=><button key={row.mac} type="button" aria-pressed={selected===row.mac} onClick={()=>setSelected(row.mac)} className="rounded-lg border border-hairline px-3 py-2 text-sm">{row.name}</button>)}
      </div>}
      <p className="text-sm text-ink-3">Incoming plus outgoing traffic seen by the agent. Arrows compare the last two samples. This is not a measurement of your internet plan's capacity.</p>
    </div></Modal>}
  </>;
}
