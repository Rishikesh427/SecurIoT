import { useState } from 'react';
import type { Traffic } from '../hooks/useTraffic';
import { rate } from '../hooks/useTraffic';
import { Sparkline } from './Sparkline';
import { Modal } from './Modal';

export function Bandwidth({ traffic }: { traffic: Traffic }) {
  const [open,setOpen]=useState(false);
  const values=traffic.total;
  const current=values.at(-1)??0;
  const peak=Math.max(0,...values);
  const average=values.length?values.reduce((a,b)=>a+b,0)/values.length:0;
  return <>
    <button type="button" aria-label="Open Bandwidth Details" onClick={()=>setOpen(true)} className="flex items-center gap-4 rounded-xl bg-fill px-4 py-3 text-left transition-transform hover:scale-[1.02]">
      <span><span className="block text-sm text-ink-3">Observed Traffic</span><strong className="tabular-nums">{rate(current)}</strong></span><Sparkline data={values} width={100} height={32} color="var(--color-ink)"/>
    </button>
    {open&&<Modal title="Bandwidth" onClose={()=>setOpen(false)}><div className="space-y-5">
      <div className="flex flex-wrap gap-6"><p>Now <strong>{rate(current)}</strong></p><p>Peak <strong>{rate(peak)}</strong></p><p>Average <strong>{rate(average)}</strong></p></div>
      <svg viewBox="0 0 600 180" role="img" aria-label="Recent observed traffic in bytes per second" className="w-full overflow-visible">
        <path d="M20 10V155H590" fill="none" stroke="currentColor" opacity=".2"/>
        <polyline points={values.map((v,i)=>`${20+i/Math.max(1,values.length-1)*570},${150-v/Math.max(1,peak)*135}`).join(' ')} fill="none" stroke="currentColor" strokeWidth="3"/>
        <text x="20" y="177" fontSize="12" fill="currentColor">Earlier</text><text x="555" y="177" fontSize="12" fill="currentColor">Now</text>
      </svg>
      <p className="text-sm text-ink-3">Incoming plus outgoing traffic seen by the agent, sampled from counter updates. This is not a measurement of your internet plan's capacity.</p>
    </div></Modal>}
  </>;
}
