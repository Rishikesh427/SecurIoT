import { useState } from 'react';
import { ChevronDown } from 'lucide-react';
import { clock, eventMeta, severityDot } from '../lib/format';
import { plainEvent } from '../lib/plain';
import type { Device, SecurEvent } from '../types';
import { Card } from './ui';
import { WhyAlert } from './WhyAlert';
import { eventOutcome, outcomeSummary } from '../lib/eventDetails';

export function ActivityList({events,devices,onSelect,limit=5}:{events:SecurEvent[];devices:Device[];onSelect:(mac:string)=>void;limit?:number}) {
  const [open,setOpen]=useState<string|null>(null);
  const [visible,setVisible]=useState(limit);
  const name=(mac:string)=>devices.find(d=>d.mac===mac)?.label||devices.find(d=>d.mac===mac)?.name||mac;
  return <Card className="overflow-hidden">
    {!events.length?<p className="px-5 py-8 text-center">No activity yet.</p>:<ol className="divide-y divide-hairline">{events.slice(0,visible).map(event=>{
      const meta=eventMeta[event.kind]??{severity:'info' as const}; const expanded=open===event.id;
      return <li key={event.id} className="animate-fade-in">
        <div className="px-5 pt-4"><span className="block break-words font-medium">{name(event.mac)}</span></div>
        <button onClick={()=>setOpen(expanded?null:event.id)} aria-expanded={expanded} className="flex w-full items-start gap-3 px-5 py-3 text-left hover:bg-fill/70">
          <span className={`mt-2 h-2 w-2 shrink-0 rounded-full ${severityDot[meta.severity]}`}/>
          <div className="min-w-0 flex-1"><div className="flex flex-wrap justify-between gap-2"><span>{plainEvent(event)}</span><time className="text-sm text-ink-3">{clock(event.ts)}</time></div>{eventOutcome(event)!=="no_action"&&<p className="mt-1 text-sm text-ink-3">{outcomeSummary(event)}</p>}</div>
          <ChevronDown size={16} className={expanded?'rotate-180':''}/>
        </button>
        {expanded&&<div className="px-5 pb-4"><WhyAlert event={event}/><button onClick={()=>onSelect(event.mac)} className="mt-2 underline">View Device</button></div>}
      </li>;
    })}</ol>}
    {events.length>visible&&<button className="w-full px-5 py-4 font-medium hover:bg-fill" onClick={()=>setVisible(value=>value+5)}>Show More</button>}
  </Card>;
}
