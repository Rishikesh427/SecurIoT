import { useEffect, useState } from 'react';
import { api, USE_MOCK } from '../api/client';
import type { PublicResearchResult } from '../types';

export function PublicResearch({ mac }: { mac: string }) {
  const [result,setResult]=useState<PublicResearchResult|null>(null);
  const [error,setError]=useState('');
  useEffect(()=>{
    if(result?.status!=='pending') return;
    let stopped=false;
    const timer=setTimeout(()=>{
      api.researchStatus(mac).then(value=>{if(!stopped)setResult(value);}).catch(()=>{if(!stopped){setError('Research could not be checked. Try again.');setResult(null);}});
    },2000);
    return()=>{stopped=true;clearTimeout(timer);};
  },[result,mac]);
  useEffect(()=>{
    if(USE_MOCK) return;
    let stopped=false;
    setResult({status:'pending',source:'rules'});
    api.researchStatus(mac).then(value=>{
      if(stopped)return;
      if(value.status==='idle') return api.research(mac).then(next=>{if(!stopped)setResult(next);});
      setResult(value);
    }).catch(()=>{if(!stopped){setResult(null);setError('Supporting details are unavailable.');}});
    return()=>{stopped=true;};
  },[mac]);
  return <section className="space-y-3 rounded-xl bg-fill p-4">
    <div className="flex items-center justify-between gap-3"><h3 className="font-semibold">Supporting Details</h3><span className="text-sm text-ink-3">{result?.status==='pending'?'Checking documentation…':result?.status==='ready'?'Source: Gemini':''}</span></div>
    {error&&<p role="alert">{error}</p>}
    {result?.status==='needs_identity'&&<p>Check the device label for its model so advice can be more specific.</p>}
    {result?.status==='unavailable'&&<p role="alert">Research unavailable: {result.reason?.replace(/_/g,' ')}. Recorded facts remain unchanged.</p>}
    {result?.status==='ready'&&<>
      <p className="whitespace-pre-wrap text-sm leading-relaxed">{result.summary}</p>
      <ul className="list-disc space-y-1 pl-5 text-sm">{result.sources?.map(source=><li key={source.url}><a className="underline" href={source.url} target="_blank" rel="noopener noreferrer">{source.title}</a></li>)}</ul>
      <p className="text-sm text-ink-3">{result.note}</p>
      {result.search_suggestions&&<iframe title="Google Search Suggestions" sandbox="allow-popups allow-popups-to-escape-sandbox" referrerPolicy="no-referrer" className="h-24 w-full border-0" srcDoc={'<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; img-src https://www.google.com https://www.gstatic.com; base-uri \'none\'; form-action \'none\'">'+result.search_suggestions}/>}
    </>}
  </section>;
}
