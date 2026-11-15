import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
const css = readFileSync(resolve(process.cwd(), 'src/index.css'), 'utf8');
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { FixSheet } from '../src/components/FixSheet';
import type { Issue } from '../src/lib/issues';

beforeEach(()=>{
  HTMLDialogElement.prototype.showModal=function(){this.setAttribute('open','');};
  HTMLDialogElement.prototype.close=function(){this.removeAttribute('open');};
});
afterEach(()=>{cleanup();document.documentElement.removeAttribute('data-theme');});
const issue={id:'x',severity:'critical',title:'Device Was Cut Off',summary:'Access is restricted.',why:'Review the recorded action.',steps:['Check device settings.'],technical:['Local action']} as Issue;

it('provides a named dark-mode modal, wraps focus, closes with Escape and restores focus',()=>{
  document.documentElement.dataset.theme='dark';
  const opener=document.createElement('button');opener.textContent='Open guide';document.body.append(opener);opener.focus();
  const close=vi.fn();
  const view=render(<FixSheet issue={issue} busy={false} onClose={close} onAction={vi.fn()} onDone={vi.fn()}/>);
  expect(screen.getByRole('dialog',{name:'Protection Guide'}).getAttribute('aria-modal')).toBe('true');
  expect(document.body.style.overflow).toBe('hidden');
  const first=screen.getByRole('button',{name:'Done'});
  const last=screen.getByRole('button',{name:'Technical Details'});
  last.focus();fireEvent.keyDown(last,{key:'Tab'});expect(document.activeElement).toBe(first);
  fireEvent.keyDown(first,{key:'Tab',shiftKey:true});expect(document.activeElement).toBe(last);
  fireEvent.keyDown(last,{key:'Escape'});expect(close).toHaveBeenCalledTimes(1);
  view.unmount();expect(document.activeElement).toBe(opener);expect(document.body.style.overflow).not.toBe('hidden');
  opener.remove();
});

function tokens(dark:boolean){
  const values:Record<string,string>={};
  for(const match of css.matchAll(/(:root|\[data-theme="dark"\])\s*\{([^}]*)\}/g)) {
    if(match[1]!==':root'&&!dark)continue;
    for(const variable of match[2].matchAll(/--([\w-]+)\s*:\s*([^;]+);/g))values[variable[1]]=variable[2].trim();
  }
  return values;
}
function rgb(hex:string){let value=hex.replace('#','');if(value.length===3)value=value.split('').map(c=>c+c).join('');return [0,2,4].map(i=>parseInt(value.slice(i,i+2),16));}
function contrast(a:number[],b:number[]){
  const lum=(v:number[])=>v.map(c=>{const s=c/255;return s<=.04045?s/12.92:((s+.055)/1.055)**2.4;}).reduce((sum,c,i)=>sum+c*[.2126,.7152,.0722][i],0);
  const x=lum(a),y=lum(b);return (Math.max(x,y)+.05)/(Math.min(x,y)+.05);
}
for(const dark of [false,true])it(`checks normal-text contrast and control borders in ${dark?'dark':'light'} theme`,()=>{
  const t=tokens(dark);
  for(const surface of ['sheet-bg','sheet-card']){
    for(const ink of ['color-ink','color-ink-2','color-ink-3','color-bad','color-warn','color-ok'])expect(contrast(rgb(t[ink]),rgb(t[surface])),`${ink} on ${surface}`).toBeGreaterThanOrEqual(4.5);
    expect(contrast(rgb(t['control-border']),rgb(t[surface]))).toBeGreaterThanOrEqual(3);
    for(const severity of ['critical','high','medium','low']){
      const foreground=rgb(t[`color-sev-${severity}`]),base=rgb(t[surface]);
      const tint=foreground.map((v,i)=>v*.1+base[i]*.9);
      expect(contrast(foreground,tint),severity).toBeGreaterThanOrEqual(4.5);
    }
  }
  for(const kind of ['primary','danger'])for(const state of ['bg','hover'])expect(contrast(rgb(t[`control-${kind}-fg`]),rgb(t[`control-${kind}-${state}`]))).toBeGreaterThanOrEqual(4.5);
  expect(contrast(rgb(t['sheet-notice-fg']),rgb(t['sheet-notice-bg']))).toBeGreaterThanOrEqual(4.5);
});
