import { useEffect, useRef, type ReactNode } from 'react';
import { createPortal } from 'react-dom';

let scrollLocks=0;
let originalOverflow='';

/** Native modal sheet: labeled, focus contained, nested-dialog safe. */
export function SidePanel({label,onClose,wide=false,children}:{label:string;onClose:()=>void;wide?:boolean;children:ReactNode}) {
  const ref=useRef<HTMLDialogElement>(null);
  useEffect(()=>{
    const dialog=ref.current!;
    const previous=document.activeElement as HTMLElement|null;
    if(scrollLocks++===0){originalOverflow=document.body.style.overflow;document.body.style.overflow='hidden';}
    if(dialog.showModal)dialog.showModal();else dialog.setAttribute('open','');
    const first=dialog.querySelector<HTMLElement>('[data-panel-close]') ?? dialog.querySelector<HTMLElement>('button:not(:disabled),input:not(:disabled),select:not(:disabled),[tabindex="0"]');
    first?.focus();
    return()=>{
      if(dialog.close)dialog.close();else dialog.removeAttribute('open');
      if(--scrollLocks===0)document.body.style.overflow=originalOverflow;
      if(previous?.isConnected)previous.focus();
    };
  },[]);
  return createPortal(<dialog ref={ref} aria-label={label} aria-modal="true"
    className="side-panel-root fixed inset-0 m-0 h-[100dvh] max-h-none w-screen max-w-none border-0 bg-transparent p-0 text-ink"
    onCancel={event=>{if(event.target!==event.currentTarget)return;event.preventDefault();onClose();}}
    onKeyDown={event=>{
      if((event.target as HTMLElement).closest('dialog')!==event.currentTarget)return;
      if(event.key==='Escape'){event.preventDefault();event.stopPropagation();onClose();return;}
      if(event.key!=='Tab')return;
      const controls=Array.from(event.currentTarget.querySelectorAll<HTMLElement>('button:not(:disabled),input:not(:disabled),select:not(:disabled),textarea:not(:disabled),a[href],[tabindex="0"]'))
        .filter(node=>!node.closest('[hidden]')&&getComputedStyle(node).display!=='none'&&getComputedStyle(node).visibility!=='hidden');
      const first=controls[0],last=controls.at(-1);
      if(!event.currentTarget.contains(document.activeElement)){event.preventDefault();(event.shiftKey?last:first)?.focus();}
      else if(event.shiftKey&&document.activeElement===first){event.preventDefault();last?.focus();}
      else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first?.focus();}
    }}>
    <div className="relative flex h-full justify-end">
      <div aria-hidden="true" className="side-panel-scrim absolute inset-0" onClick={onClose}/>
      <aside className={`side-panel relative flex h-full w-full ${wide?'max-w-[640px]':'max-w-[480px]'} animate-sheet-in flex-col overflow-y-auto shadow-2xl`}>{children}</aside>
    </div>
  </dialog>,document.body);
}
