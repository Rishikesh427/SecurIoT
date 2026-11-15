import { afterEach, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { Bandwidth } from '../src/components/Bandwidth';
import type { Device } from '../src/types';
afterEach(cleanup);
it('separates device rates and switches detail charts without new requests',()=>{
  HTMLDialogElement.prototype.showModal=function(){this.setAttribute('open','');};
  HTMLDialogElement.prototype.close=function(){this.removeAttribute('open');};
  const devices=[{mac:'a',label:'Kitchen Speaker',status:'normal',simulated:false},{mac:'b',label:'Guest Phone',status:'normal',simulated:false}] as Device[];
  render(<Bandwidth devices={devices} traffic={{byMac:{a:[100,200],b:[400,300]},total:[500,500]}}/>);
  expect(screen.getByRole('button',{name:'Open Traffic for Kitchen Speaker'}).textContent).toContain('200 B/s');
  expect(screen.getByRole('button',{name:'Open Traffic for Guest Phone'}).textContent).toContain('300 B/s');
  fireEvent.click(screen.getByRole('button',{name:'Open Traffic for Kitchen Speaker'}));
  expect(screen.getByRole('img',{name:'Recent observed traffic for Kitchen Speaker'})).toBeTruthy();
  fireEvent.click(screen.getByRole('button',{name:'Guest Phone',exact:true}));
  expect(screen.getByRole('img',{name:'Recent observed traffic for Guest Phone'})).toBeTruthy();
  expect(screen.getByRole('button',{name:'Guest Phone',exact:true}).getAttribute('aria-pressed')).toBe('true');
});
