import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { StrictMode } from 'react';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Login } from '../src/components/Login';

const { login, setToken, animate } = vi.hoisted(()=>({login:vi.fn(),setToken:vi.fn(),animate:vi.fn()}));
vi.mock('../src/api/client',()=>({USE_MOCK:false,api:{login},setToken}));
vi.mock('../src/lib/alert',()=>({unlockAudio:vi.fn()}));
vi.mock('gsap',()=>({default:{context:(callback:()=>void)=>{callback();return {revert:vi.fn()};},from:animate}}));
beforeEach(()=>{
  vi.clearAllMocks();
  Object.defineProperty(window,'matchMedia',{configurable:true,value:vi.fn(()=>({matches:false}))});
});
afterEach(cleanup);

it('keeps labeled controls visible without animation progress, including StrictMode remounts',()=>{
  render(<StrictMode><Login onLogin={vi.fn()} /></StrictMode>);
  for(const node of [screen.getByLabelText('Username'),screen.getByLabelText('Password'),screen.getByRole('button',{name:'Sign In'})]) {
    expect(node.hasAttribute('data-login-reveal')).toBe(false);
    for(let ancestor:HTMLElement|null=node;ancestor;ancestor=ancestor.parentElement) {
      expect(ancestor.style.opacity).not.toBe('0');
      expect(ancestor.classList.contains('animate-rise-in')).toBe(false);
    }
  }
  for(const [selector,options] of animate.mock.calls) {
    expect(selector).not.toMatch(/input|button|form|data-login-reveal/);
    expect(options).not.toHaveProperty('opacity');
    expect(options).not.toHaveProperty('autoAlpha');
  }
  expect(screen.getByLabelText('Password').getAttribute('autocomplete')).toBe('current-password');
});

it('retains sign-in, saved credentials support, and visible API errors',async()=>{
  const done=vi.fn();login.mockRejectedValueOnce(new Error('Check your password')).mockResolvedValueOnce({access_token:'test-token'});
  render(<Login onLogin={done} />);
  fireEvent.change(screen.getByLabelText('Username'),{target:{value:'judge'}});
  fireEvent.change(screen.getByLabelText('Password'),{target:{value:'long-test-password'}});
  fireEvent.submit(screen.getByRole('form',{name:'Sign In'}));
  expect(await screen.findByRole('alert')).toHaveProperty('textContent','Check your password');
  await waitFor(()=>expect((screen.getByRole('button',{name:'Sign In'}) as HTMLButtonElement).disabled).toBe(false));
  fireEvent.submit(screen.getByRole('form',{name:'Sign In'}));
  await waitFor(()=>expect(done).toHaveBeenCalledTimes(1));
  expect(login).toHaveBeenLastCalledWith('judge','long-test-password');
  expect(setToken).toHaveBeenCalledWith('test-token');
});
