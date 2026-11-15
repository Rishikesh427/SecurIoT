import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
const animation = vi.hoisted(() => ({ paused:vi.fn(), fromTo:vi.fn(), invalidate:vi.fn(), revert:vi.fn(), timeline:vi.fn(), set:vi.fn() }));
vi.mock('gsap', () => ({ default: {
  context: (callback:()=>void) => { callback(); return {revert:animation.revert}; },
  set:animation.set,
  timeline: (options:unknown) => { animation.timeline(options); return {fromTo:animation.fromTo,paused:animation.paused,invalidate:animation.invalidate}; },
  to:()=>({paused:animation.paused}),
} }));
import { TurtleParade } from '../src/components/TurtleParade';
beforeEach(()=>{
  vi.clearAllMocks();
  vi.stubGlobal('matchMedia',vi.fn(()=>({matches:false,addEventListener:vi.fn(),removeEventListener:vi.fn()})));
  vi.stubGlobal('ResizeObserver',class{observe(){}disconnect(){}});
});
afterEach(()=>{cleanup();vi.unstubAllGlobals();});
it('renders one adult and four distinct younger turtles on a seven-second loop',()=>{
  const view=render(<TurtleParade/>);
  expect(view.container.querySelectorAll('[data-age="adult"]')).toHaveLength(1);
  expect(view.container.querySelectorAll('[data-age="young"]')).toHaveLength(4);
  expect(animation.timeline).toHaveBeenCalledWith(expect.objectContaining({repeat:-1}));
  expect(animation.fromTo).toHaveBeenCalledWith(expect.anything(),expect.objectContaining({x:expect.any(Function)}),expect.objectContaining({duration:7,ease:'none'}));
});
it('has no footer pause button',()=>{render(<TurtleParade/>);expect(screen.queryByRole('button')).toBeNull();});
it('keeps a static family for reduced-motion users',()=>{
  vi.stubGlobal('matchMedia',vi.fn(()=>({matches:true,addEventListener:vi.fn(),removeEventListener:vi.fn()})));
  render(<TurtleParade/>);
  expect(animation.timeline).not.toHaveBeenCalled();
  expect(screen.queryByRole('button')).toBeNull();
  expect(animation.set).toHaveBeenCalled();
});
