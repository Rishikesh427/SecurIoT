import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { act, cleanup, render } from '@testing-library/react';
import type { DashDevice } from '../src/types';
const state = vi.hoisted(() => ({ handlers: {} as Record<string, (event: unknown) => void>, nodes: new Map<string, any>(), options: null as any }));
vi.mock('cytoscape', () => ({ default: (options: any) => {
  state.options = options;
  function makeNode(id: string, present = true, classes = '') {
    const tags = new Set(classes.split(' ').filter(Boolean));
    const node: any = { id: () => id, nonempty: () => present, grabbed: () => false, animated: () => false,
      hasClass: (name: string) => tags.has(name), addClass: (name: string) => { tags.add(name); return node; },
      remove: vi.fn(() => { state.nodes.delete(id); return node; }),
      ungrabify: vi.fn(), stop: vi.fn(), position: vi.fn(() => ({ x: 100, y: 100 })), style: vi.fn(), data: vi.fn(), animate: vi.fn(), classes: vi.fn() };
    for (const key of ['stop','style','data','animate','classes']) node[key].mockReturnValue(node);
    return node;
  }
  state.nodes.set('router', makeNode('router'));
  const collection = (items: any[]): any => ({ not: () => collection(items.filter(n => n.id() !== 'router')),
    map: (fn: any) => items.map(fn), forEach: (fn: any) => items.forEach(fn),
    filter: (fn: any) => collection(items.filter(fn)), remove: () => items.forEach(n => state.nodes.delete(n.id())), stop: vi.fn() });
  return { on: (type: string, _selector: string, handler: any) => { state.handlers[type] = handler; },
    getElementById: (id: string) => state.nodes.get(id) ?? makeNode(id, false),
    nodes: () => collection([...state.nodes.values()]), edges: () => ({ style: vi.fn() }),
    add: (definition: any) => { const node = makeNode(definition.data.id, true, definition.classes); state.nodes.set(definition.data.id, node); return node; },
    resize: vi.fn(), destroy: vi.fn() };
} }));
import NetworkMap, { mapPositions } from '../src/components/NetworkMap';
const device = { mac:'02:00:00:00:00:01', label:'Camera', risk:75, risk_adjusted:80, band:'high', status:'normal' } as DashDevice;
beforeEach(() => {
  state.handlers = {}; state.nodes.clear();
  vi.stubGlobal('matchMedia', vi.fn(() => ({ matches:false, addEventListener:vi.fn(), removeEventListener:vi.fn() })));
  vi.stubGlobal('ResizeObserver', class { observe() {} disconnect() {} });
  vi.stubGlobal('requestAnimationFrame', vi.fn(() => 1));
  vi.stubGlobal('cancelAnimationFrame', vi.fn());
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
it('allows dragging and springs back to a stable anchor without opening device details', () => {
  const select=vi.fn();
  render(<NetworkMap devices={[device]} rates={{}} issueCounts={{[device.mac]:3}} onSelect={select} />);
  const node=state.nodes.get(device.mac);
  node.animate.mockClear();
  act(() => { state.handlers.drag({target:node}); state.handlers.dragfree({target:node}); state.handlers.tap({target:node}); });
  expect(state.options.autoungrabify).toBe(false);
  expect(node.animate).toHaveBeenCalledWith(expect.objectContaining({position:expect.any(Object)}), expect.objectContaining({duration:650,easing:'spring(350, 24)'}));
  expect(select).not.toHaveBeenCalled();
});
it('uses the issue count in its badge, not the risk score', () => {
  const view=render(<NetworkMap devices={[device]} rates={{}} issueCounts={{[device.mac]:3}} onSelect={vi.fn()} />);
  view.rerender(<NetworkMap devices={[device]} rates={{}} issueCounts={{[device.mac]:4}} onSelect={vi.fn()} />);
  const data=state.nodes.get(device.mac).data.mock.calls.at(-1)[0];
  expect(decodeURIComponent(data.badge)).toContain('>4</text>');
  expect(decodeURIComponent(data.badge)).not.toContain('>75</text>');
});
it('snaps without animation for reduced-motion users', () => {
  vi.stubGlobal('matchMedia', vi.fn(() => ({ matches:true, addEventListener:vi.fn(), removeEventListener:vi.fn() })));
  render(<NetworkMap devices={[device]} rates={{}} issueCounts={{}} onSelect={vi.fn()} />);
  const node=state.nodes.get(device.mac); node.animate.mockClear();
  act(() => state.handlers.dragfree({target:node}));
  expect(node.position).toHaveBeenCalled();
  expect(node.animate).not.toHaveBeenCalled();
});
it('uses stable device positions independent of input ordering', () => {
  expect(mapPositions(['b','a'],800,500)).toEqual(mapPositions(['a','b'],800,500));
});

it('pops a disconnected device like a balloon: inflate, burst into particles, then remove', () => {
  const view = render(<NetworkMap devices={[device]} rates={{}} issueCounts={{}} onSelect={vi.fn()} />);
  const node = state.nodes.get(device.mac); node.animate.mockClear();
  view.rerender(<NetworkMap devices={[{ ...device, status: 'offline' }]} rates={{}} issueCounts={{}} onSelect={vi.fn()} />);
  expect(node.hasClass('popping')).toBe(true);
  const [inflate, timing] = node.animate.mock.calls[0];
  expect(inflate.style).toEqual({ width: 74, height: 74 });
  act(() => timing.complete());
  const particles = [...state.nodes.values()].filter(n => n.hasClass('particle'));
  expect(particles).toHaveLength(14);
  const [shrink, shrinkTiming] = node.animate.mock.calls[1];
  expect(shrink.style).toEqual(expect.objectContaining({ width: 2, height: 2, opacity: 0 }));
  act(() => shrinkTiming.complete());
  expect(node.remove).toHaveBeenCalled();
  expect(state.nodes.has(device.mac)).toBe(false);
});
it('removes a disconnected device immediately for reduced-motion users', () => {
  vi.stubGlobal('matchMedia', vi.fn(() => ({ matches:true, addEventListener:vi.fn(), removeEventListener:vi.fn() })));
  const view = render(<NetworkMap devices={[device]} rates={{}} issueCounts={{}} onSelect={vi.fn()} />);
  view.rerender(<NetworkMap devices={[{ ...device, status: 'offline' }]} rates={{}} issueCounts={{}} onSelect={vi.fn()} />);
  expect(state.nodes.has(device.mac)).toBe(false);
  expect([...state.nodes.values()].some(n => n.hasClass('particle'))).toBe(false);
});
it('keeps a quarantined device on the map and brings a reconnected device back', () => {
  const view = render(<NetworkMap devices={[{ ...device, status: 'quarantined' }]} rates={{}} issueCounts={{}} onSelect={vi.fn()} />);
  expect(state.nodes.get(device.mac).hasClass('popping')).toBe(false);
  view.rerender(<NetworkMap devices={[{ ...device, status: 'offline' }]} rates={{}} issueCounts={{}} onSelect={vi.fn()} />);
  view.rerender(<NetworkMap devices={[device]} rates={{}} issueCounts={{}} onSelect={vi.fn()} />);
  const back = state.nodes.get(device.mac);
  expect(back).toBeDefined();
  expect(back.hasClass('popping')).toBe(false);
});
it('adds a gentle device hover emphasis and restores the original circle size', () => {
  render(<NetworkMap devices={[device]} rates={{}} issueCounts={{}} onSelect={vi.fn()} />);
  const node=state.nodes.get(device.mac); node.style.mockClear();
  act(()=>state.handlers.mouseover({target:node}));
  expect(node.style).toHaveBeenCalledWith(expect.objectContaining({width:64,height:64}));
  act(()=>state.handlers.mouseout({target:node}));
  expect(node.style).toHaveBeenCalledWith(expect.objectContaining({width:56,height:56}));
});
