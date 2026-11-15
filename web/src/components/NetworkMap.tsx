import { useEffect, useRef } from 'react';
import cytoscape, { type Core, type NodeSingular } from 'cytoscape';
import { shortLabel } from '../lib/format';
import type { DashDevice } from '../types';

const COLORS = { low: '#28a745', medium: '#c77700', high: '#e5332a' } as const;
const uri = (svg: string) => `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
const css = (name: string, fallback: string) => getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;

export function mapPositions(macs: string[], width: number, height: number) {
  const radius = Math.max(80, Math.min(width, height) * .32);
  return Object.fromEntries([...macs].sort().map((mac, index, all) => {
    const angle = -Math.PI / 2 + index / Math.max(1, all.length) * Math.PI * 2;
    return [mac, { x: width / 2 + radius * Math.cos(angle), y: height / 2 + radius * Math.sin(angle) }];
  }));
}

export default function NetworkMap({ devices, rates, issueCounts = {}, onSelect }: {
  devices: DashDevice[]; rates: Record<string, number>; issueCounts?: Record<string, number>; onSelect: (mac: string) => void;
}) {
  const box = useRef<HTMLDivElement>(null);
  const graph = useRef<Core | null>(null);
  const select = useRef(onSelect); select.current = onSelect;
  const anchors = useRef<Record<string, { x: number; y: number }>>({});
  const draggedAt = useRef(0);
  const reduced = useRef(false);

  useEffect(() => {
    const element = box.current!;
    const ink = css('--color-ink', '#000');
    const background = css('--color-white', '#fff');
    const line = css('--color-ink-3', '#6b6b70');
    const preference = matchMedia('(prefers-reduced-motion: reduce)');
    reduced.current = preference.matches;
    const cy = cytoscape({
      container: element, layout: { name: 'preset', fit: false },
      elements: [{ data: { id: 'router', label: 'Router' }, classes: 'router', position: { x: element.clientWidth / 2, y: element.clientHeight / 2 } }],
      zoom: 1, minZoom: 1, maxZoom: 1, userZoomingEnabled: false, userPanningEnabled: false,
      boxSelectionEnabled: false, autoungrabify: false,
      style: [
        { selector: 'node', style: {
          width: 56, height: 56, 'background-color': background, 'background-image': 'data(badge)', 'background-fit': 'contain',
          'border-width': 3, 'border-color': 'data(color)', label: 'data(label)',
          'text-valign': 'top', 'text-halign': 'center', 'text-margin-y': -14,
          'font-size': 16, 'font-family': '-apple-system, Helvetica, Arial, sans-serif', 'font-weight': 600,
          'text-wrap': 'wrap', 'text-max-width': '170px', color: ink,
          'text-background-color': background, 'text-background-opacity': 1, 'text-background-padding': '5px',
          'z-index': 10, 'overlay-opacity': 0,
          'transition-property': 'width, height, border-width', 'transition-duration': reduced.current ? 0 : .18,
        } as cytoscape.Css.Node },
        { selector: 'node.router', style: { width: 68, height: 68, 'background-color': ink, 'border-width': 0,
          'background-image': uri(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><path fill="${background}" d="M16 5l9 4v7c0 6-5 10-9 12-4-2-9-6-9-12V9z"/></svg>`) } },
        { selector: 'edge', style: { width: 2, 'curve-style': 'straight', 'line-color': line, 'line-style': 'dashed', 'line-dash-pattern': [6, 6], 'z-index': 0 } },
        { selector: 'edge.cut', style: { 'line-color': COLORS.high, opacity: .45 } },
        { selector: 'edge.blocked', style: { 'line-color': COLORS.medium, opacity: .6 } },
        { selector: 'edge.offline', style: { opacity: .35 } },
      ],
    });
    graph.current = cy;
    cy.getElementById('router').ungrabify();
    cy.on('tap', 'node', (event) => {
      const node = event.target as NodeSingular;
      if (node.id() !== 'router' && Date.now() - draggedAt.current > 250) select.current(node.id());
    });
    cy.on('grab', 'node', (event) => { (event.target as NodeSingular).stop(true, false).style("opacity", 1); element.style.cursor = 'grabbing'; });
    cy.on('drag', 'node', () => { draggedAt.current = Date.now(); });
    cy.on('dragfree', 'node', (event) => {
      const node = event.target as NodeSingular;
      const anchor = anchors.current[node.id()];
      draggedAt.current = Date.now(); element.style.cursor = 'grab';
      if (!anchor) return;
      node.stop(true, false);
      if (reduced.current) node.position(anchor);
      else node.animate({ position: anchor }, { duration: 650, easing: 'spring(350, 24)' as cytoscape.Css.TransitionTimingFunction });
    });
    cy.on('mouseover', 'node', (event) => {
      element.style.cursor = 'grab';
      const node = event.target as NodeSingular;
      if (node.id() !== 'router' && !reduced.current) node.style({ width: 64, height: 64, 'border-width': 4 });
    });
    cy.on('mouseout', 'node', (event) => {
      element.style.cursor = 'default';
      const node = event.target as NodeSingular;
      if (node.id() !== 'router') node.style({ width: 56, height: 56, 'border-width': 3 });
    });
    let frame = 0, offset = 0;
    const animate = () => {
      if (!reduced.current && !document.hidden) cy.edges('.flow').style('line-dash-offset', offset = (offset - .5) % 1200);
      frame = requestAnimationFrame(animate);
    };
    // Reduced-motion users get static links and immediate snap-back.
    if (!reduced.current) frame = requestAnimationFrame(animate);
    const motion = (event: MediaQueryListEvent) => {
      reduced.current = event.matches;
      cy.nodes().style('transition-duration', event.matches ? 0 : .18);
      cancelAnimationFrame(frame);
      if (event.matches) cy.nodes().stop(true, true); else frame = requestAnimationFrame(animate);
    };
    preference.addEventListener?.('change', motion);
    const resize = new ResizeObserver(() => {
      cy.resize();
      cy.getElementById('router').position({ x: element.clientWidth / 2, y: element.clientHeight / 2 });
      anchors.current = mapPositions(cy.nodes().not('.router').map(node => node.id()), element.clientWidth, element.clientHeight);
      cy.nodes().not('.router').forEach(node => { if (!node.grabbed()) node.stop(true, false).style('opacity', 1).position(anchors.current[node.id()]); });
    });
    resize.observe(element);
    return () => { cancelAnimationFrame(frame); preference.removeEventListener?.('change', motion); resize.disconnect(); cy.destroy(); graph.current = null; };
  }, []);

  useEffect(() => {
    const cy = graph.current, element = box.current;
    if (!cy || !element) return;
    anchors.current = mapPositions(devices.map(device => device.mac), element.clientWidth, element.clientHeight);
    cy.nodes().not('.router').filter(node => !devices.some(device => device.mac === node.id())).remove();
    const ink = css('--color-ink', '#000');
    for (const device of devices) {
      const count = issueCounts[device.mac] ?? 0;
      const color = ['quarantined', 'wan_blocked'].includes(device.status) ? COLORS.high : COLORS[device.band];
      const data = { id: device.mac, label: shortLabel(device.label), color,
        badge: uri(`<svg xmlns="http://www.w3.org/2000/svg" width="56" height="56"><text x="28" y="36" text-anchor="middle" font-family="Helvetica,Arial,sans-serif" font-size="20" font-weight="600" fill="${ink}">${count}</text></svg>`) };
      const existing = cy.getElementById(device.mac);
      if (existing.nonempty()) {
        existing.data(data);
        if (!existing.grabbed() && !existing.animated()) existing.position(anchors.current[device.mac]);
      } else {
        const node = cy.add({ data, position: anchors.current[device.mac] });
        cy.add({ data: { id: `e-${device.mac}`, source: 'router', target: device.mac } });
        if (!reduced.current) node.style('opacity', 0).animate({ style: { opacity: 1 } }, { duration: 350 });
      }
      cy.getElementById(`e-${device.mac}`).classes(device.status === 'quarantined' ? 'cut' : device.status === 'wan_blocked' ? 'blocked' : device.status === 'offline' ? 'offline' : 'flow');
    }
  }, [devices, issueCounts]);

  useEffect(() => {
    const cy = graph.current;
    if (!cy) return;
    const maximum = Math.max(1, ...Object.values(rates));
    for (const [mac, value] of Object.entries(rates)) cy.getElementById(`e-${mac}`).style('width', 1.5 + value / maximum * 3);
  }, [rates]);

  return <div role="group" aria-label="Home Network Map">
    <div ref={box} className="h-[500px] w-full" aria-hidden="true" />
    <ul className="sr-only">{devices.map(device => <li key={device.mac}><button onClick={() => onSelect(device.mac)}>{shortLabel(device.label)}: {issueCounts[device.mac] ?? 0} Security Issues. Open Fixes.</button></li>)}</ul>
  </div>;
}
