// Map view: the router in the middle, devices around it (Cytoscape.js).
// Links animate while traffic flows, turn red and dashed when a device is cut off,
// and new devices slide out from the router with a pulse.
import { useEffect, useRef } from "react";
import cytoscape, { type Core, type NodeSingular } from "cytoscape";
import { shortLabel, statusStyle } from "../lib/format";
import type { DashDevice } from "../types";

const INK = "#1d1d1f";
const HAIRLINE = "#d2d2d7";
const COLORS = { low: "#28a745", medium: "#c77700", high: "#e5332a" } as const;
const FONT = '-apple-system, BlinkMacSystemFont, "SF Pro Text", "Helvetica Neue", Arial, sans-serif';

const svgUri = (svg: string) => `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
const riskBadge = (risk: number) =>
  svgUri(
    `<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48"><text x="24" y="30" text-anchor="middle" font-family="-apple-system,Helvetica,Arial,sans-serif" font-size="16" font-weight="600" fill="${INK}">${risk}</text></svg>`,
  );
const ROUTER_ICON = svgUri(
  `<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 32 32"><path d="M16 9l6 2.6v4.3c0 3.9-2.6 7-6 8.1-3.4-1.1-6-4.2-6-8.1v-4.3z" fill="#fff"/></svg>`,
);

function nodeData(d: DashDevice) {
  const cut = d.status === "quarantined" || d.status === "wan_blocked";
  return {
    id: d.mac,
    label: `${shortLabel(d.label)}\n${statusStyle[d.status].label}`,
    color: cut ? COLORS.high : COLORS[d.band],
    badge: riskBadge(d.risk),
  };
}

function edgeClass(d: DashDevice) {
  return d.status === "quarantined" ? "cut" : d.status === "wan_blocked" ? "blocked" : d.status === "offline" ? "offline" : "flow";
}

/** Devices on a circle around the router, in a stable order. */
function positions(macs: string[], w: number, h: number) {
  const r = Math.max(110, Math.min(w, h) * 0.34);
  const sorted = [...macs].sort();
  return Object.fromEntries(
    sorted.map((mac, i) => {
      const a = -Math.PI / 2 + (i / Math.max(1, sorted.length)) * Math.PI * 2;
      return [mac, { x: w / 2 + r * Math.cos(a), y: h / 2 + r * Math.sin(a) }];
    }),
  );
}

export default function NetworkMap({
  devices,
  rates,
  onSelect,
}: {
  devices: DashDevice[];
  rates: Record<string, number>;
  onSelect: (mac: string) => void;
}) {
  const box = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const selectRef = useRef(onSelect);
  selectRef.current = onSelect;

  // Create the graph once.
  useEffect(() => {
    const el = box.current!;
    const cy = cytoscape({
      container: el,
      elements: [{ data: { id: "router", label: "Router", color: INK, badge: ROUTER_ICON }, position: { x: el.clientWidth / 2, y: el.clientHeight / 2 }, classes: "router" }],
      // Positions are computed in pixels, so keep the view at 1:1 (no auto-fit).
      layout: { name: "preset", fit: false },
      zoom: 1,
      pan: { x: 0, y: 0 },
      minZoom: 1,
      maxZoom: 1,
      userZoomingEnabled: false,
      userPanningEnabled: false,
      boxSelectionEnabled: false,
      autoungrabify: true,
      style: [
        {
          selector: "node",
          style: {
            width: 48,
            height: 48,
            "background-color": "#ffffff",
            "background-image": "data(badge)",
            "background-fit": "contain",
            "border-width": 3,
            "border-color": "data(color)",
            label: "data(label)",
            "text-valign": "bottom",
            "text-margin-y": 8,
            "text-wrap": "wrap",
            "text-max-width": "140px",
            "font-family": FONT,
            "font-size": 12,
            "line-height": 1.35,
            color: INK,
            "overlay-shape": "ellipse",
            "overlay-opacity": 0,
            "transition-property": "border-color, background-color",
            "transition-duration": 0.6,
            // overlay-shape exists in Cytoscape 3.30 but not in @types/cytoscape yet.
          } as cytoscape.Css.Node,
        },
        {
          selector: "node.router",
          style: {
            width: 64,
            height: 64,
            "background-color": INK,
            "background-image": ROUTER_ICON,
            "border-width": 0,
            "font-weight": 600,
          },
        },
        {
          selector: "edge",
          style: {
            width: 2,
            "curve-style": "straight",
            "line-color": HAIRLINE,
            "line-style": "dashed",
            "line-dash-pattern": [6, 6],
            "transition-property": "line-color, opacity, width",
            "transition-duration": 0.6,
          },
        },
        { selector: "edge.cut", style: { "line-color": COLORS.high, opacity: 0.45, "line-dash-pattern": [3, 7] } },
        { selector: "edge.blocked", style: { "line-color": COLORS.medium, opacity: 0.6 } },
        { selector: "edge.offline", style: { "line-color": HAIRLINE, opacity: 0.4, "line-dash-pattern": [2, 8] } },
      ],
    });
    cy.on("tap", "node", (e) => {
      const id = (e.target as NodeSingular).id();
      if (id !== "router") selectRef.current(id);
    });
    cy.on("mouseover", "node", () => (el.style.cursor = "pointer"));
    cy.on("mouseout", "node", () => (el.style.cursor = "default"));
    cyRef.current = cy;

    // Traffic flowing along the live links.
    let offset = 0;
    let raf = 0;
    const tick = () => {
      offset = (offset - 0.6) % 1200;
      cy.edges(".flow").style("line-dash-offset", offset);
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);

    const ro = new ResizeObserver(() => {
      cy.resize();
      const w = el.clientWidth;
      const h = el.clientHeight;
      cy.getElementById("router").position({ x: w / 2, y: h / 2 });
      const pos = positions(cy.nodes().not(".router").map((n) => n.id()), w, h);
      cy.nodes().not(".router").forEach((n) => {
        n.position(pos[n.id()]);
      });
    });
    ro.observe(el);

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      cy.destroy();
      cyRef.current = null;
    };
  }, []);

  // Keep the graph in sync with the device list.
  useEffect(() => {
    const cy = cyRef.current;
    const el = box.current;
    if (!cy || !el) return;
    const w = el.clientWidth;
    const h = el.clientHeight;
    const center = { x: w / 2, y: h / 2 };
    const pos = positions(devices.map((d) => d.mac), w, h);
    const firstRender = cy.nodes().length === 1;

    cy.batch(() => {
      cy.nodes()
        .not(".router")
        .filter((n) => !devices.some((d) => d.mac === n.id()))
        .remove();
    });

    for (const d of devices) {
      const existing = cy.getElementById(d.mac);
      if (existing.nonempty()) {
        existing.data(nodeData(d));
        const edge = cy.getElementById(`e-${d.mac}`);
        edge.classes(edgeClass(d));
        const p = pos[d.mac];
        const cur = existing.position();
        if (Math.abs(cur.x - p.x) > 1 || Math.abs(cur.y - p.y) > 1) existing.animate({ position: p }, { duration: 600, easing: "ease-out-cubic" });
        continue;
      }
      const node = cy.add({ data: nodeData(d), position: firstRender ? pos[d.mac] : center });
      cy.add({ data: { id: `e-${d.mac}`, source: "router", target: d.mac }, classes: edgeClass(d) });
      if (!firstRender) {
        // New device: slide out from the router, then pulse.
        node.style("opacity", 0);
        node.animate({ position: pos[d.mac], style: { opacity: 1 } }, { duration: 700, easing: "ease-out-cubic" });
        const pulse = (n: number) => {
          if (n === 0 || node.removed()) return;
          node
            .style({ "overlay-color": COLORS.low, "overlay-opacity": 0.25, "overlay-padding": 0 })
            .animate({ style: { "overlay-opacity": 0, "overlay-padding": 16 } }, { duration: 900, complete: () => pulse(n - 1) });
        };
        setTimeout(() => pulse(3), 700);
        // If animation frames were paused (background tab), don't leave the tint behind.
        setTimeout(() => !node.removed() && node.style({ opacity: 1, "overlay-opacity": 0 }).position(pos[d.mac]), 4500);
      }
    }
  }, [devices]);

  // Thicker links for busier devices.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const max = Math.max(1, ...Object.values(rates));
    for (const [mac, r] of Object.entries(rates)) {
      cy.getElementById(`e-${mac}`).style("width", 1.5 + (r / max) * 3);
    }
  }, [rates]);

  return <div ref={box} className="h-[440px] w-full" role="img" aria-label="Map of devices connected to the router" />;
}
