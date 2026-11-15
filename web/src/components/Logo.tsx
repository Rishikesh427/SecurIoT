import { useId } from "react";

// A turtle shell seen from above, in the Home parade turtles' colors (TurtleParade).
const SHELL = "#23733d";
const RIM = "#3c8d4a";
const SKIN = "#54a95d";

export function Logo({ size = 28 }: { size?: number }) {
  const clip = useId();
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden>
      <defs>
        <clipPath id={clip}><ellipse cx="16" cy="16" rx="12.5" ry="14.5" /></clipPath>
      </defs>
      {/* Edge plates, then the main shell inside them */}
      <ellipse cx="16" cy="16" rx="12.5" ry="14.5" fill={RIM} />
      <ellipse cx="16" cy="16" rx="10" ry="12" fill={SHELL} />
      <g clipPath={`url(#${clip})`} fill="none" stroke={SKIN} strokeWidth="1.2" strokeLinejoin="round" strokeLinecap="round">
        {/* Center plates down the spine */}
        <path d="M13.5 6.5h5l1.5 3-1.5 3h-5l-1.5-3z" />
        <path d="M13.5 12.5h5l1.5 3-1.5 3h-5l-1.5-3z" />
        <path d="M13.5 18.5h5l1.5 3-1.5 3h-5l-1.5-3z" />
        {/* Side plates out to the rim */}
        <path d="M13.5 12.5L3 11.5M13.5 18.5L3 20M18.5 12.5L29 11.5M18.5 18.5L29 20" />
        <path d="M13.5 6.5L11 2M18.5 6.5L21 2M13.5 24.5L11 30M18.5 24.5L21 30" />
        <ellipse cx="16" cy="16" rx="10" ry="12" />
      </g>
    </svg>
  );
}
