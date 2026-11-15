import { useEffect, useRef, useState } from 'react';
import gsap from 'gsap';

const family = [
  { size: 40, shell: '#23733d', skin: '#54a95d', marking: 'scutes' },
  { size: 30, shell: '#3c8d4a', skin: '#85bf68', marking: 'spots' },
  { size: 28, shell: '#528f35', skin: '#a0cc74', marking: 'stripe' },
  { size: 32, shell: '#267c63', skin: '#6bbd91', marking: 'diamond' },
  { size: 29, shell: '#658c37', skin: '#b0ca77', marking: 'scutes' },
] as const;

function Turtle({ size, shell, skin, marking }: typeof family[number]) {
  return <svg width={size * 1.4} height={size} viewBox="0 0 70 50" aria-hidden="true" focusable="false">
    <path d="M60 30l8 4-8 3" fill={skin} />
    <g data-leg style={{transformOrigin:'25px 34px'}}><ellipse cx="25" cy="39" rx="6" ry="8" fill={skin}/></g>
    <g data-leg style={{transformOrigin:'48px 34px'}}><ellipse cx="49" cy="39" rx="6" ry="8" fill={skin}/></g>
    <ellipse cx="12" cy="29" rx="11" ry="9" fill={skin}/><circle cx="7" cy="26" r="1.8" fill="#153d26"/>
    <path d="M5 32q4 3 7 0" fill="none" stroke="#315a31" strokeWidth="1.4" strokeLinecap="round"/>
    <path d="M18 34c-1-31 43-34 44 0z" fill={shell}/>
    <path d="M18 34h44" stroke={skin} strokeWidth="3" strokeLinecap="round"/>
    <g fill="none" stroke={skin} strokeWidth="1.8" opacity=".8">
      {marking==='scutes' && <><path d="M33 12l12-1 8 10-7 10-13-1-7-10z"/><path d="M33 12l-4-6M45 11l5-5M53 21l8 1M46 31l3 3M33 30l-3 4M26 20l-6-2"/></>}
      {marking==='spots' && <><circle cx="31" cy="20" r="4"/><circle cx="47" cy="19" r="4"/><circle cx="40" cy="29" r="3"/></>}
      {marking==='stripe' && <><path d="M27 12q-3 10 3 20M39 7q-3 12 2 26M50 11q-1 10 4 20"/></>}
      {marking==='diamond' && <><path d="M39 8l12 13-12 12-12-12z"/><path d="M39 14l6 7-6 6-6-6z"/></>}
    </g>
  </svg>;
}

/** Decorative, silent seven-second loop. No logo assets are used or changed. */
export function TurtleParade() {
  const track = useRef<HTMLDivElement>(null);
  const train = useRef<HTMLDivElement>(null);
  const paused = false;
  const [reduced, setReduced] = useState(() => typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches);
  const animations = useRef<gsap.core.Animation[]>([]);
  const pausedRef = useRef(paused); pausedRef.current = paused;
  useEffect(() => { animations.current.forEach(animation => animation.paused(paused)); }, [paused]);
  useEffect(() => {
    const query = matchMedia('(prefers-reduced-motion: reduce)');
    const update = () => setReduced(query.matches);
    update(); query.addEventListener?.('change', update);
    return () => query.removeEventListener?.('change', update);
  }, []);
  useEffect(() => {
    const element = train.current!, container = track.current!;
    if (reduced) { gsap.set(element, { x: 16, y: 0 }); return; }
    const context = gsap.context(() => {
      const walk = gsap.timeline({ paused: pausedRef.current, repeat: -1 });
      walk.fromTo(element, { x: () => container.clientWidth + 8 }, { x: () => -element.offsetWidth - 8, duration: 7, ease: 'none' });
      const legs = gsap.to('[data-leg]', { rotation: 18, duration: .22, yoyo: true, repeat: -1, stagger: .06, ease: 'sine.inOut', paused: pausedRef.current });
      const bounce = gsap.to('[data-turtle]', { y: -1.5, duration: .32, yoyo: true, repeat: -1, stagger: .09, ease: 'sine.inOut', paused: pausedRef.current });
      animations.current = [walk, legs, bounce];
      const resize = new ResizeObserver(() => { walk.invalidate(); });
      resize.observe(container);
      return () => resize.disconnect();
    }, container);
    return () => { animations.current = []; context.revert(); };
  }, [reduced]);
  return <footer className="pointer-events-none fixed inset-x-0 bottom-0 z-20 h-12 overflow-hidden" aria-label="Turtle Mascot Animation">
    <div ref={track} className="absolute inset-0" aria-hidden="true">
      <div ref={train} className="absolute bottom-1 left-0 flex w-max items-end gap-3 will-change-transform">
        {family.map((turtle, index) => <span key={index} data-turtle data-age={index===0?'adult':'young'}><Turtle {...turtle}/></span>)}
      </div>
    </div>

  </footer>;
}

export function TurtleHelpIcon(){return <span className="relative block h-8 w-10 [&_svg]:h-full [&_svg]:w-full" aria-hidden="true"><Turtle {...family[0]}/><span className="absolute left-[21px] top-[3px] text-[16px] font-bold text-white">?</span></span>;}
