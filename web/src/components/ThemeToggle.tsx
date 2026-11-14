import { useEffect, useRef, useState } from "react";
import { Moon, Sun, Volume2, VolumeX } from "lucide-react";
import gsap from "gsap";

const KEY = "casawarden.theme";
export type Theme = "light" | "dark";

export function useTheme() {
  const [theme, setTheme] = useState<Theme>(() => (localStorage.getItem(KEY) as Theme) || "light");
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem(KEY, theme);
  }, [theme]);
  return [theme, () => setTheme((t) => (t === "light" ? "dark" : "light"))] as const;
}

/** Icon button whose icon spins/pops in whenever `state` changes (not on first render). */
function IconToggle({ state, label, onClick, children }: { state: unknown; label: string; onClick: () => void; children: React.ReactNode }) {
  const icon = useRef<HTMLSpanElement>(null);
  const first = useRef(true);
  useEffect(() => {
    if (first.current) { first.current = false; return; }
    gsap.fromTo(icon.current, { rotate: -120, scale: 0.3, opacity: 0 }, { rotate: 0, scale: 1, opacity: 1, duration: 0.55, ease: "back.out(2)" });
  }, [state]);
  return (
    <button onClick={onClick} aria-label={label} className="grid h-8 w-8 place-items-center rounded-full text-ink hover:bg-fill">
      <span ref={icon} className="grid place-items-center">{children}</span>
    </button>
  );
}

export function ThemeToggle({ theme, onToggle }: { theme: Theme; onToggle: () => void }) {
  return (
    <IconToggle state={theme} onClick={onToggle} label={theme === "light" ? "Switch to dark mode" : "Switch to light mode"}>
      {theme === "light" ? <Moon size={18} /> : <Sun size={18} />}
    </IconToggle>
  );
}

export function SoundToggle({ muted, onToggle }: { muted: boolean; onToggle: () => void }) {
  return (
    <IconToggle state={muted} onClick={onToggle} label={muted ? "Turn alert sound on" : "Turn alert sound off"}>
      {muted ? <VolumeX size={18} /> : <Volume2 size={18} />}
    </IconToggle>
  );
}