import { useState } from 'react';
import { Volume2 } from 'lucide-react';
import { speak, unlockAudio } from '../lib/alert';

export function ReadAloud({ text, enabled, label = 'Read Aloud', iconOnly = false }: { text: string; enabled: boolean; label?: string; iconOnly?: boolean }) {
  const [error, setError] = useState(false);
  const supported = typeof window !== 'undefined' && typeof window.speechSynthesis?.speak === 'function' && typeof window.SpeechSynthesisUtterance === 'function';
  return <span className="inline-flex flex-wrap items-center gap-2">
    <button type="button" aria-label={label} disabled={!enabled || !supported} title={!enabled ? 'Turn Audio On First' : !supported ? 'Speech Is Unavailable in This Browser' : label}
      className="inline-flex items-center gap-2 rounded-full px-3 py-2 text-sm transition-transform hover:bg-fill active:scale-95 disabled:opacity-40"
      onClick={() => { unlockAudio(); setError(!speak(text)); }}><Volume2 size={18} /><span className={iconOnly ? "sr-only" : undefined}>{label}</span></button>
    {error && <span role="status" className="text-xs">Audio could not start. The text remains available.</span>}
  </span>;
}
