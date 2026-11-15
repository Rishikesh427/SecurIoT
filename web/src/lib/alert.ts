// One audio channel shared by alerts, chat answers and read-aloud controls.
// Browser policy is respected: unlock from a click; never force autoplay.
let ctx: AudioContext | null = null;
let enabled = true;
let unlocked = false;
const active = new Set<OscillatorNode>();

export function stopAudio() {
  if (typeof window !== 'undefined' && typeof window.speechSynthesis?.cancel === 'function') window.speechSynthesis.cancel();
  for (const oscillator of active) { try { oscillator.stop(); } catch { /* already stopped */ } }
  active.clear();
}

export function setAudioEnabled(value: boolean) {
  enabled = value;
  if (!enabled) stopAudio();
}

export function unlockAudio() {
  unlocked = true;
  try {
    ctx ??= new AudioContext();
    if (ctx.state === 'suspended') void ctx.resume().catch(() => undefined);
  } catch { ctx = null; }
}

export function playAlertTone() {
  if (!enabled || !unlocked || !ctx || ctx.state !== 'running') return;
  const start = ctx.currentTime;
  [0, .28, .56].forEach((offset, i) => {
    const oscillator = ctx!.createOscillator();
    const gain = ctx!.createGain();
    oscillator.type = 'square'; oscillator.frequency.value = i % 2 === 0 ? 880 : 660;
    gain.gain.setValueAtTime(.0001, start + offset);
    gain.gain.exponentialRampToValueAtTime(.15, start + offset + .02);
    gain.gain.exponentialRampToValueAtTime(.0001, start + offset + .24);
    oscillator.connect(gain).connect(ctx!.destination);
    active.add(oscillator); oscillator.onended = () => active.delete(oscillator);
    oscillator.start(start + offset); oscillator.stop(start + offset + .25);
  });
}

export function speak(text: string): boolean {
  if (!enabled || !unlocked || !text.trim() || typeof window.speechSynthesis?.speak !== 'function' || typeof window.SpeechSynthesisUtterance !== 'function') return false;
  stopAudio();
  const utterance = new SpeechSynthesisUtterance(text);
  utterance.rate = 1; utterance.pitch = 1;
  try { window.speechSynthesis.speak(utterance); return true; } catch { return false; }
}
