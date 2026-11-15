import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { ReadAloud } from '../src/components/ReadAloud';
import { setAudioEnabled, speak, unlockAudio } from '../src/lib/alert';
const speech = { speak: vi.fn(), cancel: vi.fn() };
beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal('speechSynthesis', speech);
  vi.stubGlobal('SpeechSynthesisUtterance', class { text: string; rate = 1; pitch = 1; constructor(text: string) { this.text = text; } });
  setAudioEnabled(true);
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
it('does not autoplay and reads only after an explicit click', () => {
  render(<ReadAloud text="Review the device." enabled />);
  expect(speech.speak).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Read Aloud' }));
  expect(speech.speak).toHaveBeenCalledWith(expect.objectContaining({ text: 'Review the device.', rate: 1, pitch: 1 }));
});
it('mute stops existing speech and blocks subsequent speech', () => {
  unlockAudio(); setAudioEnabled(false);
  expect(speech.cancel).toHaveBeenCalled();
  expect(speak('Must stay silent')).toBe(false);
  expect(speech.speak).not.toHaveBeenCalled();
  render(<ReadAloud text="Muted" enabled={false} />);
  expect((screen.getByRole('button', { name: 'Read Aloud' }) as HTMLButtonElement).disabled).toBe(true);
});
it('leaves the UI usable when speech is not supported', () => {
  vi.stubGlobal('speechSynthesis', undefined);
  // A missing API is modeled by removing the property, as in unsupported browsers.
  const saved = window.speechSynthesis;
  Reflect.deleteProperty(window, 'speechSynthesis');
  render(<ReadAloud text="Available as text" enabled />);
  expect((screen.getByRole('button', { name: 'Read Aloud' }) as HTMLButtonElement).disabled).toBe(true);
  Object.defineProperty(window, 'speechSynthesis', { configurable: true, value: saved });
});
