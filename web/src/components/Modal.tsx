import { useEffect, useId, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { titleCase } from "../lib/titles";
import { X } from "lucide-react";

/** Native dialog provides focus trapping, Escape, and focus restoration. */
export function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  const ref = useRef<HTMLDialogElement>(null);
  const heading = useId();
  useEffect(() => {
    const dialog = ref.current!;
    const previous = document.activeElement as HTMLElement | null;
    if (dialog.showModal) dialog.showModal(); else dialog.setAttribute("open", "");
    return () => { if (dialog.close) dialog.close(); previous?.focus(); };
  }, []);
  return createPortal(
    <dialog ref={ref} aria-labelledby={heading}
      onCancel={(event) => { event.preventDefault(); onClose(); }}
      onClick={(event) => { if (event.target === event.currentTarget) onClose(); }}
      className="fixed inset-0 z-50 m-auto w-[min(92vw,760px)] max-h-[90dvh] overflow-hidden rounded-2xl border border-hairline bg-white p-0 text-ink shadow-2xl backdrop:bg-black/40">
      <div>
        <header className="flex items-center justify-between gap-4 border-b border-hairline px-5 py-4">
          <h2 id={heading} className="text-xl font-semibold">{titleCase(title)}</h2>
          <button type="button" onClick={onClose} aria-label={`Close ${titleCase(title)}`} className="grid h-9 w-9 place-items-center rounded-full hover:bg-fill"><X size={20} /></button>
        </header>
        <div className="max-h-[72dvh] overflow-y-auto overscroll-contain p-5">{children}</div>
      </div>
    </dialog>, document.body,
  );
}
