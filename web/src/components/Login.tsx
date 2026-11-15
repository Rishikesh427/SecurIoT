import { useEffect, useRef, useState, type FormEvent } from "react";
import { USE_MOCK, api, setToken } from "../api/client";
import { unlockAudio } from "../lib/alert";
import { Button } from "./ui";
import gsap from "gsap";
import { Logo } from "./Logo";

export function Login({ onLogin, onHome }: { onLogin: () => void; onHome?: () => void }) {
  const root = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    // Controls remain visible even if animations are interrupted or throttled.
    const context = gsap.context(() => {
      gsap.from("[data-login-title]", { y: 12, duration: .45, ease: "power3.out", clearProps: "transform" });
      gsap.from("[data-login-orbit]", { scale: .9, rotation: -12, duration: 1.1, ease: "power2.out" });
    }, root);
    return () => context.revert();
  }, []);
  const [username, setUsername] = useState(USE_MOCK ? "judge" : "");
  const [password, setPassword] = useState(USE_MOCK ? "securiot" : "");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    unlockAudio();
    setBusy(true);
    setError(null);
    try {
      const { access_token } = await api.login(username, password);
      setToken(access_token);
      onLogin();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign in failed");
    } finally {
      setBusy(false);
    }
  }

  const field = "block min-h-12 w-full rounded-xl border border-hairline bg-fill px-4 py-3 text-[18px] text-ink outline-none placeholder:text-ink-3 focus:border-ink focus:ring-2 focus:ring-ink/15";

  return (
    <div ref={root} className="relative flex min-h-[100svh] items-center justify-center bg-white px-4 py-8 sm:py-12">
      <div aria-hidden="true" className="pointer-events-none absolute inset-0 overflow-hidden text-ink opacity-[0.05]">
        <div data-login-orbit className="absolute -left-32 top-1/4 h-96 w-96 rounded-full border-2 border-current" />
        <div data-login-orbit className="absolute -right-24 bottom-1/4 h-80 w-80 rounded-full border-2 border-current" />
      </div>
      <div className="relative z-10 w-full max-w-[400px]">
        <header className="mb-6 flex flex-col items-center text-center">
          {onHome ? <button type="button" aria-label="CasaWarden Landing Page" onClick={onHome} className="rounded-lg"><Logo size={56} /></button> : <Logo size={56} />}
          <h1 data-login-title className="mt-4 text-[32px] font-semibold leading-tight tracking-tight text-ink">CasaWarden</h1>
          <p className="mt-2 text-[18px] leading-relaxed text-ink-2">Security for the devices you can't patch.</p>
        </header>
        <form onSubmit={submit} aria-label="Sign In" className="space-y-4 rounded-2xl border border-hairline bg-white p-5 shadow-sm sm:p-6">
          <label htmlFor="login-username" className="block text-[17px] font-medium text-ink">
            Username
            <input id="login-username" name="username" className={`${field} mt-2`} placeholder="Enter your username"
              value={username} onChange={e => setUsername(e.target.value)} autoComplete="username" autoCapitalize="none" spellCheck={false} required />
          </label>
          <label htmlFor="login-password" className="block text-[17px] font-medium text-ink">
            Password
            <input id="login-password" name="password" className={`${field} mt-2`} type="password" placeholder="Enter your password"
              value={password} onChange={e => setPassword(e.target.value)} autoComplete="current-password" required />
          </label>
          {error && <p role="alert" className="text-[17px] text-bad">{error}</p>}
          <Button type="submit" variant="primary" className="min-h-12 w-full text-[18px]" disabled={busy}>
            {busy ? "Signing in…" : "Sign In"}
          </Button>
          {USE_MOCK && <p className="text-center text-[16px] text-ink-3">Demo mode. Any username and password works.</p>}
        </form>
      </div>
    </div>
  );
}
