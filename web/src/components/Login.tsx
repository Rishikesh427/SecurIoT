import { useEffect, useRef, useState, type FormEvent } from "react";
import { USE_MOCK, api, setToken } from "../api/client";
import { unlockAudio } from "../lib/alert";
import { Button } from "./ui";
import gsap from "gsap";
import { Logo } from "./Logo";

export function Login({ onLogin }: { onLogin: () => void }) {
  const root=useRef<HTMLDivElement>(null);
  useEffect(()=>{
    if(matchMedia('(prefers-reduced-motion: reduce)').matches)return;
    const context=gsap.context(()=>{
      gsap.from('[data-login-reveal]',{y:24,opacity:0,duration:.65,stagger:.09,ease:'power3.out'});
      gsap.from('[data-login-orbit]',{scale:.75,opacity:0,rotation:-12,duration:1.1,stagger:.12,ease:'power2.out'});
    },root);
    return()=>context.revert();
  },[]);
  const [username, setUsername] = useState(USE_MOCK ? "judge" : "");
  const [password, setPassword] = useState(USE_MOCK ? "securiot" : "");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    unlockAudio(); // user gesture: allow the alert tone later
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

  const field =
    "w-full rounded-xl bg-fill px-4 py-3 text-[19px] text-ink outline-none ring-1 ring-transparent transition placeholder:text-ink-3 focus:bg-white focus:ring-ink/20";

  return (
    <div ref={root} className="relative flex min-h-screen items-center justify-center overflow-hidden bg-white px-4">
      <div aria-hidden="true" className="pointer-events-none absolute inset-0 overflow-hidden text-ink opacity-[0.05]">
        <div data-login-orbit className="absolute -left-32 top-1/4 h-96 w-96 rounded-full border-[2px] border-current"/>
        <div data-login-orbit className="absolute -right-24 bottom-1/4 h-80 w-80 rounded-full border-[2px] border-current"/>
      </div>
      <form onSubmit={submit} className="relative w-full max-w-[400px] animate-rise-in">
        <div className="mb-10 flex flex-col items-center text-center">
          <Logo size={56} />
          <h1 data-login-reveal className="mt-6 text-[36px] font-semibold tracking-tight text-ink">CasaWarden</h1>
          <p data-login-reveal className="mt-1 text-[19px] text-ink-2">Security for the devices you can't patch.</p>
        </div>
        <div className="space-y-3">
          <input data-login-reveal className={field} placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
          <input data-login-reveal
            className={field}
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
        </div>
        {error && <p className="mt-4 text-center text-[17px] text-bad">{error}</p>}
        <Button data-login-reveal type="submit" variant="primary" className="mt-6 h-12 w-full text-[19px]" disabled={busy}>
          {busy ? "Signing in" : "Sign in"}
        </Button>
        {USE_MOCK && <p className="mt-5 text-center text-[16px] text-ink-3">Demo mode. Any username and password works.</p>}
      </form>
    </div>
  );
}
