import { useState, type FormEvent } from "react";
import { USE_MOCK, api, setToken } from "../api/client";
import { unlockAudio } from "../lib/alert";
import { Button } from "./ui";
import { TurtleCompanion } from "./TurtleParade";
import { Logo } from "./Logo";

export function Login({ onLogin, onBack }: { onLogin: () => void; onBack?: () => void }) {
  const [signup, setSignup] = useState(false);
  const [invite, setInvite] = useState("");
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
      const { access_token } = await (signup ? api.signup(username, password, invite) : api.login(username, password));
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
    <div className="flex min-h-screen items-center justify-center bg-white px-4">
      <form onSubmit={submit} className="w-full max-w-[360px] animate-rise-in">
        <div className="mb-10 flex flex-col items-center text-center">
          <Logo size={56} />
          <h1 className="mt-6 text-[36px] font-semibold tracking-tight text-ink">CasaWarden</h1>
          <p className="mt-1 text-[19px] text-ink-2">Security for the devices you can't patch.</p>
        </div>
        <div className="mb-5 flex items-center gap-3 text-sm text-ink-2"><TurtleCompanion variant={2} /><p>Sign in to discover devices, review risks, and choose protection.</p></div>
        <div className="space-y-3">
          <input className={field} placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
          <input
            className={field}
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete={signup ? "new-password" : "current-password"}
            minLength={signup ? 16 : undefined} required
          />
        </div>
        {signup && <input className={`${field} mt-3`} aria-label="Invitation code" placeholder="Invitation code" type="password" value={invite} onChange={e => setInvite(e.target.value)} required />}
        {error && <p className="mt-4 text-center text-[17px] text-bad">{error}</p>}
        <Button type="submit" variant="primary" className="mt-6 h-12 w-full text-[19px]" disabled={busy}>
          {busy ? "Please wait" : signup ? "Create account" : "Sign in"}
        </Button>
        {!USE_MOCK && <p className="mt-4 text-sm text-ink-2">Sign up requires an invitation from your network administrator and a password of at least 16 characters.</p>}
        <Button type="button" variant="plain" className="mt-3 w-full" disabled={busy} onClick={() => { setSignup(!signup); setError(null); }}>{signup ? "Already registered? Sign in" : "New here? Sign up"}</Button>
        {onBack && <Button type="button" variant="plain" className="mt-3 w-full" onClick={onBack}>Back to home</Button>}
        {USE_MOCK && <p className="mt-5 text-center text-[16px] text-ink-3">Demo mode. Any username and password works.</p>}
      </form>
    </div>
  );
}
