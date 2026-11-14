import { useState, type FormEvent } from "react";
import { USE_MOCK, api, setToken } from "../api/client";
import { unlockAudio } from "../lib/alert";
import { Button } from "./ui";
import { Logo } from "./Logo";

export function Login({ onLogin }: { onLogin: () => void }) {
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
    "w-full rounded-xl bg-fill px-4 py-3 text-[15px] text-ink outline-none ring-1 ring-transparent transition placeholder:text-ink-3 focus:bg-white focus:ring-ink/20";

  return (
    <div className="flex min-h-screen items-center justify-center bg-white px-4">
      <form onSubmit={submit} className="w-full max-w-[360px] animate-rise-in">
        <div className="mb-10 flex flex-col items-center text-center">
          <Logo size={56} />
          <h1 className="mt-6 text-[32px] font-semibold tracking-tight text-ink">CasaWarden</h1>
          <p className="mt-1 text-[15px] text-ink-2">Security for the devices you can't patch.</p>
        </div>
        <div className="space-y-3">
          <input className={field} placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
          <input
            className={field}
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
        </div>
        {error && <p className="mt-4 text-center text-[13px] text-bad">{error}</p>}
        <Button type="submit" variant="primary" className="mt-6 h-12 w-full text-[15px]" disabled={busy}>
          {busy ? "Signing in" : "Sign in"}
        </Button>
        {USE_MOCK && <p className="mt-5 text-center text-[12px] text-ink-3">Demo mode. Any username and password works.</p>}
      </form>
    </div>
  );
}
