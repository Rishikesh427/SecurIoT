import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ApiError, USE_MOCK, api, getToken, isMissing, setToken } from "./api/client";
import { ActivityList } from "./components/ActivityList";
import { ActivityView } from "./components/ActivityView";
import { CameraCard } from "./components/CameraCard";
import { ContainmentPanel } from "./components/ContainmentPanel";
import { DeviceDetail } from "./components/DeviceDetail";
import { DeviceList } from "./components/DeviceList";
import { Login } from "./components/Login";
import { Logo } from "./components/Logo";
import { SettingsView } from "./components/SettingsView";
import { Button, Card, SectionTitle, Segmented, Switch } from "./components/ui";
import { usePoll } from "./hooks/usePoll";
import { playAlertTone, speak, unlockAudio } from "./lib/alert";
import { isContained, shortLabel } from "./lib/format";
import { isIncident, summarize } from "./lib/incident";
import { mockServer } from "./mock/mockServer";
import type { ActionName, DashDevice, Device, Policy, SecurEvent } from "./types";

type Tab = "overview" | "activity" | "settings";

export default function App() {
  const [authed, setAuthed] = useState(() => !!getToken());
  if (!authed) return <Login onLogin={() => setAuthed(true)} />;
  return (
    <Dashboard
      onLogout={() => {
        setToken(null);
        setAuthed(false);
      }}
    />
  );
}

function Dashboard({ onLogout }: { onLogout: () => void }) {
  const [tab, setTab] = useState<Tab>("overview");
  const [rawDevices, setRawDevices] = useState<Device[]>([]);
  const [events, setEvents] = useState<SecurEvent[]>([]);
  const [policy, setPolicy] = useState<Policy | null>(null);
  // Routes from later API milestones; false = the server doesn't have them yet.
  const [hasPolicy, setHasPolicy] = useState(true);
  const [canAct, setCanAct] = useState(false);
  const [canRunAudit, setCanRunAudit] = useState(false);
  const [offline, setOffline] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const [muted, setMuted] = useState(false);
  const [dismissed, setDismissed] = useState<string | null>(null);
  const [now, setNow] = useState(Date.now());
  const seenIncidents = useRef<Set<string> | null>(null);

  usePoll(() => setNow(Date.now()), 200);

  useEffect(() => {
    api.capabilities().then((c) => {
      setCanAct(c.actions);
      setCanRunAudit(c.auditRun);
    });
  }, []);

  const refresh = useCallback(async () => {
    try {
      const [d, e] = await Promise.all([api.devices(), api.events()]);
      setRawDevices(d);
      setEvents(e);
      setOffline(false);
      if (hasPolicy) {
        try {
          setPolicy(await api.policy());
        } catch (err) {
          if (!isMissing(err)) throw err;
          setHasPolicy(false); // stop asking until the next reload
        }
      }

      // Alert once per new incident (skip whatever already existed on first load).
      const incidents = e.filter(isIncident);
      if (!seenIncidents.current) {
        seenIncidents.current = new Set(incidents.map((x) => x.id));
      } else {
        for (const inc of incidents) {
          if (seenIncidents.current.has(inc.id)) continue;
          seenIncidents.current.add(inc.id);
          if (!muted) {
            playAlertTone();
            const spoken = summarize(inc, d.find((x) => x.mac === inc.mac)).spoken;
            setTimeout(() => speak(spoken), 900);
          }
        }
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) onLogout(); // token expired
      else setOffline(true);
    }
  }, [muted, onLogout, hasPolicy]);

  usePoll(refresh, 2000);

  const devices: DashDevice[] = useMemo(
    () => rawDevices.map((d) => ({ ...d, protected: !!policy?.protected_macs.includes(d.mac) })),
    [rawDevices, policy],
  );

  const flash = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(null), 3000);
  };

  async function act(action: ActionName, mac?: string) {
    setBusy(true);
    try {
      await api.action(action === "restore_all" ? { action } : { action, mac });
      await refresh();
      const name = shortLabel(devices.find((d) => d.mac === mac)?.label ?? "");
      // POST /actions only queues a command; the agent applies it on its next sync.
      const msg: Record<ActionName, string> = {
        quarantine: `Isolating ${name}`,
        block_wan: `Blocking internet for ${name}`,
        restore: `Restoring ${name}. It will rejoin Wi-Fi shortly.`,
        restore_all: "Restoring all devices",
      };
      flash(msg[action]);
    } catch (e) {
      flash(e instanceof Error ? e.message : "Action failed");
    } finally {
      setBusy(false);
    }
  }

  async function savePolicy(p: Policy) {
    try {
      setPolicy(await api.savePolicy(p));
    } catch (e) {
      flash(e instanceof Error ? e.message : "Couldn't save settings");
      throw e;
    }
  }

  async function setArmed(armed: boolean) {
    if (!policy) return;
    unlockAudio();
    await savePolicy({ ...policy, learning_mode: !armed });
  }

  const feedDevice = devices.find((d) => d.has_feed);
  const selectedDevice = devices.find((d) => d.mac === selected);
  const latestIncident = events.find(isIncident);
  const incidentSummary = latestIncident ? summarize(latestIncident, devices.find((d) => d.mac === latestIncident.mac)) : null;
  const showAlert = latestIncident && latestIncident.id !== dismissed && now - Date.parse(latestIncident.ts) < 5 * 60_000;
  const isolated = devices.filter((d) => isContained(d.status));
  const highRisk = devices.filter((d) => d.band === "high");
  const armed = policy ? !policy.learning_mode : false;

  const headline = !hasPolicy && !isolated.length
    ? "Your network is being monitored."
    : isolated.length
    ? `${isolated.length === 1 ? shortLabel(isolated[0].label) : `${isolated.length} devices`} ${isolated.length === 1 ? "is" : "are"} isolated.`
    : armed
      ? "Your network is protected."
      : "Learning mode is on.";
  const subline = !hasPolicy && !isolated.length
    ? "Automatic protection settings aren't available from the server yet."
    : isolated.length
    ? "The threat is contained. Follow the cleanup steps before restoring."
    : armed
      ? "SecurIoT will isolate any device that starts attacking your network."
      : "SecurIoT is watching but won't act. Turn on protection to isolate threats automatically.";

  return (
    <div className="min-h-screen bg-white text-ink">
      <header className="sticky top-0 z-30 border-b border-hairline bg-white/75 backdrop-blur-xl backdrop-saturate-150">
        <div className="mx-auto grid h-14 max-w-[1200px] grid-cols-[1fr_auto_1fr] items-center gap-4 px-6">
          <div className="flex items-center gap-2.5">
            <Logo size={26} />
            <span className="text-[17px] font-semibold tracking-tight">SecurIoT</span>
          </div>
          <Segmented<Tab>
            value={tab}
            onChange={setTab}
            options={[
              { value: "overview", label: "Overview" },
              { value: "activity", label: "Activity" },
              { value: "settings", label: "Settings" },
            ]}
          />
          <div className="flex items-center justify-end gap-1">
            {isolated.length > 0 && canAct && (
              <Button onClick={() => act("restore_all")} disabled={busy} className="h-8">
                Restore all
              </Button>
            )}
            <Button variant="plain" className="h-8 px-3" onClick={() => setMuted((m) => !m)}>
              {muted ? "Sound off" : "Sound on"}
            </Button>
            <Button variant="plain" className="h-8 px-3" onClick={onLogout}>
              Sign out
            </Button>
          </div>
        </div>
        <div
          className={`overflow-hidden bg-fill text-center text-[13px] text-ink transition-all duration-500 ${offline ? "max-h-10 py-2.5" : "max-h-0 py-0"}`}
          style={{ transitionTimingFunction: "var(--ease-apple)" }}
        >
          Can't reach the server. The agent keeps protecting your network locally at port 8787.
        </div>
      </header>

      <main className="mx-auto max-w-[1200px] px-6 pb-32 pt-10">
        {tab === "overview" && (
          <div key="overview" className="animate-rise-in space-y-10">
            <section className="flex flex-col gap-6 md:flex-row md:items-end md:justify-between">
              <div className="max-w-[640px]">
                <h1 className="text-[40px] font-semibold leading-[1.08] tracking-[-0.025em] text-ink sm:text-[48px]">{headline}</h1>
                <p className="mt-3 text-[17px] leading-relaxed text-ink-2">{subline}</p>
              </div>
              <Card className="flex shrink-0 items-center gap-5 px-5 py-4">
                <div>
                  <div className="text-[15px] font-medium text-ink">Automatic protection</div>
                  <div className="text-[13px] text-ink-2">{!hasPolicy ? "Not available yet" : armed ? "On" : "Off, learning mode"}</div>
                </div>
                <Switch label="Automatic protection" checked={armed} disabled={!policy} onChange={setArmed} />
              </Card>
            </section>

            <section className="grid grid-cols-3 gap-4">
              <Stat label="Devices" value={devices.length} />
              <Stat label="High risk" value={highRisk.length} tone={highRisk.length ? "bad" : undefined} />
              <Stat label="Isolated" value={isolated.length} tone={isolated.length ? "bad" : undefined} />
            </section>

            {showAlert && latestIncident && incidentSummary && (
              <Card className="animate-rise-in overflow-hidden">
                <div className="flex gap-5 px-6 py-5">
                  <span className={`mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full ${latestIncident.actions_taken.length ? "bg-bad" : "bg-warn"}`} />
                  <div className="flex-1">
                    <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                      <h2 className="text-[17px] font-semibold text-ink">{incidentSummary.headline}</h2>
                      <span className="text-[13px] text-ink-3">
                        {latestIncident.actions_taken.length ? "Contained, not fixed" : "Learning mode, no action taken"}
                      </span>
                    </div>
                    <p className="mt-1.5 text-[15px] leading-relaxed text-ink-2">{incidentSummary.body}</p>
                    <div className="mt-4 flex gap-2">
                      <Button variant="primary" onClick={() => setSelected(latestIncident.mac)}>
                        View cleanup steps
                      </Button>
                      <Button onClick={() => setDismissed(latestIncident.id)}>Dismiss</Button>
                    </div>
                  </div>
                </div>
              </Card>
            )}

            <div className="grid gap-10 lg:grid-cols-[minmax(0,1fr)_380px]">
              <div className="space-y-10">
                <DeviceList devices={devices} onSelect={setSelected} now={now} />
                <div>
                  <SectionTitle
                    action={
                      <button onClick={() => setTab("activity")} className="text-[14px] font-medium text-ink-2 transition-colors hover:text-ink">
                        See all
                      </button>
                    }
                  >
                    Recent activity
                  </SectionTitle>
                  <ActivityList events={events} devices={devices} onSelect={setSelected} limit={6} />
                </div>
              </div>
              <div className="space-y-4 lg:sticky lg:top-24 lg:self-start">
                <SectionTitle>Status</SectionTitle>
                {feedDevice && <CameraCard device={feedDevice} now={now} />}
                <ContainmentPanel events={events} devices={devices} now={now} />
              </div>
            </div>
          </div>
        )}

        {tab === "activity" && (
          <div key="activity" className="animate-rise-in">
            <ActivityView devices={devices} events={events} onAction={act} onSelect={setSelected} canAct={canAct} canRunAudit={canRunAudit} />
          </div>
        )}

        {tab === "settings" && !hasPolicy && (
          <div key="settings-missing" className="mx-auto max-w-[680px] animate-rise-in">
            <Card className="px-6 py-8 text-center">
              <h2 className="text-[19px] font-semibold text-ink">Settings aren't available yet</h2>
              <p className="mt-2 text-[15px] text-ink-2">The server doesn't have the policy route yet. Protection, response and protected devices will appear here once it does.</p>
            </Card>
          </div>
        )}

        {tab === "settings" && policy && (
          <div key="settings" className="animate-rise-in">
            <SettingsView policy={policy} devices={devices} onSave={savePolicy} />
          </div>
        )}
      </main>

      {USE_MOCK && tab === "overview" && <DemoControls />}

      {selectedDevice && <DeviceDetail device={selectedDevice} events={events} busy={busy} canAct={canAct} onClose={() => setSelected(null)} onAction={act} />}

      <div
        className={`fixed left-1/2 top-20 z-50 -translate-x-1/2 transition-all duration-500 ${toast ? "translate-y-0 opacity-100" : "pointer-events-none -translate-y-3 opacity-0"}`}
        style={{ transitionTimingFunction: "var(--ease-apple)" }}
      >
        <div className="rounded-full bg-ink/90 px-5 py-2.5 text-[14px] font-medium text-white shadow-[0_10px_30px_rgba(0,0,0,0.18)] backdrop-blur-xl">
          {toast}
        </div>
      </div>
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: number; tone?: "bad" }) {
  return (
    <Card className="px-5 py-4">
      <div className="text-[13px] font-medium text-ink-2">{label}</div>
      <div className={`mt-1 text-[32px] font-semibold leading-none tracking-tight tabular-nums ${tone === "bad" ? "text-bad" : "text-ink"}`}>{value}</div>
    </Card>
  );
}

/** Mock-only controls standing in for the phone and a cloud outage. */
function DemoControls() {
  const [offline, setOffline] = useState(mockServer.isOffline());
  const [running, setRunning] = useState(false);
  usePoll(() => setRunning(mockServer.attackRunning()), 300);

  return (
    <div className="fixed bottom-6 left-6 z-30 flex items-center gap-1.5 rounded-full bg-white/80 p-1.5 pl-4 shadow-[0_10px_40px_rgba(0,0,0,0.12)] ring-1 ring-hairline backdrop-blur-xl">
      <span className="pr-1.5 text-[12px] font-semibold uppercase tracking-wide text-ink-3">Demo</span>
      <Button
        variant="primary"
        className="h-8"
        disabled={running}
        onClick={() => {
          unlockAudio();
          mockServer.simulateQrAttack();
          setRunning(true);
        }}
      >
        {running ? "Attack in progress" : "Simulate QR attack"}
      </Button>
      <Button
        className="h-8"
        onClick={() => {
          mockServer.setOffline(!offline);
          setOffline(!offline);
        }}
      >
        {offline ? "Restore cloud" : "Cloud outage"}
      </Button>
    </div>
  );
}
