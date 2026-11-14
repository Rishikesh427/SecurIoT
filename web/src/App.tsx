import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ApiError, USE_MOCK, api, getToken, isMissing, setToken } from "./api/client";
import { ActivityList } from "./components/ActivityList";
import { AdvisorPriorities } from "./components/Advisor";
import { ActivityView } from "./components/ActivityView";
import { CameraCard } from "./components/CameraCard";
import { ContainmentPanel } from "./components/ContainmentPanel";
import { DeviceDetail } from "./components/DeviceDetail";
import { DeviceList } from "./components/DeviceList";
import { Login } from "./components/Login";
import { Logo } from "./components/Logo";
import { StorageBadge } from "./components/StorageBadge";
import { SettingsView } from "./components/SettingsView";
import { AttentionList } from "./components/AttentionList";
import { FixSheet } from "./components/FixSheet";
import { Sparkline } from "./components/Sparkline";
import { StatusBanner } from "./components/StatusBanner";
import { Button, Card, SectionTitle, Segmented } from "./components/ui";
import { useCountUp } from "./hooks/useCountUp";
import { usePoll } from "./hooks/usePoll";
import { rate, useTraffic } from "./hooks/useTraffic";
import { deriveIssues, type Issue } from "./lib/issues";
import { severityMeta } from "./lib/severity";
import { playAlertTone, speak, unlockAudio } from "./lib/alert";
import { isContained, shortLabel } from "./lib/format";
import { isIncident, summarize } from "./lib/incident";
import { mockServer } from "./mock/mockServer";
import type { ActionName, AuditEntry, DashDevice, Device, Policy, SecurEvent } from "./types";

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
  const [fixing, setFixing] = useState<Issue | null>(null);
  const [doneIds, setDoneIds] = useState<Set<string>>(loadDone);
  const [now, setNow] = useState(Date.now());
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [commands, setCommands] = useState<Record<string, {id: string; action: ActionName}>>({});
  const requestBusy = useRef(false);
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
      const [d, e, a] = await Promise.all([api.devices(), api.events(), api.audit().catch(() => null)]);
      if (a) setAudit(a);
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
    if (requestBusy.current || commands[mac || "all"] || commands.all || (action === "restore_all" && Object.keys(commands).length)) return;
    requestBusy.current = true; setBusy(true);
    try {
      const command = await api.action(action === "restore_all" ? { action } : { action, mac });
      setCommands(previous => ({...previous, [mac || "all"]: {id: command.id, action}}));
      await refresh();
      const name = shortLabel(devices.find((d) => d.mac === mac)?.label ?? "");
      // POST /actions only queues a command; the agent applies it on its next sync.
      const msg: Record<ActionName, string> = {
        quarantine: `Quarantine requested for ${name}. Awaiting agent acknowledgement.`,
        block_wan: `Internet block requested for ${name}. Awaiting agent acknowledgement.`,
        restore: `Restore requested for ${name}. Awaiting agent acknowledgement.`,
        restore_all: "Restore all requested. Awaiting agent acknowledgement.",
      };
      flash(msg[action]);
    } catch (e) {
      const text = e instanceof Error ? e.message : "Action failed";
      // Say it in the dashboard's words: "learning mode" is "automatic protection off".
      flash(/learning mode/i.test(text) ? "Turn on automatic protection first, then isolate." : text);
    } finally {
      requestBusy.current = false; setBusy(false);
    }
  }

  useEffect(() => {
    const finished = Object.entries(commands).filter(([, command]) => audit.some(row => row.command_id === command.id && row.outcome !== "requested"));
    if (!finished.length) return;
    const remaining = {...commands};
    for (const [mac, command] of finished) {
      delete remaining[mac];
      const row = audit.find(entry => entry.command_id === command.id);
      flash(`${command.action === "restore" || command.action === "restore_all" ? "Restore" : "Containment"} ${row?.outcome === "applied" ? "acknowledged by the agent" : "failed or cancelled. Check the agent and audit log"}.`);
    }
    setCommands(remaining);
  }, [audit, commands]);

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

  const traffic = useTraffic(rawDevices);
  const feedDevice = devices.find((d) => d.has_feed);
  const selectedDevice = devices.find((d) => d.mac === selected);
  const isolated = devices.filter((d) => isContained(d.status));
  const armed = policy ? !policy.learning_mode : false;
  const issues = deriveIssues(devices, events, policy, { now, canAct }).filter((i) => !doneIds.has(i.id));

  function markDone(issue: Issue) {
    const next = new Set([...doneIds, issue.id]);
    setDoneIds(next);
    saveDone(next);
    setFixing(null);
    flash("Marked as done");
  }

  async function runFix(issue: Issue) {
    const kind = issue.action?.kind;
    setFixing(null);
    if (kind === "turn_on_protection") await setArmed(true).then(() => flash("Automatic protection is on"));
    else if (kind === "isolate" && issue.mac) await act("quarantine", issue.mac);
    else if (kind === "protect_and_isolate" && issue.mac) {
      await setArmed(true);
      await act("quarantine", issue.mac);
    }
    else if (kind === "restore" && issue.mac) await act("restore", issue.mac);
  }

  return (
    <div className="min-h-screen bg-white text-ink">
      <header className="sticky top-0 z-30 border-b border-hairline bg-white/75 backdrop-blur-xl backdrop-saturate-150">
        <div className="mx-auto grid h-14 max-w-[1200px] grid-cols-[1fr_auto_1fr] items-center gap-4 px-6">
          <div className="flex items-center gap-2.5">
            <Logo size={26} />
            <span className="text-[17px] font-semibold tracking-tight">CasaWarden</span>
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
              <Button onClick={() => act("restore_all")} disabled={busy || Object.keys(commands).length > 0} className="h-8">
                Restore all
              </Button>
            )}
            <StorageBadge />
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
          Can't reach the server. Commands remain pending until the agent reconnects.
        </div>
      </header>

      <main className="mx-auto max-w-[1200px] px-6 pb-32 pt-10">
        {tab === "overview" && (
          <div key="overview" className="animate-rise-in space-y-10">
            <StatusBanner
              issues={issues}
              armed={armed}
              hasPolicy={hasPolicy && !!policy}
              onArm={setArmed}
              onReview={() => document.getElementById("attention")?.scrollIntoView({ behavior: "smooth", block: "start" })}
            />

            <section className="grid grid-cols-2 gap-4 lg:grid-cols-4">
              <Stat label="Devices" value={devices.length} />
              <Stat
                label="Need attention"
                value={issues.length}
                color={issues.length ? severityMeta[issues[0].severity].color : undefined}
              />
              <Stat label="Cut off" value={isolated.length} color={isolated.length ? "text-sev-critical" : undefined} />
              <Card className="flex flex-col justify-between px-5 py-4">
                <div className="flex items-baseline justify-between">
                  <span className="text-[13px] font-medium text-ink-2">Network traffic</span>
                  <span className="flex items-center gap-1.5 text-[11px] font-medium text-ok">
                    <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-ok" />
                    Live
                  </span>
                </div>
                <div className="mt-2 flex items-end justify-between gap-3">
                  <span className="text-[22px] font-semibold leading-none tracking-tight tabular-nums text-ink">{rate(traffic.total[traffic.total.length - 1] ?? 0)}</span>
                  <Sparkline data={traffic.total} width={96} height={30} color="var(--color-ink)" />
                </div>
              </Card>
            </section>

            <AttentionList issues={issues} onFix={setFixing} />

            <div className="grid gap-10 lg:grid-cols-[minmax(0,1fr)_380px]">
              <div className="space-y-10">
                <DeviceList devices={devices} traffic={traffic} onSelect={setSelected} />
                <AdvisorPriorities devices={devices} onSelect={setSelected} />
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

      {fixing && (
        <FixSheet
          issue={fixing}
          busy={busy}
          onClose={() => setFixing(null)}
          onAction={runFix}
          onDone={markDone}
          onOpenDevice={(mac) => {
            setFixing(null);
            setSelected(mac);
          }}
        />
      )}

      {selectedDevice && <DeviceDetail device={selectedDevice} events={events} busy={busy} canAct={canAct} policy={policy} pending={commands[selectedDevice.mac]?.action || commands.all?.action} onClose={() => setSelected(null)} onAction={act} />}

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

const DONE_KEY = "securiot.doneIssues";

function loadDone(): Set<string> {
  try {
    return new Set(JSON.parse(localStorage.getItem(DONE_KEY) ?? "[]"));
  } catch {
    return new Set();
  }
}

function saveDone(ids: Set<string>) {
  try {
    localStorage.setItem(DONE_KEY, JSON.stringify([...ids]));
  } catch {
    // per-viewer convenience only
  }
}

function Stat({ label, value, color }: { label: string; value: number; color?: string }) {
  const shown = useCountUp(value);
  return (
    <Card className="px-5 py-4">
      <div className="text-[13px] font-medium text-ink-2">{label}</div>
      <div className={`mt-1 text-[32px] font-semibold leading-none tracking-tight tabular-nums transition-colors duration-500 ${color ?? "text-ink"}`}>{shown}</div>
    </Card>
  );
}

/** Mock-only controls standing in for the phone and a cloud outage. */
function DemoControls() {
  const [offline, setOffline] = useState(mockServer.isOffline());
  const [running, setRunning] = useState(false);
  const [joined, setJoined] = useState(mockServer.guestJoined());
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
        disabled={joined}
        onClick={() => {
          mockServer.simulateNewDevice();
          setJoined(true);
        }}
      >
        Device joins
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
