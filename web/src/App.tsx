import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ApiError, USE_MOCK, api, getToken, isMissing, setToken } from "./api/client";
import { Bandwidth } from "./components/Bandwidth";
import { TurtleParade, TurtleHelpIcon } from "./components/TurtleParade";
import { ActivityExplorer } from "./components/ActivityExplorer";
import { Modal } from "./components/Modal";
import { deviceGroups, deviceIssueCounts } from "./lib/deviceGroups";
import { ActivityView } from "./components/ActivityView";
import { DeviceDetail } from "./components/DeviceDetail";
import { Landing } from "./components/Landing";
import { Login } from "./components/Login";
import { HomeMap } from "./components/HomeMap";
import { OlderDevices } from "./components/OlderDevices";
import { Heatmap } from "./components/Heatmap";
import { SettingsToggle, SoundToggle, ThemeToggle, useTheme } from "./components/ThemeToggle";
import { Logo } from "./components/Logo";
import { StorageBadge } from "./components/StorageBadge";
import { SettingsView } from "./components/SettingsView";
import { AttentionList } from "./components/AttentionList";
import { FixSheet } from "./components/FixSheet";
import { Button, Card } from "./components/ui";
import { usePoll } from "./hooks/usePoll";
import { useTraffic } from "./hooks/useTraffic";
import { deriveIssues, type Issue } from "./lib/issues";
import { playAlertTone, setAudioEnabled, speak, unlockAudio } from "./lib/alert";
import { isContained, shortLabel } from "./lib/format";
import { isIncident, summarize } from "./lib/incident";
import { mockServer } from "./mock/mockServer";
import type { ActionName, AuditEntry, DashDevice, Device, Policy, SecurEvent } from "./types";

type Tab = "map" | "heatmap" | "overview";

export default function App() {
  const [authed, setAuthed] = useState(() => !!getToken());
  const [landing, setLanding] = useState(false);
  if (landing) return <Landing authenticated={authed} onEnter={() => setLanding(false)} />;
  if (!authed) return <Login onHome={() => setLanding(true)} onLogin={() => setAuthed(true)} />;
  return (
    <Dashboard onHome={() => setLanding(true)}
      onLogout={() => {
        setToken(null);
        setAuthed(false);
        setLanding(true);
      }}
    />
  );
}

function Dashboard({ onLogout, onHome }: { onLogout: () => void; onHome: () => void }) {
  const [tab, setTab] = useState<Tab>("map");
  const [rawDevices, setRawDevices] = useState<Device[]>([]);
  const [events, setEvents] = useState<SecurEvent[]>([]);
  const [policy, setPolicy] = useState<Policy | null>(null);
  // Routes from later API milestones; false = the server doesn't have them yet.
  const [hasPolicy, setHasPolicy] = useState(true);
  const [canAct, setCanAct] = useState(false);
  const [canRunAudit, setCanRunAudit] = useState(false);
  const [offline, setOffline] = useState(false);
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [policyFresh, setPolicyFresh] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [tutorialOpen, setTutorialOpen] = useState(false);
  const [armingBusy, setArmingBusy] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const [muted, setMuted] = useState(() => { try { return localStorage.getItem("casawarden.muted") === "true"; } catch { return false; } });
  useEffect(() => { setAudioEnabled(!muted); try { localStorage.setItem("casawarden.muted", String(muted)); } catch { /* storage unavailable */ } }, [muted]);
  const [theme, toggleTheme] = useTheme();
  const [fixing, setFixing] = useState<Issue | null>(null);
  const [doneIds, setDoneIds] = useState<Set<string>>(loadDone);
  const [now, setNow] = useState(Date.now());
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [commands, setCommands] = useState<Record<string, {id: string; action: ActionName}>>({});
  const requestBusy = useRef(false);
  const refreshBusy = useRef(false);
  const [agentConnected,setAgentConnected] = useState<boolean|null>(null);
  const policyRevision = useRef(0);
  const seenIncidents = useRef<Set<string> | null>(null);

  usePoll(() => setNow(Date.now()), 200);

  usePoll(async () => {
    try { const c = await api.capabilities(); setCanAct(c.actions); setCanRunAudit(c.auditRun); }
    catch { /* Core data polling reports connectivity separately. */ }
  }, 300000);

  const refresh = useCallback(async () => {
    if (refreshBusy.current) return;
    refreshBusy.current = true;
    const revision = policyRevision.current;
    try {
      // One snapshot request replaces four overlapping endpoint polls.
      const snapshot = api.dashboard ? await api.dashboard() : null;
      if (snapshot) setAgentConnected(snapshot.agent_connected);
      const results = snapshot ? [
        {status:"fulfilled" as const,value:snapshot.devices}, {status:"fulfilled" as const,value:snapshot.events},
        {status:"fulfilled" as const,value:snapshot.audit}, {status:"fulfilled" as const,value:snapshot.policy},
      ] as const : await Promise.allSettled([
        api.devices(), api.events(), api.audit(), hasPolicy ? api.policy() : Promise.resolve(null),
      ] as const);
      for (const result of results) {
        if (result.status === "rejected" && result.reason instanceof ApiError && result.reason.status === 401) { onLogout(); return; }
      }
      const [deviceResult, eventResult, auditResult, policyResult] = results;
      const partialWarnings: string[] = [];
      const reason = (error: unknown) => error instanceof Error ? error.message : "Request failed";
      if (deviceResult.status === "fulfilled") {
        const next = deviceResult.value;
        setRawDevices(next); setLoaded(true); setOffline(false); setConnectionError(null);
      } else {
        setOffline(true); setConnectionError(reason(deviceResult.reason));
      }
      if (eventResult.status === "fulfilled") setEvents(eventResult.value);
      else partialWarnings.push(`Activity: ${reason(eventResult.reason)}`);
      if (auditResult.status === "fulfilled") setAudit(auditResult.value);
      else partialWarnings.push(`Audit: ${reason(auditResult.reason)}`);
      if (revision !== policyRevision.current) {
        // A policy save started after this refresh; ignore its stale policy response.
      } else if (policyResult.status === "fulfilled" && policyResult.value) {
        setPolicy(policyResult.value); setPolicyFresh(true);
      } else {
        setPolicyFresh(false);
        if (policyResult.status === "rejected") {
          if (isMissing(policyResult.reason)) setHasPolicy(false);
          partialWarnings.push(`Policy: ${reason(policyResult.reason)}`);
        }
      }
      setWarnings(partialWarnings);
      // A slow optional endpoint must not discard successfully loaded devices.
      if (deviceResult.status !== "fulfilled" || eventResult.status !== "fulfilled") return;
      const d = deviceResult.value;
      const e = eventResult.value;

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
      else { setOffline(true); setConnectionError(err instanceof Error ? err.message : "Dashboard update failed"); }
    } finally { refreshBusy.current = false; }
  }, [muted, onLogout, hasPolicy]);

  usePoll(refresh, offline ? 10000 : 1000);

  const devices: DashDevice[] = useMemo(
    () => rawDevices.filter(d => !d.simulated).map((d) => ({ ...d, protected: d.identification?.manual_protected === true || !!policy?.protected_macs.includes(d.mac) })),
    [rawDevices, policy],
  );

  const flash = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(null), 3000);
  };

  async function act(action: ActionName, mac?: string) {
    if (requestBusy.current || (!action.startsWith("restore") && (commands[mac || "all"] || commands.all))) return;
    requestBusy.current = true; setBusy(true);
    try {
      const command = await api.action(action === "restore_all" ? { action } : { action, mac });
      if (command.status === 'applied') { setCommands(previous => { const next = {...previous}; if(action==='restore_all') return {}; delete next[mac || 'all']; return next; }); flash(USE_MOCK || command.detail?.includes('mock enforcement') || devices.find(device=>device.mac===mac)?.simulated ? 'Simulated access change recorded.' : 'Access change applied.'); await refresh(); return; }
      if (command.status === 'failed' || command.status === 'cancelled') { flash(command.detail || 'The access change could not be applied.'); await refresh(); return; }
      setCommands(previous => ({...previous, [mac || "all"]: {id: command.id, action}}));
      await refresh();
      const name = shortLabel(devices.find((d) => d.mac === mac)?.label ?? "");
      // POST /actions only queues a command; the agent applies it on its next sync.
      const msg: Record<ActionName, string> = {
        quarantine: `Quarantine requested for ${name}. Applying automatically when the Pi is connected.`,
        block_wan: `Internet block requested for ${name}. Applying automatically when the Pi is connected.`,
        restore: `Restore requested for ${name}. Applying automatically when the Pi is connected.`,
        restore_all: "Restore all requested. Applying automatically when the Pi is connected.",
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
    policyRevision.current++;
    try {
      setPolicy(await api.savePolicy(p));
    } catch (e) {
      setPolicyFresh(false);
      flash(e instanceof Error ? e.message : "Couldn't save settings");
      throw e;
    }
  }

  async function setArmed(armed: boolean) {
    if (!policy || !policyFresh || offline || armingBusy) return;
    unlockAudio(); setArmingBusy(true);
    try { await savePolicy({ ...policy, learning_mode: !armed }); }
    finally { setArmingBusy(false); }
  }

  const traffic = useTraffic(rawDevices);
  const rates = Object.fromEntries(Object.entries(traffic.byMac).map(([m, s]) => [m, s[s.length - 1] ?? 0]));
  const selectedDevice = devices.find((d) => d.mac === selected);
  const isolated = devices.filter((d) => isContained(d.status));
  const armed = policy ? !policy.learning_mode : false;
  const issues = deriveIssues(devices, events, policy, { now, canAct }).filter((i) => !doneIds.has(i.id));
  const groups = deviceGroups(devices, issues);
  const issueCounts = deviceIssueCounts(devices, issues);

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
      <header className="sticky top-0 z-30 bg-white/90 backdrop-blur-xl">
        <div className="flex h-16 items-center justify-between gap-2 px-3 sm:px-6">
          <button type="button" aria-label="CasaWarden Landing Page" onClick={onHome} className="flex items-center gap-2 rounded-lg"><Logo size={28} /><span className="hidden text-lg font-semibold sm:inline">CasaWarden</span></button>
          <div className="flex flex-wrap items-center gap-1">
            {isolated.length > 0 && canAct && <Button onClick={() => act("restore_all")} disabled={busy || offline} className="h-8">Restore all</Button>}
            <div className="hidden lg:block"><StorageBadge /></div>
            <SoundToggle muted={muted} onToggle={() => { unlockAudio(); setMuted((m) => !m); }} />
            <ThemeToggle theme={theme} onToggle={toggleTheme} />
            <SettingsToggle open={settingsOpen} onToggle={() => setSettingsOpen((value) => !value)} />
            <Button variant="plain" className="h-8 px-3" onClick={onLogout}>Sign out</Button>
          </div>
        </div>
      </header>
      <div className="flex min-h-[calc(100dvh-64px)]">
        <nav aria-label="Main navigation" className="sticky top-16 h-[calc(100dvh-64px)] w-36 shrink-0 space-y-2 px-2 py-6 sm:w-48 sm:px-4">
          {([{ value: "map", label: "Home" }, { value: "heatmap", label: "Activity" }, { value: "overview", label: "Prevention" }] as const).map((item) =>
            <button key={item.value} aria-current={tab === item.value ? "page" : undefined} onClick={() => setTab(item.value)}
              className={`w-full rounded-xl px-3 py-3 text-left text-sm font-medium transition-all ${tab === item.value ? "bg-ink text-white" : "text-ink-2 hover:bg-fill"}`}>{item.label}</button>)}
        </nav>
        <main className="min-w-0 flex-1 px-4 pb-32 pt-8 sm:px-8">
          <div className="mx-auto max-w-[1200px] space-y-5">
            {offline && <div role="alert" className="rounded-xl border border-hairline bg-fill p-4 text-sm">
              Dashboard updates unavailable. {connectionError} Last received data is retained. Agent connectivity cannot be determined from this error.
            </div>}
            {agentConnected === false && <p role="status" className="text-sm text-ink-3">Pi agent not connected. Check its service logs and API URL; access changes require the running Linux agent.</p>}
            {warnings.length > 0 && <div role="alert" className="rounded-xl border border-hairline p-3 text-xs text-ink-2">{warnings.join(" · ")}</div>}
            {Object.keys(commands).length > 0 && <p className="text-xs text-ink-3">{Object.keys(commands).length} command(s) awaiting agent acknowledgement. Check the audit log for results.</p>}
            {tab === "map" && <div className="animate-rise-in"><HomeMap devices={devices} rates={rates} groups={groups} issueCounts={issueCounts} theme={theme} onSelect={setSelected} bandwidth={<Bandwidth traffic={traffic} devices={devices}/>}
              status={<p className="flex items-center gap-2 text-xs text-ink-3"><span className={`h-2 w-2 rounded-full ${offline ? "bg-bad" : loaded ? "bg-ok" : "bg-gray-400"}`} />{offline ? "Updates unavailable" : loaded ? "Dashboard connected" : "Connecting"}{armed ? " · System engaged" : " · Learning mode"}</p>}
              controls={<>
                <button type="button" aria-label="Open tutorial" onClick={() => setTutorialOpen(true)} className="grid h-16 w-20 place-items-center rounded-full text-ink transition-transform hover:rotate-12 hover:bg-fill"><TurtleHelpIcon/></button>
              </>} /></div>}
            {tab === "heatmap" && <div className="animate-rise-in space-y-10">
              <Heatmap devices={devices} events={events} now={now} />
              <section><ActivityExplorer events={events} devices={devices} onSelect={setSelected} /></section>
              <OlderDevices devices={devices} now={now} onSelect={setSelected} />
              <ActivityView devices={devices} entries={audit} onAction={act} canAct={canAct && !offline} canRunAudit={canRunAudit && !offline} />
            </div>}
            {tab === "overview" && <div className="animate-rise-in space-y-6"><h1 className="t-head">Prevention</h1><AttentionList issues={issues} onFix={setFixing} /></div>}
          </div>
        </main>
      </div>
      {settingsOpen && <Modal title="Settings" onClose={() => setSettingsOpen(false)}>
        {!hasPolicy ? <Card className="p-5">Settings are unavailable because this server does not provide the policy route.</Card>
          : policy ? <SettingsView policy={policy} devices={devices} onSave={savePolicy} /> : <p>Settings are loading. Check the dashboard connection if this persists.</p>}
      </Modal>}
      {tutorialOpen && <Modal title="CasaWarden tutorial" onClose={() => setTutorialOpen(false)}>
        <div className="space-y-6 text-sm leading-relaxed">
          <section><h3 className="font-semibold">1. Home and Devices</h3><p>Tap a device to see its reported facts, traffic, alerts and AI advisor. Safe, Caution and Danger count devices once each. Unknown facts do not establish safety.</p></section>
          <section><h3 className="font-semibold">2. Monitoring and Protection</h3><p>Devices appear as they are discovered. Open Settings and enable Automatic protection to request an armed policy. The agent also needs local arm permission. New devices do not disable protection; routine monitoring continues in the background.</p></section>
          <section><h3 className="font-semibold">3. Activity and Audit</h3><p>Activity shows the heatmap and recent recorded events. Open an event for evidence and the recorded safety-gate decision. Run audit for a digest; open the audit log to inspect requested, applied, failed and simulated outcomes.</p></section>
          <section><h3 className="font-semibold">4. Prevention</h3><p>Review Protect your devices for suggested actions. Multiple issues can refer to one device; a system-wide learning-mode issue is not an extra device.</p></section>
          <section><h3 className="font-semibold">5. Safety and Recovery</h3><p>Protected devices, learning mode, startup warmup, cooldown and restore grace constrain automatic actions. Restore returns access; it does not clean or repair a device. Volume and trained-model findings are advisory in this build.</p></section>
          <section><h3 className="font-semibold">6. Connection and Settings</h3><p>The indicator reports dashboard connectivity, not an agent heartbeat. Pending commands need agent acknowledgement. Use the gear beside the theme button for policy and protected-device settings. Mock results are simulations.</p></section>
        </div>
      </Modal>}
      <TurtleParade />
      {USE_MOCK && <DemoControls />}

      {fixing && (
        <FixSheet
          issue={fixing}
          busy={busy}
          audioEnabled={!muted}
          onClose={() => setFixing(null)}
          onAction={runFix}
          onDone={markDone}
          onOpenDevice={(mac) => {
            setFixing(null);
            setSelected(mac);
          }}
        />
      )}

      {selectedDevice && <DeviceDetail onWarn={async (mac) => { try { await api.warn(mac); flash('Warning recorded.'); await refresh(); } catch(e) { flash(e instanceof Error ? e.message : 'Could not record warning'); } }} audioEnabled={!muted} device={selectedDevice} events={events} busy={busy} canAct={canAct} policy={policy} pending={commands[selectedDevice.mac]?.action || commands.all?.action} onClose={() => setSelected(null)} onAction={act} />}

      <div
        className={`fixed left-1/2 top-20 z-50 -translate-x-1/2 transition-all duration-500 ${toast ? "translate-y-0 opacity-100" : "pointer-events-none -translate-y-3 opacity-0"}`}
        style={{ transitionTimingFunction: "var(--ease-apple)" }}
      >
        <div className="rounded-full bg-ink/90 px-5 py-2.5 text-[18px] font-medium text-white shadow-[0_10px_30px_rgba(0,0,0,0.18)] backdrop-blur-xl">
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

/** Mock-only controls standing in for the phone and a cloud outage. */
function DemoControls() {
  const [offline, setOffline] = useState(mockServer.isOffline());
  const [running, setRunning] = useState(false);
  const [joined, setJoined] = useState(mockServer.guestJoined());
  const [away, setAway] = useState(mockServer.deviceAway());
  usePoll(() => setRunning(mockServer.attackRunning()), 300);

  return (
    <div className="fixed bottom-16 left-6 z-30 flex max-w-[calc(100vw-48px)] items-center gap-1.5 overflow-x-auto whitespace-nowrap rounded-full [&>*]:shrink-0 bg-white/80 p-1.5 pl-4 shadow-[0_10px_40px_rgba(0,0,0,0.12)] ring-1 ring-hairline backdrop-blur-xl">
      <span className="pr-1.5 text-[16px] font-semibold uppercase tracking-wide text-ink-3">Demo</span>
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
          mockServer.toggleDeviceAway();
          setAway(mockServer.deviceAway());
        }}
      >
        {away ? "Device returns" : "Device leaves"}
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
