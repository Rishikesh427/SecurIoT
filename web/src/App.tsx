import { useEffect, useRef, useState, type FormEvent } from 'react';
import { createApiClient, transport } from './api';
import { mockMode } from './config';
import type { AuditEntry, Device, NetworkEvent, StorageStatus, User } from './types';

const labels: Record<string, string> = { scan_arp: 'ARP scan detected', scan_targets: 'Multiple targets scanned', decoy_touch: 'Decoy contacted', new_domain: 'New domain contacted', new_device: 'Device discovered', block_wan: 'Block internet access', quarantine: 'Quarantine', restore: 'Restore access', restore_all: 'Restore all devices', normal: 'Normal', wan_blocked: 'Internet blocked', quarantined: 'Quarantined', offline: 'Offline' };
const label = (value: string) => labels[value] ?? value;
const message = (error: unknown) => error instanceof Error ? error.message : 'Request failed. Please try again.';
function date(value: string) { const d = new Date(value); return Number.isNaN(d.valueOf()) ? 'Unknown' : d.toLocaleString(); }

function StorageBadge() {
  if (mockMode) return <aside className="rounded-md bg-amber-50 p-4 text-amber-950"><strong>Fixture mock mode</strong><p>No backend connection. Reports are static fixtures; no actions are sent to devices.</p></aside>;
  const [mode, setMode] = useState<string>('');
  const [busy, setBusy] = useState(false);
  const pending = useRef(false);
  const alive = useRef(true);
  async function refresh() {
    if (pending.current) return;
    pending.current = true; setBusy(true);
    try {
      const response = await transport('/storage', { cache: 'no-store', signal: AbortSignal.timeout(10000) });
      if (!response.ok) throw new Error();
      const result: StorageStatus = await response.json();
      if (!['memory', 'postgres'].includes(result.mode)) throw new Error();
      if (alive.current) setMode(result.mode);
    } catch { if (alive.current) setMode('error'); }
    finally { pending.current = false; if (alive.current) setBusy(false); }
  }
  useEffect(() => { alive.current = true; void refresh(); const timer = setInterval(() => { if (!document.hidden) void refresh(); }, 10000); return () => { alive.current = false; clearInterval(timer); }; }, []);
  return <aside><p id="storage-status" role="status" data-mode={mode}>{mode === 'memory' ? 'Demo storage' : mode === 'postgres' ? 'Tiger Data connected' : mode === 'error' ? 'Storage status unavailable' : 'Checking storage…'}</p><p>{mode === 'memory' ? 'Changes are temporary and disappear when the API restarts.' : mode === 'postgres' ? 'Device reports and commands are stored in the database.' : mode === 'error' ? 'Check that the API is running, then try again.' : ''}</p><button disabled={busy} onClick={() => void refresh()}>Check storage</button></aside>;
}

function Inventory({ devices, restore, restoring }: { devices: Device[]; restore:(mac:string)=>void; restoring:string }) {
  const [query, setQuery] = useState('');
  const filtered = devices.filter(d => [d.label, d.name, d.ip, d.mac].some(v => v.toLowerCase().includes(query.trim().toLowerCase())));
  return <><label>Find a device<input type="search" value={query} onChange={e => setQuery(e.target.value)} placeholder="Name, IP or MAC" /></label>{!filtered.length ? <p>{devices.length ? 'No devices match your search.' : 'No devices reported yet. Connect the agent to upload inventory.'}</p> : <div className="scroll" tabIndex={0} role="region" aria-label="Device inventory"><table><caption>Reported state · times shown in your local timezone</caption><thead><tr>{['Device', 'Address', 'Risk', 'Status', 'Last seen', 'Action'].map(h => <th scope="col" key={h}>{h}</th>)}</tr></thead><tbody>{filtered.map(d => <tr key={d.mac}><td><strong>{d.label || d.name}</strong><small>{d.type}</small>{d.simulated && <span className="badge">Simulated</span>}</td><td>{d.ip}<small>{d.mac}</small></td><td><span className={`badge ${d.band}`}>{d.risk}/100 · {d.band}</span><small>{d.confidence} confidence</small>{d.reasons.length > 0 && <details><summary>Risk factors</summary><ul>{d.reasons.map((reason, i) => <li key={i}>{reason}</li>)}</ul></details>}</td><td>{label(d.status)}</td><td>{date(d.last_seen)}</td><td>{['wan_blocked','quarantined'].includes(d.status) ? <button disabled={mockMode || restoring === d.mac} onClick={() => restore(d.mac)}>{restoring === d.mac ? 'Queueing…' : 'Restore access'}</button> : <span className="muted">No restore needed</span>}</td></tr>)}</tbody></table></div>}</>;
}

function EventFeed({ events, devices }: { events: NetworkEvent[]; devices: Device[] }) {
  if (!events.length) return <p>No events reported yet. New activity will appear automatically.</p>;
  return <ol id="feed">{events.map(event => { const device = devices.find(d => d.mac === event.mac); return <li key={event.id}><h3>{label(event.kind)}</h3><small><time dateTime={event.ts}>{date(event.ts)}</time></small><p>{device?.label || device?.name || 'Device'} · {event.mac}</p><span className="badge">{event.source === 'simulator' ? 'Simulated event' : 'Agent report'}</span><p>{event.explanation?.plain_language}</p>{event.explanation?.recommended_next_step && <p><strong>Next step:</strong> {event.explanation.recommended_next_step}</p>}<small>{event.explanation_status === 'pending' ? 'Generating an optional explanation; template shown for now.' : event.explanation_status === 'template' ? 'Template explanation' : 'Generated explanation'}</small><p>Reported actions: {event.actions_taken.map(label).join(', ') || 'None'}</p>{event.would_have.length > 0 && <p>Would have: {event.would_have.map(label).join(', ')}. These actions were not applied.</p>}<details><summary>View evidence</summary><pre>{JSON.stringify(event.evidence, null, 2)}</pre><small>Event ID: {event.id}</small></details></li>; })}</ol>;
}

function AuditLog({ rows, digest, runDigest, busy }: {rows:AuditEntry[];digest:string;runDigest:()=>void;busy:boolean}) {
  return <section id="audit"><div className="heading"><h2>Audit log</h2><button disabled={busy || mockMode} onClick={runDigest}>{busy?'Generating…':'Generate digest'}</button></div><p>Requests become applied only after the agent acknowledges them. Seeded demo history is labelled.</p>{digest && <p role="status"><strong>Digest:</strong> {digest}</p>}{!rows.length ? <p>No audit entries yet.</p> : <div className="scroll" tabIndex={0} role="region" aria-label="Audit history"><table><thead><tr>{['Time','Actor','Action','Device','Outcome'].map(h=><th scope="col" key={h}>{h}</th>)}</tr></thead><tbody>{rows.map(row=><tr key={row.id}><td>{date(row.ts)}</td><td>{row.actor}{row.actor==='seeded-demo'&&<small>Seeded history</small>}</td><td>{label(row.action)}</td><td>{row.mac||'All / not applicable'}</td><td><span className={`badge ${row.outcome==='failed'?'high':row.outcome==='applied'?'low':'medium'}`}>{label(row.outcome)}</span></td></tr>)}</tbody></table></div>}</section>;
}

function Reports({ client }: { client: ReturnType<typeof createApiClient> }) {
  const [devices, setDevices] = useState<Device[] | null>(null);
  const [events, setEvents] = useState<NetworkEvent[] | null>(null);
  const [audit, setAudit] = useState<AuditEntry[] | null>(null);
  const [errors, setErrors] = useState(['', '', '']);
  const [updated, setUpdated] = useState('Loading reports…');
  const [busy, setBusy] = useState(false);
  const [restoring, setRestoring] = useState('');
  const [actionNotice, setActionNotice] = useState('');
  const [digest, setDigest] = useState('');
  const [digestBusy, setDigestBusy] = useState(false);
  const pending = useRef(false), alive = useRef(true);
  async function refresh() {
    if (pending.current) return;
    pending.current = true; setBusy(true);
    try {
      const results = await Promise.allSettled([client.request<Device[]>('/devices'), client.request<NetworkEvent[]>('/events?limit=100'), client.request<AuditEntry[]>('/audit')]);
      if (!alive.current) return;
      const nextErrors = results.map(result => result.status === 'rejected' ? message(result.reason) : Array.isArray(result.value) ? '' : 'Invalid server response.');
      if (!nextErrors[0] && results[0].status === 'fulfilled') setDevices(results[0].value as Device[]);
      if (!nextErrors[1] && results[1].status === 'fulfilled') setEvents(results[1].value as NetworkEvent[]);
      if (!nextErrors[2] && results[2].status === 'fulfilled') setAudit(results[2].value as AuditEntry[]);
      setErrors(nextErrors);
      setUpdated(nextErrors.some(Boolean) ? 'Some reports could not refresh. Previously loaded reports may be out of date.' : `Updated ${new Date().toLocaleTimeString()}. Checks every 10 seconds while this tab is visible.`);
    } finally { pending.current = false; if (alive.current) setBusy(false); }
  }
  async function restore(mac?: string) {
    if (mockMode || restoring) return;
    setRestoring(mac || 'all'); setActionNotice('');
    try {
      await client.request('/actions',{method:'POST',headers:{'Idempotency-Key':crypto.randomUUID()},body:JSON.stringify(mac?{action:'restore',mac}:{action:'restore_all'})});
      setActionNotice(`${mac?'Restore':'Restore all'} requested. Status changes only after the agent applies and acknowledges the command.`);
      await refresh();
    } catch (error) { setActionNotice(message(error)); }
    finally { setRestoring(''); }
  }
  async function runDigest() {
    setDigestBusy(true); setDigest('');
    try { const result=await client.request<{summary:string}>('/audit/run',{method:'POST'}); setDigest(result.summary); }
    catch (error) { setDigest(message(error)); }
    finally { setDigestBusy(false); }
  }
  useEffect(() => {
    alive.current = true; void refresh();
    const visible = () => { if (!document.hidden) void refresh(); };
    const timer = setInterval(visible, 10000); document.addEventListener('visibilitychange', visible);
    return () => { alive.current = false; clearInterval(timer); document.removeEventListener('visibilitychange', visible); };
  }, []);
  return <><div className="heading"><h1>Network overview</h1><div className="actions"><button disabled={mockMode || !!restoring} onClick={() => void restore()}>{restoring==='all'?'Queueing…':'Restore all devices'}</button><button disabled={busy} onClick={() => void refresh()}>Refresh reports</button></div></div><p role="status">{actionNotice || updated}</p><nav aria-label="Dashboard sections"><a href="#devices">Devices</a><a href="#events">Events</a><a href="#audit">Audit</a></nav><section id="devices"><h2>Devices</h2>{errors[0] && <p role="alert">{errors[0]} Use Refresh reports to retry.</p>}{devices ? <Inventory devices={devices} restore={mac=>void restore(mac)} restoring={restoring} /> : <p>{errors[0] ? 'Unable to load devices.' : 'Loading devices…'}</p>}</section><section id="events"><h2>Recent events</h2><p>Latest 100 events, newest first. Simulated activity is labelled.</p>{errors[1] && <p role="alert">{errors[1]} Use Refresh reports to retry.</p>}{events ? <EventFeed events={events} devices={devices ?? []} /> : <p>{errors[1] ? 'Unable to load events.' : 'Loading events…'}</p>}</section>{errors[2] && <p role="alert">{errors[2]} Use Refresh reports to retry.</p>}{audit ? <AuditLog rows={audit} digest={digest} runDigest={()=>void runDigest()} busy={digestBusy} /> : <section id="audit"><h2>Audit log</h2><p>{errors[2]?'Unable to load audit history.':'Loading audit history…'}</p></section>}</>;
}

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const clientRef = useRef<ReturnType<typeof createApiClient> | null>(null);
  if (!clientRef.current) clientRef.current = createApiClient({ onSessionExpired: () => { setUser(null); setError('Your session expired. Please sign in again.'); } });
  const client = clientRef.current;
  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = event.currentTarget; const data = new FormData(form);
    setBusy(true); setError('');
    try { const identity = await client.login(String(data.get('username')).trim(), String(data.get('password'))); form.reset(); setUser(identity); }
    catch (error) { setError(message(error)); }
    finally { setBusy(false); }
  }
  return <><header><a href="/">SecurIoT</a><span>Network overview{user && ` · ${user.username} (${user.role === 'admin' ? 'Admin' : 'Judge'})`}</span>{user && <button onClick={() => { client.logout(); setUser(null); setError(''); }}>Sign out</button>}</header><main>{user ? <Reports client={client} /> : <section id="login"><h1>Your network, in view.</h1><p>Sign in to review devices and recent activity.</p><form onSubmit={login}><label>Username<input name="username" autoComplete="username" required maxLength={100} autoFocus /></label><label>Password<input name="password" type="password" autoComplete="current-password" required maxLength={1024} /></label><p role="alert">{error}</p><button id="submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button></form><p>Use your configured dashboard account. Refreshing this page signs you out.</p></section>}<StorageBadge /></main></>;
}
