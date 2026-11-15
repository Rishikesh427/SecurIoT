import { useRef, useState } from "react";
import { Search } from "lucide-react";
import { api, USE_MOCK } from "../api/client";
import type { AdvisorTriage, AdvisorTurn, Device } from "../types";
import { Button, Card, SectionTitle } from "./ui";
import { Modal } from "./Modal";
import { PublicResearch } from "./PublicResearch";
import { RiskBreakdown } from "./RiskBreakdown";
import { ReadAloud } from "./ReadAloud";

const quickQuestions = ["What should I do first?", "Is it safe to keep this device?", "How do I protect it?"];

export function DeviceAdvisor({ device, audioEnabled = true }: { device: Device; audioEnabled?: boolean }) {
  const [question, setQuestion] = useState("");
  const [turns, setTurns] = useState<AdvisorTurn[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [source, setSource] = useState<"gemini" | "rules" | null>(null);
  const [breakdown, setBreakdown] = useState(false);
  const inFlight = useRef(false);
  const advice = device.ai;
  const deviceType = !device.type || ['unknown', 'generic', 'iot', 'device'].includes(device.type.toLowerCase()) ? 'device' : device.type.toLowerCase();
  const assessment = `This ${deviceType} is ${device.band} risk.`;
  const nextStep = advice?.next_step || "Review the reported device facts and available fixes.";

  async function ask(text: string) {
    const q = text.trim();
    if (!q || inFlight.current || USE_MOCK) return;
    inFlight.current = true; setBusy(true); setError(""); setQuestion("");
    const history = turns.slice(-6).map(t => ({ ...t, text: t.text.slice(0, 800) }));
    setTurns(previous => [...previous, { role: "user", text: q }]);
    try {
      const result = await api.advisorChat(device.mac, q, history);
      setSource(result.source);
      setTurns(previous => [...previous, { role: "assistant", text: result.answer }]);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load advice. Try again.");
      setQuestion(q);
    } finally { inFlight.current = false; setBusy(false); }
  }

  return <section aria-label="Device Assessment" className="space-y-3">
    <h3 className="px-1 text-[17px] font-semibold tracking-wide text-ink-3">Score</h3>
    <Card className="space-y-5 px-5 py-4 leading-relaxed">
      <strong className="block text-[40px] tabular-nums" aria-label="Device Score">{100-device.risk}</strong>
      <p>{assessment} <button type="button" onClick={() => setBreakdown(true)} className="italic underline underline-offset-4">Why?</button></p>
      <div className="flex items-start justify-between gap-3"><p><strong>Next Step:</strong> {nextStep}</p>
        <ReadAloud text={`${assessment} Next step: ${nextStep}`} enabled={audioEnabled} label="Read Next Step" iconOnly />
      </div>
      {USE_MOCK && <p className="text-sm text-ink-3">Connect to the live API to ask the advisor.</p>}
      <form className="flex items-center gap-2" onSubmit={e => { e.preventDefault(); void ask(question); }}>
        <label className="min-w-0 flex-1"><span className="sr-only">Ask about the next steps</span>
          <input className="w-full rounded-full border border-hairline bg-white px-4 py-3 outline-none focus:ring-2 focus:ring-ink/20"
            value={question} maxLength={500} disabled={USE_MOCK || busy} onChange={e => setQuestion(e.target.value)} placeholder="Ask about the next steps" />
        </label>
        <button type="submit" aria-label="Ask Advisor" disabled={USE_MOCK || busy || !question.trim()} className="grid h-12 w-12 shrink-0 place-items-center rounded-full bg-fill transition-transform hover:scale-105 active:scale-95 disabled:opacity-40"><Search size={22} /></button>
      </form>
      <div className="flex flex-wrap gap-2">{quickQuestions.map(q => <Button key={q} className="h-auto min-h-11 whitespace-normal py-2 text-left text-sm" disabled={busy || USE_MOCK} onClick={() => void ask(q)}>{q}</Button>)}</div>
      <div role="log" aria-label="Advisor Conversation" aria-live="polite" className="max-h-80 space-y-4 overflow-y-auto">
        {turns.map((turn, i) => <div key={i} className={`animate-row-in rounded-xl p-3 ${turn.role === "user" ? "bg-fill" : "border border-hairline"}`}>
          <p className="whitespace-pre-wrap break-words"><strong>{turn.role === "user" ? "You" : "Advisor"}:</strong> {turn.text}</p>
          {turn.role === "assistant" && <ReadAloud text={turn.text} enabled={audioEnabled} label="Read Answer" iconOnly />}
        </div>)}
        {busy && <p>Thinking…</p>}
      </div>
      {source === "rules" && <p className="text-sm text-ink-3">Local rules reply; Gemini is unavailable.</p>}
      {error && <p role="alert" className="text-bad">{error}</p>}
    </Card>
    {breakdown && <Modal title="Rules Risk Breakdown" onClose={() => setBreakdown(false)}><div className="space-y-6"><RiskBreakdown device={device} /><PublicResearch mac={device.mac}/></div></Modal>}
  </section>;
}

export function AdvisorPriorities({ devices, onSelect }: { devices: Device[]; onSelect: (mac: string) => void }) {
  const [result, setResult] = useState<AdvisorTriage | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const inFlight = useRef(false);
  async function prioritise() {
    if (inFlight.current || USE_MOCK) return;
    inFlight.current = true; setBusy(true); setError("");
    try { setResult(await api.advisorTriage()); }
    catch (err) { setError(err instanceof Error ? err.message : "Couldn't rank devices. Try again."); }
    finally { inFlight.current = false; setBusy(false); }
  }
  return <section aria-label="Advisor priorities">
    <SectionTitle>What should I fix first?</SectionTitle>
    <Card className="space-y-3 px-5 py-4 text-[18px]">
      <p className="text-ink-2">Get a suggested fix order, then open a device to ask for specific steps.</p>
      <Button onClick={() => void prioritise()} disabled={USE_MOCK || busy || !devices.length}>{busy ? "Reviewing…" : "Prioritize devices"}</Button>
      {USE_MOCK && <p className="text-ink-3">AI advice needs the live API.</p>}
      {error && <p role="alert" className="text-bad">{error}</p>}
      {result && <>
        <p className="text-ink-3">{result.source === "gemini" ? "Suggested by Gemini; devices beyond the first 12 follow by score." : "Rules-based order; Gemini is unavailable."} This is a snapshot; refresh after changes.</p>
        <ol className="list-decimal space-y-2 pl-5">{result.order.filter(row => devices.some(d => d.mac === row.mac)).map(row => {
          const device = devices.find(d => d.mac === row.mac)!;
          return <li key={row.mac}><button className="font-medium underline underline-offset-2" onClick={() => onSelect(row.mac)}>{device.label || device.name}</button>: {row.why}</li>;
        })}</ol>
      </>}
    </Card>
  </section>;
}
