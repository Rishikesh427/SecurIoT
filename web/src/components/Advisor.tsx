import { useRef, useState } from "react";
import { api, USE_MOCK } from "../api/client";
import type { AdvisorTriage, AdvisorTurn, Device } from "../types";
import { Button, Card, SectionTitle } from "./ui";

const quickQuestions = ["What should I do first?", "Is it safe to keep this device?", "How do I harden it?"];
const inputStyle = "w-full rounded-xl border border-hairline bg-white px-3 py-2 text-[14px] outline-none focus:ring-2 focus:ring-ink/20";

/** Key this component by MAC so replies can never move to another device's chat. */
export function DeviceAdvisor({ device }: { device: Device }) {
  const [question, setQuestion] = useState("");
  const [turns, setTurns] = useState<AdvisorTurn[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [source, setSource] = useState<"gemini" | "rules">("gemini");
  const inFlight = useRef(false);
  const advice = device.ai;
  const guessed = ["unknown", "generic", "iot", "device", ""].includes(device.type.toLowerCase());

  async function ask(text: string) {
    const q = text.trim();
    if (!q || inFlight.current || USE_MOCK) return;
    inFlight.current = true;
    setBusy(true); setError(""); setQuestion("");
    const history = turns.slice(-6).map(t => ({ ...t, text: t.text.slice(0, 800) }));
    setTurns(previous => [...previous, { role: "user", text: q }]);
    try {
      const result = await api.advisorChat(device.mac, q, history);
      setSource(result.source);
      setTurns(previous => [...previous, { role: "assistant", text: result.answer }]);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Couldn't load advice. Try again.");
      setQuestion(q);
    } finally {
      inFlight.current = false; setBusy(false);
    }
  }

  return <section aria-label="Device AI advisor" className="space-y-3">
    <h3 className="px-1 text-[13px] font-semibold uppercase tracking-wide text-ink-3">AI assessment & advice</h3>
    <Card className="space-y-3 px-5 py-4 text-[14px] leading-relaxed">
      <p className="text-ink-2">Gemini explains and advises. It never decides what gets contained.</p>
      {advice && <>
        <p className="font-medium">Rules {device.risk} · AI {advice.delta >= 0 ? "+" : ""}{advice.delta} (max ±10) · Displayed {device.risk_adjusted ?? device.risk}/100</p>
        <p className="text-[12px] text-ink-3">The color band reflects the rules score. AI advice does not change protection.</p>
        <p>{advice.assessment}</p>
        {advice.status === "ready" ? <>
          <p className="text-[12px] text-ink-2">Gemini confidence: {advice.confidence}</p>
          {guessed && <p><strong>AI guess:</strong> {advice.likely_type}</p>}
          <p><strong>Expected behavior (hypothesis):</strong> {advice.expected_behavior}</p>
          <p><strong>Top risk:</strong> {advice.top_risk}</p>
          {advice.delta !== 0 && <p><strong>Score adjustment:</strong> {advice.delta_reason}</p>}
        </> : <p className="text-ink-3">{advice.status === "pending" ? "Gemini is preparing an assessment. Rules-based advice is shown meanwhile." : advice.status === "off" ? "Gemini is off. Rules-based advice remains available." : "Gemini is unavailable. Rules-based advice is shown."}</p>}
        <p><strong>Next step:</strong> {advice.next_step}</p>
      </>}
      {USE_MOCK && <p className="text-ink-3">Connect to the live API to ask Gemini for advice.</p>}
      <div className="flex flex-wrap gap-2">{quickQuestions.map(q =>
        <Button key={q} className="h-auto min-h-9 text-left text-[12px]" disabled={busy || USE_MOCK} onClick={() => void ask(q)}>{q}</Button>)}</div>
      <div role="log" aria-label="Advisor conversation" aria-live="polite" className="max-h-80 space-y-3 overflow-y-auto">
        {turns.map((turn, i) => <p key={i} className="whitespace-pre-wrap break-words"><strong>{turn.role === "user" ? "You" : "Advisor"}:</strong> {turn.text}</p>)}
        {busy && <p>Thinking…</p>}
      </div>
      {source === "rules" && <p className="text-ink-3">This reply uses local rules because Gemini is unavailable.</p>}
      {error && <p role="alert" className="text-bad">{error}</p>}
      <form className="space-y-2" onSubmit={e => { e.preventDefault(); void ask(question); }}>
        <label className="block">Your question
          <input className={inputStyle} value={question} maxLength={500} disabled={USE_MOCK || busy} onChange={e => setQuestion(e.target.value)} placeholder="Ask about the next steps" />
        </label>
        <Button type="submit" disabled={USE_MOCK || busy || !question.trim()}>Ask advisor</Button>
      </form>
    </Card>
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
    <Card className="space-y-3 px-5 py-4 text-[14px]">
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
