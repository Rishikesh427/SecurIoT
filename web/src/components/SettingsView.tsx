import { useEffect, useState, type ReactNode } from "react";
import type { Device, Policy } from "../types";
import { Button, Card, Row, Switch } from "./ui";

export function SettingsView({ policy, devices, onSave }: { policy: Policy; devices: Device[]; onSave: (p: Policy) => Promise<void> }) {
  const [draft, setDraft] = useState<Policy>(policy);
  const [saved, setSaved] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => setDraft(policy), [policy]);

  const dirty = JSON.stringify(draft) !== JSON.stringify(policy);
  const set = (fn: (p: Policy) => Policy) => {
    setDraft((p) => fn(structuredClone(p)));
    setSaved(false);
  };

  async function save() {
    setSaving(true);
    try {
      await onSave(draft);
      setSaved(true);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="mx-auto max-w-[680px] space-y-8 pb-24">
      <Group title="Protection" footer="New installs start in learning mode. Turn on automatic protection to let SecurIoT isolate threats on its own.">
        <Row label="Automatic protection" detail={draft.learning_mode ? "Learning mode, watch only" : "Threats are isolated automatically"}>
          <Switch label="Automatic protection" checked={!draft.learning_mode} onChange={(v) => set((p) => ({ ...p, learning_mode: !v }))} />
        </Row>
      </Group>

      <Group title="Response" footer="When protection is on, blocking and quarantine are applied together.">
        <Row label="Notify">
          <Switch label="Notify" checked={draft.ladder.notify} onChange={(v) => set((p) => ({ ...p, ladder: { ...p.ladder, notify: v } }))} />
        </Row>
        <Row label="Block internet access">
          <Switch label="Block internet" checked={draft.ladder.block_wan} onChange={(v) => set((p) => ({ ...p, ladder: { ...p.ladder, block_wan: v } }))} />
        </Row>
        <Row label="Quarantine" detail="Remove from Wi-Fi and prevent rejoining">
          <Switch label="Quarantine" checked={draft.ladder.quarantine} onChange={(v) => set((p) => ({ ...p, ladder: { ...p.ladder, quarantine: v } }))} />
        </Row>
      </Group>

      <Group title="Protected devices" footer="Protected devices are never acted on automatically.">
        {devices.map((d) => (
          <Row key={d.mac} label={d.label} detail={d.ip}>
            <Switch
              label={`Protect ${d.label}`}
              checked={draft.protected_macs.includes(d.mac)}
              onChange={(v) =>
                set((p) => ({ ...p, protected_macs: v ? [...new Set([...p.protected_macs, d.mac])] : p.protected_macs.filter((m) => m !== d.mac) }))
              }
            />
          </Row>
        ))}
      </Group>

      <div
        className={`fixed inset-x-0 bottom-6 z-30 flex justify-center transition-all duration-500 ${
          dirty || saved ? "translate-y-0 opacity-100" : "pointer-events-none translate-y-6 opacity-0"
        }`}
        style={{ transitionTimingFunction: "var(--ease-apple)" }}
      >
        <div className="flex items-center gap-2 rounded-full bg-white/80 p-1.5 pl-5 shadow-[0_10px_40px_rgba(0,0,0,0.12)] ring-1 ring-hairline backdrop-blur-xl">
          <span className="pr-2 text-[14px] text-ink-2">{saved && !dirty ? "Settings saved" : "Unsaved changes"}</span>
          {dirty && (
            <>
              <Button onClick={() => setDraft(policy)}>Discard</Button>
              <Button variant="primary" disabled={saving} onClick={save}>
                {saving ? "Saving" : "Save"}
              </Button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function Group({ title, footer, children }: { title: string; footer?: string; children: ReactNode }) {
  return (
    <section>
      <h3 className="mb-2 px-5 text-[13px] font-semibold uppercase tracking-wide text-ink-3">{title}</h3>
      <Card className="divide-y divide-hairline overflow-hidden">{children}</Card>
      {footer && <p className="mt-2 px-5 text-[12px] leading-relaxed text-ink-3">{footer}</p>}
    </section>
  );
}
