"""Deterministic audit summaries; no network or optional model is required."""
from collections import Counter


def _summarize(rows):
    counts = Counter((row['action'], row['outcome']) for row in rows)
    detections = sum(count for (action, outcome), count in counts.items()
                     if action.startswith('detected:'))
    parts = [f'{detections} detection(s)']
    labels = {'block_wan': 'internet block(s)', 'quarantine': 'quarantine(s)',
              'restore': 'device restore(s)', 'restore_all': 'restore-all operation(s)'}
    for action, label in labels.items():
        parts.append(f"{counts[action, 'applied']} {label} reported applied")
    outcomes = Counter(row['outcome'] for row in rows
                       if not row['action'].startswith('detected:'))
    parts.extend((f"{outcomes['requested']} request(s) awaiting acknowledgement",
                  f"{outcomes['failed']} failed action(s)",
                  f"{outcomes['would_have']} proposed action(s), not applied"))
    return '; '.join(parts) + '.'


def digest(history):
    """Summarize the supplied audit window, never infer current device state.

    Seeded examples and simulator reports must not inflate actual activity.
    The API supplies at most its latest 1,000 audit entries, not a full week.
    """
    groups = {'Recorded activity': [], 'Simulator activity': [], 'Seeded demo history': []}
    seen = set()
    for row in history:
        key = str(row['id'])
        if key in seen:
            continue
        seen.add(key)
        actor = row['actor']
        group = ('Seeded demo history' if actor == 'seeded-demo' else
                 'Simulator activity' if actor == 'simulator' else 'Recorded activity')
        groups[group].append(row)
    if not seen:
        return {'summary': 'No audit activity recorded yet.'}
    sections = [f'Audit summary of {len(seen)} available entries (latest 1,000 maximum).']
    for name, rows in groups.items():
        if rows:
            sections.append(f'{name} ({len(rows)} entries): {_summarize(rows)}')
        elif name == 'Recorded activity':
            sections.append('Recorded activity: none yet.')
    sections.append('Simulator activity and seeded examples are not evidence of real containment. '
                    'Applied outcomes are reports, not independent verification. '
                    'Containment does not fix a device; restore does not mean it is safe. '
                    'Check current device status before taking further action.')
    return {'summary': ' '.join(sections)}


def consumer_digest(history):
    """Three short bullets from the same audit window, excluding demo examples."""
    unique = {str(row['id']): row for row in history}
    real = [row for row in unique.values() if row['actor'] not in ('simulator', 'seeded-demo')]
    examples = len(unique) - len(real)
    counts = Counter((row['action'], row['outcome']) for row in real)
    alerts = sum(count for (action, _), count in counts.items() if action.startswith('detected:'))
    restrictions = sum(counts[action, 'applied'] for action in ('block_wan', 'quarantine'))
    restores = sum(counts[action, 'applied'] for action in ('restore', 'restore_all'))
    pending = sum(count for (action, outcome), count in counts.items() if outcome == 'requested' and not action.startswith('detected:'))
    failed = sum(count for (action, outcome), count in counts.items() if outcome == 'failed' and not action.startswith('detected:'))
    proposed = sum(count for (action, outcome), count in counts.items() if outcome == 'would_have' and not action.startswith('detected:'))
    def count(number, singular, plural=None):
        return f"{number} {singular if number == 1 else (plural or singular + 's')}"

    return [
        f"{count(alerts, 'warning')} in the available history. A warning alone does not prove an attack."
        + (f" {count(examples, 'demo/sample entry', 'demo/sample entries')} excluded." if examples else ''),
        f"Access was reported blocked {count(restrictions, 'time')} and restored {count(restores, 'time')}. Blocking access does not fix a device.",
        f"{count(pending, 'request')} still waiting; {failed} failed; {count(proposed, 'suggested action')} not taken. Check the audit log for details.",
    ]
