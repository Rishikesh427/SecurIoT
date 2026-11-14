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
