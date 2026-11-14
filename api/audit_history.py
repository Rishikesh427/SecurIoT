"""Audit views derived from durable events and dashboard command records.

Projecting events also covers history ingested before this view was introduced.
Stable IDs and the ingest UUID constraint make retries safe without dual writes.
"""
from datetime import datetime
from uuid import NAMESPACE_URL, uuid5


def merge_history(commands, events, limit=1000):
    rows = [dict(row) for row in commands]
    for event in events:
        event_id = str(event['id'])
        base = {'ts': event['ts'], 'mac': str(event['mac']),
                'actor': event['source'], 'event_id': event_id}
        entries = [('detected:' + event['kind'], 'applied')]
        entries.extend((action, 'applied') for action in set(event['actions_taken']))
        entries.extend((action, 'would_have') for action in set(event['would_have'])
                       if action not in event['actions_taken'])
        for action, outcome in entries:
            rows.append({**base, 'id': str(uuid5(NAMESPACE_URL,
                f'securiot:audit:event:{event_id}:{action}:{outcome}')),
                'action': action, 'outcome': outcome})

    def order(row):
        ts = row['ts']
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        return ts, str(row['id'])

    return sorted(rows, key=order, reverse=True)[:limit]
