import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg import sql
from fastapi import HTTPException


class Database:
    def __init__(self, settings):
        self.settings = settings

    def connect(self):
        return psycopg.connect(self.settings.database_url, connect_timeout=5,
                               options="-c search_path=securiot,public -c statement_timeout=10000",
                               row_factory=dict_row)

    def ready(self):
        with self.connect() as conn:
            return conn.execute("SELECT version FROM schema_migrations WHERE version = 1").fetchone() is not None

    def user_by_name(self, username):
        with self.connect() as conn:
            return conn.execute("SELECT id, username, password_hash, role, active FROM users WHERE username = %s", (username,)).fetchone()

    def user_by_id(self, user_id):
        with self.connect() as conn:
            return conn.execute("SELECT id, username, role, active FROM users WHERE id = %s", (user_id,)).fetchone()

    def ingest(self, batch):
        counts = {'accepted_devices': 0, 'accepted_events': 0}
        with self.connect() as conn:
            # A transaction-scoped lock serializes UUID checks across all API workers.
            # This avoids a second hypertable and enforces global UUID identity.
            conn.execute('SELECT pg_advisory_xact_lock(714281005)')
            for event in batch.events:
                existing = conn.execute('SELECT * FROM events WHERE id = %s', (event.id,)).fetchone()
                data = event.model_dump(mode='json')
                if existing:
                    from api.telemetry import Event
                    if Event.model_validate(existing) != event:
                        raise HTTPException(409, 'Event UUID already exists with different content')
                    continue
                self._insert(conn, 'events', data)
                counts['accepted_events'] += 1
            for device in sorted(batch.devices, key=lambda d: d.mac):
                data = device.model_dump(mode='json')
                columns = list(data)
                query = sql.SQL('INSERT INTO devices ({}) VALUES ({}) ON CONFLICT (mac) DO UPDATE SET {} WHERE EXCLUDED.last_seen > devices.last_seen RETURNING mac').format(
                    sql.SQL(',').join(map(sql.Identifier, columns)),
                    sql.SQL(',').join(sql.Placeholder() for _ in columns),
                    sql.SQL(',').join(sql.SQL('{} = EXCLUDED.{}').format(sql.Identifier(c), sql.Identifier(c)) for c in columns if c != 'mac'))
                if conn.execute(query, [Jsonb(v) if isinstance(v, (list, dict)) else v for v in data.values()]).fetchone():
                    counts['accepted_devices'] += 1
        return counts

    @staticmethod
    def _insert(conn, table, data):
        conn.execute(sql.SQL('INSERT INTO {} ({}) VALUES ({})').format(
            sql.Identifier(table), sql.SQL(',').join(map(sql.Identifier, data)),
            sql.SQL(',').join(sql.Placeholder() for _ in data)),
            [Jsonb(v) if isinstance(v, (dict, list)) else v for v in data.values()])

    def sync(self):
        with self.connect() as conn:
            # One statement gives policy and pending commands the same snapshot.
            row = conn.execute("""
                SELECT jsonb_build_object(
                    'etag', revision::text,
                    'policy', jsonb_build_object('learning_mode', learning_mode,
                        'protected_macs', protected_macs, 'ladder', ladder),
                    'commands', (SELECT COALESCE(jsonb_agg(jsonb_strip_nulls(
                        jsonb_build_object('id', c.id, 'created_at', c.created_at,
                            'action', c.action, 'mac', c.mac)) ORDER BY c.created_at, c.id), '[]'::jsonb)
                        FROM commands c WHERE c.status = 'pending')
                ) AS payload FROM policy WHERE id = true
            """).fetchone()
            if row is None:
                raise HTTPException(503, 'Policy not initialized')
            return row['payload']

    def ack(self, command_id, ack):
        with self.connect() as conn:
            row = conn.execute('SELECT status, ack_ts, detail FROM commands WHERE id = %s FOR UPDATE', (command_id,)).fetchone()
            if row is None:
                raise HTTPException(404, 'Command not found')
            if row['status'] != 'pending':
                if (row['status'], row['ack_ts'], row['detail']) != (ack.status, ack.ts, ack.detail):
                    raise HTTPException(409, 'Command already acknowledged differently')
                return
            conn.execute('UPDATE commands SET status = %s, ack_ts = %s, detail = %s WHERE id = %s', (ack.status, ack.ts, ack.detail, command_id))

    def devices(self):
        from api.telemetry import Device
        with self.connect() as conn:
            return [Device.model_validate(row).model_dump(mode='json') for row in conn.execute('SELECT * FROM devices ORDER BY mac')]

    def events(self, limit, offset):
        from api.telemetry import Event
        with self.connect() as conn:
            return [Event.model_validate(row).model_dump(mode='json') for row in conn.execute('SELECT * FROM events ORDER BY ts DESC, id DESC LIMIT %s OFFSET %s', (limit, offset))]
