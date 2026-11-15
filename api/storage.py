"""Single-process demo storage and a one-way outage switch.

Memory never silently reconciles with PostgreSQL. Restart deliberately to return.
"""
import copy
import sqlite3
import json
from datetime import datetime, timezone
from threading import RLock
from uuid import NAMESPACE_URL, uuid4, uuid5

import psycopg
from fastapi import HTTPException

from api.auth import passwords
from api.control import Policy, check_action, check_retry


class MemoryDatabase:
    def __init__(self, settings):
        self.lock = RLock()
        self.conn = sqlite3.connect(':memory:', check_same_thread=False)
        self.conn.executescript('''
            CREATE TABLE devices (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE events (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE commands (id TEXT PRIMARY KEY, payload TEXT NOT NULL, status TEXT NOT NULL, ack TEXT);
            CREATE TABLE audit (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
        ''')
        self.policy = Policy().model_dump()
        self.revision = 1
        self.epoch = uuid4().hex
        self.users = {}
        now = datetime.now(timezone.utc)
        seeded = [('301','notify','applied'), ('302','block_wan','would_have'),
                  ('303','quarantine','would_have'), ('304','restore','applied')]
        for index, (suffix, action, outcome) in enumerate(seeded, 1):
            entry = {'id':f'00000000-0000-4000-8000-000000000{suffix}',
                     'ts':now.replace(microsecond=0).isoformat(), 'actor':'seeded-demo',
                     'action':action, 'mac':None, 'command_id':None, 'outcome':outcome}
            self.conn.execute('INSERT INTO audit VALUES (?,?)', (entry['id'], json.dumps(entry)))
        password = settings.judge_password
        if len(password) >= 16 and not password.startswith('GENERATE_'):
            user_id = uuid5(NAMESPACE_URL, 'securiot-demo:' + settings.judge_username)
            self.users[str(user_id)] = {'id':user_id, 'username':settings.judge_username,
                'password_hash':passwords.hash(password), 'role':'judge', 'active':True}

    def close(self):
        self.conn.close()

    def remember_user(self, user):
        if not user:
            return
        with self.lock:
            remembered = {}
            for key in list(self.users):
                if self.users[key]['username'] == user['username'] and key != str(user['id']):
                    remembered = self.users[key]
                    del self.users[key]
            existing = self.users.get(str(user['id']), remembered)
            self.users[str(user['id'])] = {**existing, **copy.deepcopy(user)}

    def ready(self):
        return True

    def audit(self):
        from api.audit_history import merge_history
        with self.lock:
            rows = merge_history(self._rows('audit'), self._rows('events'))
            return [{key:value for key,value in row.items() if value is not None} for row in rows]

    def user_by_name(self, username):
        with self.lock:
            return copy.deepcopy(next((u for u in self.users.values() if u['username'] == username and 'password_hash' in u), None))

    def user_by_id(self, user_id):
        with self.lock:
            return copy.deepcopy(self.users.get(str(user_id)))

    def create_user(self, username, password_hash):
        with self.lock:
            if any(user['username'] == username for user in self.users.values()):
                raise HTTPException(409, 'Username is already in use')
            user = {'id': uuid4(), 'username': username, 'password_hash': password_hash,
                    'role': 'judge', 'active': True}
            self.users[str(user['id'])] = user
            return copy.deepcopy(user)

    def _rows(self, table):
        # Internal constant table names only.
        return [json.loads(row[0]) for row in self.conn.execute(f'SELECT payload FROM {table}')]

    def ingest(self, batch):
        from api.telemetry import Device, Event
        counts = {'accepted_devices':0, 'accepted_events':0}
        with self.lock, self.conn:
            for event in batch.events:
                key = str(event.id)
                old = self.conn.execute('SELECT payload FROM events WHERE id=?', (key,)).fetchone()
                if old:
                    if Event.model_validate_json(old[0]) != event:
                        raise HTTPException(409, 'Event UUID already exists with different content')
                    continue
                self.conn.execute('INSERT INTO events VALUES (?,?)', (key,event.model_dump_json()))
                counts['accepted_events'] += 1
            for device in batch.devices:
                old = self.conn.execute('SELECT payload FROM devices WHERE id=?', (device.mac,)).fetchone()
                if old:
                    prior = Device.model_validate_json(old[0])
                    if (prior.snapshot_at or prior.last_seen) >= (device.snapshot_at or device.last_seen):
                        continue
                self.conn.execute('INSERT OR REPLACE INTO devices VALUES (?,?)', (device.mac,device.model_dump_json()))
                counts['accepted_devices'] += 1
            if self.conn.execute('SELECT count(*) FROM events').fetchone()[0] > 10000 or self.conn.execute('SELECT count(*) FROM devices').fetchone()[0] > 1000:
                raise HTTPException(503, 'Demo storage capacity reached; export or restart the demo')
        return counts

    def get_policy(self):
        with self.lock:
            return {'etag':f'memory-{self.epoch}-{self.revision}', 'policy':copy.deepcopy(self.policy)}

    def put_policy(self, body, if_match=None):
        with self.lock, self.conn:
            if if_match is not None and if_match != '"' + self.get_policy()['etag'] + '"':
                raise HTTPException(412, 'Policy changed; reload before saving')
            data = body.model_dump()
            if self.policy != data:
                for command in self._rows('commands'):
                    if command['action'] in ('block_wan','quarantine') and (
                        data['learning_mode'] or command.get('mac') in data['protected_macs'] or not data['ladder'][command['action']]):
                        self.conn.execute("UPDATE commands SET status='cancelled' WHERE id=? AND status='pending'", (command['id'],))
                        audit = self.conn.execute('SELECT payload FROM audit WHERE id=?', (command['id'],)).fetchone()
                        if audit:
                            entry = json.loads(audit[0]); entry.update(outcome='failed', ts=datetime.now(timezone.utc).isoformat())
                            self.conn.execute('UPDATE audit SET payload=? WHERE id=?', (json.dumps(entry),command['id']))
                self.policy = data
                self.revision += 1
            return self.get_policy()

    def create_command(self, body, command_id, actor='judge'):
        with self.lock, self.conn:
            key = str(command_id)
            old = self.conn.execute('SELECT payload FROM commands WHERE id=?', (key,)).fetchone()
            if old:
                command = json.loads(old[0])
                check_retry(command, body)
                return command
            known = body.mac is None or self.conn.execute('SELECT 1 FROM devices WHERE id=?', (body.mac,)).fetchone() is not None
            check_action(body, self.policy, known)
            if self.conn.execute('SELECT count(*) FROM commands').fetchone()[0] >= 1000:
                raise HTTPException(503, 'Demo command capacity reached')
            command = {'id':key, 'created_at':datetime.now(timezone.utc).isoformat(), **body.model_dump(exclude_none=True)}
            self.conn.execute("INSERT INTO commands VALUES (?,?,'pending',NULL)", (key,json.dumps(command)))
            entry = {'id':key, 'ts':command['created_at'], 'actor':actor, 'action':body.action,
                     'mac':body.mac, 'command_id':key, 'outcome':'requested'}
            self.conn.execute('INSERT INTO audit VALUES (?,?)', (key,json.dumps(entry)))
            return command

    def sync(self):
        with self.lock:
            commands = [json.loads(row[0]) for row in self.conn.execute("SELECT payload FROM commands WHERE status='pending'")]
            commands.sort(key=lambda c:(c['created_at'],c['id']))
            return {**self.get_policy(), 'commands':commands}

    def ack(self, command_id, ack):
        from api.telemetry import Ack
        with self.lock, self.conn:
            key = str(command_id)
            old = self.conn.execute('SELECT status,ack FROM commands WHERE id=?', (key,)).fetchone()
            if old is None:
                raise HTTPException(404, 'Command not found')
            if old[0] not in ('pending', 'cancelled'):
                if Ack.model_validate_json(old[1]) != ack:
                    raise HTTPException(409, 'Command already acknowledged differently or cancelled')
                return
            self.conn.execute('UPDATE commands SET status=?,ack=? WHERE id=?', (ack.status,ack.model_dump_json(),key))
            audit = self.conn.execute('SELECT payload FROM audit WHERE id=?', (key,)).fetchone()
            if audit:
                entry = json.loads(audit[0]); entry.update(outcome=ack.status, ts=ack.ts.isoformat())
                self.conn.execute('UPDATE audit SET payload=? WHERE id=?', (json.dumps(entry),key))

    def devices(self):
        with self.lock:
            return sorted(self._rows('devices'), key=lambda d:d['mac'])

    def events(self, limit, offset):
        with self.lock:
            rows = self._rows('events')
            rows.sort(key=lambda e:(datetime.fromisoformat(e['ts'].replace('Z','+00:00')),e['id']), reverse=True)
            return rows[offset:offset+limit]


class Storage:
    METHODS = {'audit','ready','user_by_name','user_by_id','create_user','ingest','sync','ack','devices','events','get_policy','put_policy','create_command'}
    WRITES = {'create_user','ingest','ack','put_policy','create_command'}

    def __init__(self, primary, settings):
        self.primary = primary
        self.mode = settings.storage_mode
        self.memory = MemoryDatabase(settings)
        self.using_memory = self.mode == 'memory'
        self.reason = 'configured' if self.using_memory else None
        self.lock = RLock()
        self.last_policy = None

    def status(self):
        # No lock: the response middleware calls this on the event loop for every
        # request, and waiting here behind a slow database call stalled the whole
        # server (even /healthz). Reading the current flags is safe without it.
        memory, reason = self.using_memory, self.reason
        return {'mode':'memory' if memory else 'postgres',
                'demo_storage':memory, 'persistent':not memory,
                'badge':'Demo storage' if memory else 'Tiger Data',
                'reason':reason, 'recovery':'restart' if memory else None}

    def close(self):
        self.memory.close()

    def __getattr__(self, name):
        if name not in self.METHODS:
            raise AttributeError(name)

        def call(*args, **kwargs):
            with self.lock:
                if self.using_memory:
                    return getattr(self.memory, name)(*args, **kwargs)
                try:
                    result = getattr(self.primary, name)(*args, **kwargs)
                except (psycopg.OperationalError, psycopg.InterfaceError) as exc:
                    # Do not conceal schema errors, constraint errors, or timeouts
                    # unrelated to a lost connection by switching stores.
                    state = getattr(exc, 'sqlstate', None)
                    disconnected = state is None or state.startswith('08') or state in ('57P01','57P02','57P03')
                    if self.mode != 'auto' or not disconnected:
                        raise
                    self.using_memory = True
                    self.reason = 'database_unavailable'
                    if self.last_policy:
                        safe = {**self.last_policy, 'learning_mode':True}
                        self.memory.put_policy(Policy.model_validate(safe))
                    if name in self.WRITES:
                        # A connection loss during COMMIT has an uncertain result.
                        # Never replay that write silently against a second store.
                        raise HTTPException(503, 'Database write outcome uncertain; switched to demo storage. Refresh storage status before retrying.') from None
                    return getattr(self.memory, name)(*args, **kwargs)
                if name in ('user_by_name','user_by_id'):
                    if result:
                        self.memory.remember_user(result)
                    else:
                        # Honor account deletion observed while PostgreSQL works.
                        for key, user in list(self.memory.users.items()):
                            if (name == 'user_by_id' and key == str(args[0])) or (name == 'user_by_name' and user['username'] == args[0]):
                                del self.memory.users[key]
                elif name in ('sync','get_policy','put_policy'):
                    self.last_policy = copy.deepcopy(result['policy'])
                return result
        return call
