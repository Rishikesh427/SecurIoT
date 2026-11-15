"""Persistent, deployment-wide Gemini budget/cache. Storage failures fail closed."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time
import urllib.error
import urllib.request


class BudgetBlocked(RuntimeError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def connection():
    default = Path(os.getenv('XDG_STATE_HOME', str(Path.home()/'.local/state')))/'casawarden/gemini.sqlite3'
    path = Path(os.getenv('GEMINI_STATE_PATH', str(default)))
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    db = sqlite3.connect(path, timeout=10)
    try:
        os.chmod(path, 0o600)
        db.executescript('''CREATE TABLE IF NOT EXISTS usage(day INTEGER PRIMARY KEY, attempts INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS circuit(id INTEGER PRIMARY KEY, until REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS cache(key TEXT PRIMARY KEY, expires REAL NOT NULL, body TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS leases(key TEXT PRIMARY KEY, expires REAL NOT NULL);''')
    except BaseException:
        db.close()
        raise
    return db


def limit():
    value = int(os.getenv('GEMINI_DAILY_REQUEST_LIMIT', '50'))
    if not 0 <= value <= 10000: raise ValueError('Invalid Gemini request limit')
    return value


def status():
    try:
        db = connection()
        try:
            now = time.time(); day = int(now//86400)
            used = db.execute('SELECT attempts FROM usage WHERE day=?',(day,)).fetchone()
            pause = db.execute('SELECT until FROM circuit WHERE id=1').fetchone()
            return {'daily_limit':limit(), 'attempts_today':used[0] if used else 0,
                    'paused_until':pause[0] if pause and pause[0]>now else None,
                    'reset_at':(day+1)*86400, 'persistent':True}
        finally:db.close()
    except (OSError, sqlite3.Error, ValueError):
        return {'persistent':False,'reason':'usage_state_unavailable'}


def request_json(request, *, timeout, max_bytes=65536):
    """Reserve before sending (including failures); cache hits cost no requests."""
    credential = request.get_header('X-goog-api-key', '')
    key = hashlib.sha256(request.full_url.encode()+b'\0'+(request.data or b'')+b'\0'+credential.encode()).hexdigest()
    db = None
    reserved = False
    try:
        db = connection(); now = time.time(); day = int(now//86400)
        db.execute('BEGIN IMMEDIATE')
        db.execute('DELETE FROM cache WHERE expires<=?',(now,))
        cached = db.execute('SELECT body FROM cache WHERE key=?',(key,)).fetchone()
        if cached:
            db.commit()
            return json.loads(cached[0])
        paused = db.execute('SELECT until FROM circuit WHERE id=1').fetchone()
        if paused and paused[0]>now: raise BudgetBlocked('quota_paused')
        lease = db.execute('SELECT expires FROM leases WHERE key=?',(key,)).fetchone()
        if lease and lease[0]>now: raise BudgetBlocked('request_pending')
        db.execute('INSERT OR IGNORE INTO usage VALUES (?,0)',(day,))
        used = db.execute('SELECT attempts FROM usage WHERE day=?',(day,)).fetchone()[0]
        if used>=limit(): raise BudgetBlocked('daily_request_limit')
        db.execute('UPDATE usage SET attempts=attempts+1 WHERE day=?',(day,))
        db.execute('INSERT OR REPLACE INTO leases VALUES (?,?)',(key,now+max(60,timeout+30)))
        db.execute('DELETE FROM usage WHERE day<?',(day-7,))
        db.execute('DELETE FROM leases WHERE expires<=?',(now,))
        db.commit(); reserved=True
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw=response.read(max_bytes+1)
            if len(raw)>max_bytes: raise ValueError('Gemini response too large')
            value=json.loads(raw)
            candidate=value['candidates'][0]
            if candidate.get('finishReason')!='STOP' or not candidate.get('content',{}).get('parts'):
                raise ValueError('Incomplete Gemini response')
            db.execute('INSERT OR REPLACE INTO cache VALUES (?,?,?)',(key,time.time()+86400,json.dumps(value)))
            db.execute('DELETE FROM cache WHERE key IN (SELECT key FROM cache ORDER BY expires DESC LIMIT -1 OFFSET 512)')
            db.commit()
            return value
        except urllib.error.HTTPError as error:
            if error.code==429:
                db.execute('INSERT OR REPLACE INTO circuit VALUES (1,?)',(time.time()+86400,))
                db.commit()
            raise
    except (OSError, sqlite3.Error) as error:
        # HTTP/URL failures remain recognizable; storage failures never bypass limits.
        if isinstance(error, urllib.error.URLError) or (reserved and isinstance(error, TimeoutError)):raise
        raise BudgetBlocked('usage_state_unavailable') from None
    except ValueError as error:
        if not reserved:raise BudgetBlocked('usage_configuration_invalid') from None
        raise
    finally:
        if db is not None:
            try:
                db.rollback()
                if reserved:
                    db.execute('DELETE FROM leases WHERE key=?',(key,));db.commit()
            finally:db.close()
