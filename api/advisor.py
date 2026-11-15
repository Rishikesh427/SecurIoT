"""Authenticated dashboard advice with a bounded worker queue and fact cache."""
import asyncio
import copy
import hashlib
import json
import time
from collections import OrderedDict, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import Field, field_validator

from api.telemetry import Mac, StrictModel
from ml.securiot_ml import advisor as ai


class Turn(StrictModel):
    role: Literal['user', 'assistant']
    text: str = Field(min_length=1, max_length=800)


class Chat(StrictModel):
    mac: Mac
    question: str = Field(min_length=1, max_length=500)
    history: list[Turn] = Field(default_factory=list, max_length=6)

    @field_validator('question')
    @classmethod
    def nonblank(cls, value):
        if not value.strip():
            raise ValueError('Question must not be blank')
        return value.strip()


def recent_events(db):
    """Only event kinds from the last day enter advisor context; no raw evidence."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=1)
    return [{'mac': e['mac'], 'kind': e['kind']} for e in db.events(1000, 0)
            if datetime.fromisoformat(e['ts'].replace('Z', '+00:00')) >= cutoff]


class AdvisorService:
    RETRY = 60
    TTL = 900

    def __init__(self, workers=2, max_pending=16, max_cache=256):
        self.pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix='advisor')
        self.lock = RLock()
        self.cache = OrderedDict()
        self.pending = {}
        self.calls = OrderedDict()
        self.configured = ai.configured()
        self.max_pending, self.max_cache = max_pending, max_cache
        self.note_limit = max(1, workers - 1)
        self.closed = False

    def allow(self, user, limit=20, window=60):
        now = time.monotonic()
        with self.lock:
            expired = [key for key, q in self.calls.items() if not q or now - q[-1] >= window]
            for key in expired:
                del self.calls[key]
            if user not in self.calls and len(self.calls) >= 1024:
                raise HTTPException(429, 'Advisor is busy; try again shortly')
            q = self.calls.setdefault(user, deque())
            while q and now - q[0] >= window:
                q.popleft()
            if len(q) >= limit:
                raise HTTPException(429, 'Too many advisor requests; wait a minute')
            q.append(now)

    def _cached(self, key):
        hit = self.cache.get(key)
        if hit and hit[0] > time.monotonic():
            self.cache.move_to_end(key)
            return copy.deepcopy(hit[1])
        self.cache.pop(key, None)
        return None

    def _submit(self, key, function, *args, cache=True):
        # Caller holds the lock. Bound running + queued jobs, including chat/triage.
        if key in self.pending:
            return self.pending[key]
        if self.closed or len(self.pending) >= self.max_pending:
            return None
        if key.startswith('note:') and sum(k.startswith('note:') for k in self.pending) >= self.note_limit:
            return None
        future = self.pool.submit(function, *copy.deepcopy(args))
        self.pending[key] = future

        def finish(done):
            with self.lock:
                self.pending.pop(key, None)
                if cache and not done.cancelled() and done.exception() is None:
                    result = done.result()
                    ttl = self.TTL if result.get('source') == 'gemini' else self.RETRY
                    self.cache[key] = (time.monotonic() + ttl, copy.deepcopy(result))
                    self.cache.move_to_end(key)
                    while len(self.cache) > self.max_cache:
                        self.cache.popitem(last=False)
        future.add_done_callback(finish)
        return future

    def decorate(self, devices, events=()):
        by_mac = defaultdict(list)
        for event in events:
            by_mac[event['mac']].append(event)
        output = []
        for device in devices:
            context = by_mac[device['mac']]
            key = 'note:' + ai.cache_key(device, context)
            with self.lock:
                result = self._cached(key)
                if result:
                    state = 'ready' if result['source'] == 'gemini' else 'unavailable'
                else:
                    future = self._submit(key, ai.note, device, context) if self.configured else None
                    state = 'pending' if future is not None else 'unavailable' if self.configured else 'off'
            advice = result or ai.fallback(device)
            output.append({**copy.deepcopy(device), 'risk_adjusted': advice['risk_adjusted'],
                           'ai': {**advice, 'status': state}})
        return output

    async def run(self, key, function, *args, cache=True):
        with self.lock:
            result = self._cached(key) if cache else None
            if result is not None:
                return result
            future = self._submit(key, function, *args, cache=cache)
        if future is None:
            raise HTTPException(503, 'Advisor is busy; try again shortly')
        try:
            return await asyncio.wait_for(asyncio.shield(asyncio.wrap_future(future)), timeout=10)
        except (TimeoutError, OSError, ValueError):
            raise HTTPException(503, 'Advisor is unavailable; try again shortly') from None

    def close(self):
        with self.lock:
            self.closed = True
        self.pool.shutdown(wait=False, cancel_futures=True)


def router(current_user):
    routes = APIRouter(tags=['advisor'])

    @routes.post('/advisor/chat')
    async def chat(body: Chat, request: Request, user=Depends(current_user)):
        service, db = request.app.state.advisor, request.app.state.db
        service.allow(user['username'])
        device = next((d for d in db.devices() if d['mac'] == body.mac), None)
        if device is None:
            raise HTTPException(404, 'Device not found')
        events = [e for e in recent_events(db) if e['mac'] == body.mac]
        history = [t.model_dump() for t in body.history]
        return await service.run(str(uuid4()), ai.chat, device, history, body.question, events, cache=False)

    @routes.get('/advisor/triage')
    async def triage(request: Request, user=Depends(current_user)):
        service, db = request.app.state.advisor, request.app.state.db
        service.allow(user['username'])
        events = recent_events(db)
        devices = service.decorate(db.devices(), events)
        inputs = sorted([{'mac': d['mac'], 'facts': ai.facts(d, [e for e in events if e['mac'] == d['mac']]),
                          'risk_adjusted': d['risk_adjusted']} for d in devices], key=lambda d: d['mac'])
        key = 'triage:' + hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()
        return await service.run(key, ai.triage, devices, events)

    return routes
