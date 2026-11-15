"""Shared-contract validation and H8–12 routes."""
import hmac
import time
from datetime import datetime, timezone
from ipaddress import IPv4Address
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, AwareDatetime, field_validator

Mac = Annotated[str, Field(pattern=r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$')]
Action = Literal['block_wan', 'quarantine', 'restore', 'restore_all']


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid')


class Device(StrictModel):
    mac: Mac
    ip: IPv4Address
    name: str = Field(min_length=1)
    label: str
    type: str
    vendor: str | None
    model: str | None = None
    firmware: str | None = None
    identification: dict = Field(default_factory=dict)
    kev: Literal['confirmed', 'possible', 'none', 'unknown'] = 'unknown'
    ports: list[Annotated[int, Field(ge=1, le=65535)]]
    bytes_in: int = Field(ge=0)
    bytes_out: int = Field(ge=0)
    dests: list[str]
    last_seen: AwareDatetime
    snapshot_at: AwareDatetime | None = None
    simulated: bool
    has_feed: bool
    eol: bool | None
    default_creds: bool | None
    cloud_only: bool | None
    anomaly: float = Field(ge=0, le=40)
    risk: int = Field(ge=0, le=100)
    band: Literal['low', 'medium', 'high']
    confidence: Literal['low', 'medium', 'high']
    reasons: list[str]
    status: Literal['normal', 'wan_blocked', 'quarantined', 'offline']

    @field_validator('ports', 'dests')
    @classmethod
    def unique_items(cls, value):
        if len(value) != len(set(value)):
            raise ValueError('Items must be unique')
        return value


class Event(StrictModel):
    id: UUID
    mac: Mac
    ts: AwareDatetime
    kind: Literal['scan_arp', 'scan_targets', 'decoy_touch', 'new_domain', 'new_device', 'volume']
    evidence: dict
    actions_taken: list[Action]
    would_have: list[Action]
    source: Literal['agent', 'simulator']


class Ingest(StrictModel):
    devices: list[Device] = Field(max_length=1000)
    events: list[Event] = Field(max_length=1000)


class Ack(StrictModel):
    status: Literal['applied', 'failed']
    ts: AwareDatetime
    detail: str | None = None


def agent_auth(request: Request, key: str | None = Header(default=None, alias='X-API-Key')):
    expected = request.app.state.settings.agent_api_key
    if not expected or expected.startswith('GENERATE_'):
        raise HTTPException(503, 'Agent authentication not configured')
    if key is None or not hmac.compare_digest(key.encode(), expected.encode()):
        raise HTTPException(401, 'Invalid agent credentials')


def router(current_user):
    routes = APIRouter()

    @routes.get('/diagnostics', dependencies=[Depends(current_user)])
    def diagnostics(request: Request):
        from ml.securiot_ml import advisor as ai
        from ml.securiot_ml.usage_guard import status as usage_status
        import os
        state = request.app.state
        sync = getattr(state, 'last_sync', None)
        return {'agent': {'connected': bool(sync and time.time()-sync < 10),
                    'sync_age_seconds': round(time.time()-sync, 1) if sync else None,
                    'last_ingest': getattr(state, 'last_ingest', None), 'last_ack': getattr(state, 'last_ack', None)},
                'live_only': state.settings.live_only,
                'gemini': {'configured': ai.configured(), 'model': os.getenv('GEMINI_MODEL', ''),
                    'last_failure': ai.LAST_FAILURE, 'usage': usage_status(),
                    'pending': len(state.advisor.pending), 'cached': len(state.advisor.cache)},
                'note': 'Connection timestamps cover this API process since restart; no heartbeat means not yet observed.'}

    @routes.get('/dashboard', dependencies=[Depends(current_user)])
    def dashboard(request: Request, response: Response):
        db = request.app.state.db
        rows = db.devices()
        activity = db.events(100, 0)
        if request.app.state.settings.live_only:
            rows = [d for d in rows if not d.get('simulated')]
            activity = [e for e in activity if e.get('source') != 'simulator']
        policy = db.get_policy()
        response.headers['ETag'] = '"' + policy['etag'] + '"'
        sync = getattr(request.app.state, 'last_sync', None)
        return {'devices': request.app.state.advisor.decorate(rows, activity),
                'events': request.app.state.explanations.decorate(activity, rows),
                'audit': db.audit(), 'policy': policy['policy'],
                'agent_connected': bool(sync and time.time()-sync < 10)}

    @routes.post('/ingest', dependencies=[Depends(agent_auth)])
    def ingest(body: Ingest, request: Request):
        if request.app.state.settings.live_only and (any(d.simulated for d in body.devices) or any(e.source == 'simulator' for e in body.events)):
            raise HTTPException(409, 'Live API rejects simulated telemetry. Run the Pi agent with Linux enforcement.')
        result = request.app.state.db.ingest(body)
        request.app.state.last_ingest = time.time()
        return result

    @routes.get('/sync', dependencies=[Depends(agent_auth)])
    def sync(request: Request, response: Response, etag: str | None = None):
        request.app.state.last_sync = time.time()
        result = request.app.state.db.sync()
        headers = {'ETag': '"' + result['etag'] + '"', 'Cache-Control': 'no-store'}
        if etag == result['etag'] and not result['commands']:
            return Response(status_code=304, headers=headers)
        response.headers.update(headers)
        return result

    @routes.post('/commands/{command_id}/ack', status_code=204, dependencies=[Depends(agent_auth)])
    @routes.post('/ack', status_code=204, dependencies=[Depends(agent_auth)])
    def ack(command_id: UUID, body: Ack, request: Request):
        if request.app.state.settings.live_only and body.detail and 'mock enforcement' in body.detail:
            raise HTTPException(409, 'Mock acknowledgement rejected by live API. Restart the Pi agent with Linux enforcement.')
        request.app.state.db.ack(command_id, body)
        request.app.state.last_ack = time.time()
        return Response(status_code=204)

    @routes.get('/devices', dependencies=[Depends(current_user)])
    def devices(request: Request):
        from api.advisor import recent_events
        rows = request.app.state.db.devices()
        if request.app.state.settings.live_only:
            rows = [d for d in rows if not d.get('simulated')]
        return request.app.state.advisor.decorate(rows, recent_events(request.app.state.db))

    @routes.get('/events', dependencies=[Depends(current_user)])
    def events(request: Request, limit: int = 100, offset: int = 0):
        if not 1 <= limit <= 1000 or offset < 0:
            raise HTTPException(422, 'limit must be 1–1000 and offset nonnegative')
        events = request.app.state.db.events(limit, offset)
        if request.app.state.settings.live_only:
            events = [e for e in events if e.get('source') != 'simulator']
        return request.app.state.explanations.decorate(events, request.app.state.db.devices())

    return routes
