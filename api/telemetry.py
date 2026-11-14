"""Shared-contract validation and H8–12 routes."""
import hmac
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

    @routes.post('/ingest', dependencies=[Depends(agent_auth)])
    def ingest(body: Ingest, request: Request):
        return request.app.state.db.ingest(body)

    @routes.get('/sync', dependencies=[Depends(agent_auth)])
    def sync(request: Request, response: Response, etag: str | None = None):
        result = request.app.state.db.sync()
        headers = {'ETag': '"' + result['etag'] + '"', 'Cache-Control': 'no-store'}
        if etag == result['etag'] and not result['commands']:
            return Response(status_code=304, headers=headers)
        response.headers.update(headers)
        return result

    @routes.post('/commands/{command_id}/ack', status_code=204, dependencies=[Depends(agent_auth)])
    @routes.post('/ack', status_code=204, dependencies=[Depends(agent_auth)])
    def ack(command_id: UUID, body: Ack, request: Request):
        request.app.state.db.ack(command_id, body)
        return Response(status_code=204)

    @routes.get('/devices', dependencies=[Depends(current_user)])
    def devices(request: Request):
        from api.advisor import recent_events
        return request.app.state.advisor.decorate(request.app.state.db.devices(), recent_events(request.app.state.db))

    @routes.get('/events', dependencies=[Depends(current_user)])
    def events(request: Request, limit: int = 100, offset: int = 0):
        if not 1 <= limit <= 1000 or offset < 0:
            raise HTTPException(422, 'limit must be 1–1000 and offset nonnegative')
        events = request.app.state.db.events(limit, offset)
        return request.app.state.explanations.decorate(events, request.app.state.db.devices())

    return routes
