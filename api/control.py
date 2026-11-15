"""Dashboard controls shared by PostgreSQL and demo storage."""
import asyncio
import time
from starlette.concurrency import run_in_threadpool
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import Field, StrictBool, model_validator

from api.telemetry import Action, Mac, StrictModel


class Ladder(StrictModel):
    notify: StrictBool = True
    block_wan: StrictBool = True
    quarantine: StrictBool = True


class Policy(StrictModel):
    learning_mode: StrictBool = True
    protected_macs: list[Mac] = Field(default_factory=list, max_length=1000)
    ladder: Ladder = Field(default_factory=Ladder)

    @model_validator(mode='after')
    def unique_protected(self):
        if len(self.protected_macs) != len(set(self.protected_macs)):
            raise ValueError('Protected MACs must be unique')
        return self


class ActionRequest(StrictModel):
    action: Action
    mac: Mac | None = None

    @model_validator(mode='after')
    def target(self):
        if self.action == 'restore_all':
            if 'mac' in self.model_fields_set:
                raise ValueError('restore_all must not specify mac')
        elif self.mac is None:
            raise ValueError('This action requires mac')
        return self


def check_action(body, policy, known):
    if body.mac is not None and not known:
        raise HTTPException(404, 'Device not found')
    if body.action in ('block_wan', 'quarantine'):
        if body.mac in policy['protected_macs']:
            raise HTTPException(409, 'Device is protected')
        if not policy['ladder'][body.action]:
            raise HTTPException(409, 'This ladder step is disabled')


def check_retry(command, body):
    if command['action'] != body.action or command.get('mac') != body.mac:
        raise HTTPException(409, 'Idempotency key already used for a different action')


def router(current_user):
    routes = APIRouter(tags=['controls'])

    @routes.get('/policy', response_model=Policy)
    def get_policy(request: Request, response: Response, user=Depends(current_user)):
        result = request.app.state.db.get_policy()
        response.headers['ETag'] = '"' + result['etag'] + '"'
        response.headers['Cache-Control'] = 'no-store'
        return result['policy']

    @routes.put('/policy', response_model=Policy)
    def put_policy(body: Policy, request: Request, response: Response,
                   if_match: str | None = Header(default=None), user=Depends(current_user)):
        result = request.app.state.db.put_policy(body, if_match)
        response.headers['ETag'] = '"' + result['etag'] + '"'
        response.headers['Cache-Control'] = 'no-store'
        return result['policy']

    @routes.post('/actions', status_code=202)
    async def action(body: ActionRequest, request: Request, response: Response, wait: bool = False,
               idempotency_key: UUID | None = Header(default=None), user=Depends(current_user)):
        db = request.app.state.db
        if request.app.state.settings.live_only and body.mac:
            device = next((d for d in db.devices() if d['mac'] == body.mac), None)
            if device and body.action in ('block_wan','quarantine') and (device.get('identification') or {}).get('manual_protected') is True:
                raise HTTPException(409, 'Device is protected by the Pi controller configuration')
            if device and device.get('simulated'):
                raise HTTPException(409, 'This is an old simulated record. Connect the live Linux agent and select a discovered device.')
        command = await run_in_threadpool(db.create_command, body, idempotency_key or uuid4(), user['username'])
        if not wait:
            return command
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            result = await run_in_threadpool(db.command_result, command['id'])
            if result and result['status'] != 'pending':
                response.status_code = 200
                return {**command, **result}
            await asyncio.sleep(.5)
        return {**command, 'status':'pending', 'detail':'The agent has not reported an outcome yet. Check that the Pi agent is running and connected.'}

    @routes.post('/devices/{mac}/warn')
    def warn(mac: Mac, request: Request, user=Depends(current_user)):
        return request.app.state.db.warn(mac, user['username'])

    return routes
