"""Authenticated action history and Person C digest integration."""
import inspect

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.concurrency import run_in_threadpool


def router(current_user):
    routes = APIRouter(tags=['audit'])

    @routes.get('/audit')
    def history(request: Request, user=Depends(current_user)):
        return request.app.state.db.audit()

    @routes.post('/audit/run')
    async def run_digest(request: Request, user=Depends(current_user)):
        from ml.securiot_ml import digest as person_c_digest
        function = getattr(person_c_digest, 'digest', None)
        if not callable(function):
            raise HTTPException(503, "Person C's digest(history) function is not available yet")
        history = request.app.state.db.audit()
        result = await run_in_threadpool(function, history)
        if inspect.isawaitable(result):
            result = await result
        if isinstance(result, str):
            result = {'summary': result}
        if not isinstance(result, dict) or not isinstance(result.get('summary'), str) or not result['summary'].strip():
            raise HTTPException(502, "Person C's digest returned an invalid result")
        return {'summary': result['summary']}

    return routes
