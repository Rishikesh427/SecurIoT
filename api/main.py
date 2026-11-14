"""Platform H4–8: database readiness, judge login, and reusable JWT auth."""
from contextlib import asynccontextmanager
from uuid import UUID

import jwt
import psycopg
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from api.auth import DUMMY_HASH, decode_token, issue_token, verify_password
from api.db import Database
from api.settings import Settings, environment

bearer = HTTPBearer(auto_error=False)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=1024)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserResponse(BaseModel):
    id: UUID
    username: str
    role: str


def unauthorized():
    return HTTPException(status_code=401, detail="Invalid credentials", headers={"WWW-Authenticate": "Bearer"})


def current_user(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
    if credentials is None:
        raise unauthorized()
    try:
        claims = decode_token(credentials.credentials, request.app.state.settings)
        user_id = UUID(claims["sub"])
    except (jwt.InvalidTokenError, ValueError, TypeError):
        raise unauthorized() from None
    user = request.app.state.db.user_by_id(user_id)
    if user is None or not user["active"]:
        raise unauthorized()
    return user


def create_app(settings=None, database=None):
    env = environment() if settings is None else {}

    @asynccontextmanager
    async def lifespan(app):
        app.state.settings = settings or Settings.load()
        app.state.db = database or Database(app.state.settings)
        yield

    root_path = settings.root_path if settings else env.get("ROOT_PATH", "")
    origins = settings.cors_origins if settings else env.get("CORS_ORIGINS", "http://localhost:5173")
    app = FastAPI(title="SecurIoT API", version="0.2.0", root_path=root_path, lifespan=lifespan)
    app.add_middleware(CORSMiddleware, allow_origins=[s.strip() for s in origins.split(",") if s.strip()],
                       allow_methods=["GET", "POST", "PUT"], allow_headers=["Authorization", "Content-Type", "X-API-Key"])

    @app.exception_handler(psycopg.Error)
    async def database_error(request, exc):
        return JSONResponse(status_code=503, content={"detail": "Database unavailable or not initialized"})

    @app.get("/healthz", tags=["platform"])
    def health():
        return {"status": "ok", "service": "securiot-api", "stage": "platform-h4-8"}

    @app.get("/readyz", tags=["platform"])
    def ready(request: Request):
        if not request.app.state.db.ready():
            raise HTTPException(status_code=503, detail="Database not initialized")
        return {"status": "ok", "database": "ready"}

    @app.post("/auth/login", response_model=TokenResponse, tags=["auth"])
    def login(body: LoginRequest, request: Request, response: Response):
        user = request.app.state.db.user_by_name(body.username)
        valid = verify_password(body.password, user["password_hash"] if user else DUMMY_HASH)
        if not valid or user is None or not user["active"]:
            raise unauthorized()
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        config = request.app.state.settings
        return TokenResponse(access_token=issue_token(user, config), expires_in=config.token_minutes * 60)

    @app.get("/auth/me", response_model=UserResponse, tags=["auth"])
    def me(user=Depends(current_user)):
        return user

    return app


app = create_app()
