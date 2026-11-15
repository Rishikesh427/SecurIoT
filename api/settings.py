"""Environment precedence: process > api/.env > repository .env."""
import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import dotenv_values

ENV_FILE = Path(__file__).with_name(".env")


def environment():
    return {**dotenv_values(ENV_FILE.parent.parent / '.env'), **dotenv_values(ENV_FILE), **os.environ}


@dataclass(frozen=True)
class Settings:
    database_url: str
    jwt_secret: str
    jwt_issuer: str = "securiot"
    jwt_audience: str = "securiot-dashboard"
    token_minutes: int = 60
    root_path: str = ""
    cors_origins: str = "http://localhost:5173"
    agent_api_key: str = ""
    storage_mode: str = 'auto'
    judge_username: str = 'judge'
    judge_password: str = field(default='', repr=False)

    @classmethod
    def load(cls):
        env = environment()
        url = env.get("DATABASE_URL", "")
        secret = env.get("JWT_SECRET", "")
        mode = env.get('STORAGE_MODE', 'auto')
        if mode not in ('auto', 'postgres', 'memory'):
            raise ValueError('STORAGE_MODE must be auto, postgres, or memory')
        if mode != 'postgres' and int(env.get('WEB_CONCURRENCY', '1')) != 1:
            raise ValueError('In-memory fallback requires one API worker')
        if mode != 'memory' and (not url or "URL_ENCODED_PASSWORD" in url):
            raise ValueError("Set DATABASE_URL in api/.env or the process environment")
        if not secret or len(secret) < 32 or secret.startswith("GENERATE_"):
            raise ValueError("JWT_SECRET must be a random value of at least 32 characters")
        minutes = int(env.get("JWT_EXPIRE_MINUTES", "60"))
        if not 1 <= minutes <= 1440:
            raise ValueError("JWT_EXPIRE_MINUTES must be between 1 and 1440")
        return cls(url, secret, env.get("JWT_ISSUER", "securiot"),
                   env.get("JWT_AUDIENCE", "securiot-dashboard"), minutes,
                   env.get("ROOT_PATH", ""), env.get("CORS_ORIGINS", "http://localhost:5173"), env.get("AGENT_API_KEY", ""),
                   mode, env.get('JUDGE_USERNAME','judge'), env.get('JUDGE_PASSWORD',''))
