"""Run from repo root: python -m api.manage init-db"""
import argparse
from pathlib import Path
from uuid import uuid4

from api.auth import passwords
from api.db import Database
from api.settings import Settings, environment


def migrate(conn):
    # Serialize concurrent initializers; DDL and version marker commit together.
    conn.execute("SELECT pg_advisory_xact_lock(714281004)")
    conn.execute("CREATE SCHEMA IF NOT EXISTS securiot")
    conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())")
    for path in sorted(Path(__file__).with_name('migrations').glob('*.sql')):
        version = int(path.name.split('_', 1)[0])
        if not conn.execute('SELECT 1 FROM schema_migrations WHERE version = %s', (version,)).fetchone():
            conn.execute(path.read_text())
            conn.execute('INSERT INTO schema_migrations (version) VALUES (%s)', (version,))


def seed_judge(conn, username, password):
    if not username or len(username) > 100 or len(password) < 16 or password.startswith("GENERATE_"):
        raise ValueError("Set JUDGE_USERNAME and a random JUDGE_PASSWORD of at least 16 characters")
    # Re-running never resets a user's password, role, or disabled status.
    return conn.execute(
        "INSERT INTO users (id, username, password_hash, role) VALUES (%s, %s, %s, 'judge') ON CONFLICT (username) DO NOTHING RETURNING id",
        (uuid4(), username, passwords.hash(password)),
    ).fetchone() is not None


def initialize(settings, username, password):
    with Database(settings).connect() as conn:
        migrate(conn)
        return seed_judge(conn, username, password)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["init-db"])
    parser.parse_args()
    try:
        env = environment()
        created = initialize(Settings.load(), env.get("JUDGE_USERNAME", "judge"), env.get("JUDGE_PASSWORD", ""))
    except Exception as exc:
        # Driver errors can contain connection details: do not print credentials.
        print(f"Database initialization failed ({type(exc).__name__}). Check database access and seed settings.")
        raise SystemExit(1) from None
    print("Schema ready; judge " + ("created." if created else "already exists (unchanged)."))


if __name__ == "__main__":
    main()
