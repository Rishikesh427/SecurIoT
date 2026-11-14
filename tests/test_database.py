"""Opt-in real Tiger Data checks; inserted rows are always rolled back.

Set SECURIOT_TEST_DATABASE=1 after running python -m api.manage init-db.
"""
import json
import os
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from psycopg.types.json import Jsonb

from api.auth import verify_password
from api.db import Database
from api.manage import migrate, seed_judge
from api.settings import Settings

pytestmark = pytest.mark.skipif(os.getenv("SECURIOT_TEST_DATABASE") != "1", reason="Live database checks are opt-in")


def test_live_schema_seed_and_constraints():
    with Database(Settings.load()).connect() as conn:
        with conn.transaction(force_rollback=True):
            migrate(conn)
            names = {r["table_name"] for r in conn.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'securiot'")}
            assert {"devices", "events", "commands", "policy", "audit", "users"} <= names
            hypertables = conn.execute("SELECT hypertable_name FROM timescaledb_information.hypertables WHERE hypertable_schema = 'securiot'").fetchall()
            assert hypertables == [{"hypertable_name": "events"}]
            policy = conn.execute("SELECT * FROM policy").fetchone()
            assert policy["learning_mode"] is True
            username = "test-" + uuid4().hex
            assert seed_judge(conn, username, "first-random-test-password")
            assert not seed_judge(conn, username, "second-random-test-password")
            user = conn.execute("SELECT * FROM users WHERE username = %s", (username,)).fetchone()
            assert verify_password("first-random-test-password", user["password_hash"])
            assert user["password_hash"].startswith("$argon2id$")
            fixture = json.loads((Path(__file__).parents[1] / "contract/fixtures.json").read_text())
            event = fixture["events"][0]
            event_id = uuid4()
            sql = "INSERT INTO events (id, mac, ts, kind, evidence, source) VALUES (%s, %s, %s, %s, %s, %s)"
            values = (event_id, event["mac"], event["ts"], event["kind"], Jsonb(event["evidence"]), event["source"])
            conn.execute(sql, values)
            with pytest.raises(psycopg.errors.UniqueViolation):
                with conn.transaction():
                    conn.execute(sql, values)
            with pytest.raises(psycopg.errors.CheckViolation):
                with conn.transaction():
                    conn.execute("INSERT INTO commands (id, action) VALUES (%s, 'quarantine')", (uuid4(),))
