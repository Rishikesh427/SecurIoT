import psycopg
from psycopg.rows import dict_row


class Database:
    def __init__(self, settings):
        self.settings = settings

    def connect(self):
        return psycopg.connect(self.settings.database_url, connect_timeout=5,
                               options="-c search_path=securiot,public -c statement_timeout=10000",
                               row_factory=dict_row)

    def ready(self):
        with self.connect() as conn:
            return conn.execute("SELECT version FROM schema_migrations WHERE version = 1").fetchone() is not None

    def user_by_name(self, username):
        with self.connect() as conn:
            return conn.execute("SELECT id, username, password_hash, role, active FROM users WHERE username = %s", (username,)).fetchone()

    def user_by_id(self, user_id):
        with self.connect() as conn:
            return conn.execute("SELECT id, username, role, active FROM users WHERE id = %s", (user_id,)).fetchone()
