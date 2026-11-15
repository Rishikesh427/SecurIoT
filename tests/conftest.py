"""Isolate persistent Gemini accounting between tests; never spend real quota."""
import pytest


@pytest.fixture(autouse=True)
def isolated_gemini_usage(tmp_path, monkeypatch):
    monkeypatch.setenv('GEMINI_STATE_PATH',str(tmp_path/'gemini.sqlite3'))
    monkeypatch.setenv('GEMINI_DAILY_REQUEST_LIMIT','50')
