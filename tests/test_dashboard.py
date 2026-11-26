"""Smoke test: the dashboard script runs top to bottom without raising.

Works without the emulator running (the sidebar then shows a connection message)."""
from streamlit.testing.v1 import AppTest


def test_dashboard_loads_without_exceptions():
    at = AppTest.from_file("dashboard/app.py", default_timeout=60).run()
    assert not at.exception, [e.value for e in at.exception]
