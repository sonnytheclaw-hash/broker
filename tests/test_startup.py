import os
import pytest
from importlib import import_module, reload

def test_startup_fails_without_secrets(monkeypatch):
    monkeypatch.delenv("BROKER_OUTBOUND_HMAC_SECRET", raising=False)
    monkeypatch.delenv("MOLTBOOK_API_KEY", raising=False)
    
    with pytest.raises(RuntimeError, match="CRITICAL: BROKER_OUTBOUND_HMAC_SECRET is not set"):
        # We need to reload app.py to trigger the top-level evaluation
        import app
        reload(app)

def test_startup_fails_without_moltbook_key(monkeypatch):
    monkeypatch.setenv("BROKER_OUTBOUND_HMAC_SECRET", "test-secret")
    monkeypatch.delenv("MOLTBOOK_API_KEY", raising=False)
    
    with pytest.raises(RuntimeError, match="CRITICAL: MOLTBOOK_API_KEY is not set"):
        import app
        reload(app)
