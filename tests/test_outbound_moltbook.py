import hmac, hashlib, json, uuid
import os
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
import respx
from httpx import Response

os.environ["BROKER_OUTBOUND_HMAC_SECRET"] = "test-outbound-hmac"
os.environ["MOLTBOOK_API_KEY"] = "test-moltbook-key"
os.environ["MOLTBOOK_SUBMOLT_ALLOWLIST"] = "general,tech"
os.environ["MOLTBOOK_DAILY_POST_BUDGET"] = "10"
os.environ["MOLTBOOK_PER_SUBMOLT_COOLDOWN_SECONDS"] = "1800"

from app import app, sign_payload

client = TestClient(app)

def _build_payload(sender="main_agent", request_id=None, ts=None, **data_overrides):
    payload = {
        "sender": sender,
        "recipient": "broker",
        "type": "moltbook.post.v1",
        "request_id": request_id or str(uuid.uuid4()),
        "timestamp": ts or datetime.now(timezone.utc).isoformat(),
        "payload": {
            "kind": "post",
            "submolt": "general",
            "title": "Test post",
            "content": "Hello from broker outbound test",
        }
    }
    payload["payload"].update(data_overrides)
    
    # Signature calculation expects no signature field in raw_body
    sig = sign_payload(payload, b"test-outbound-hmac")
    payload["signature"] = sig
    return payload

def test_rejects_missing_signature():
    payload = _build_payload(submolt="tech")
    del payload["signature"]
    resp = client.post("/outbound/moltbook", json=payload)
    assert resp.status_code == 401
    assert "Missing signature" in resp.json()["detail"]

def test_rejects_invalid_signature():
    payload = _build_payload(submolt="tech")
    payload["signature"] = "deadbeef" * 8
    resp = client.post("/outbound/moltbook", json=payload)
    assert resp.status_code == 401
    assert "Invalid cryptographic signature" in resp.json()["detail"]

def test_rejects_sender_other_than_main_agent():
    payload = _build_payload(sender="conny")
    resp = client.post("/outbound/moltbook", json=payload)
    assert resp.status_code == 403
    assert "Unauthorized sender" in resp.json()["detail"]

@respx.mock
def test_rejects_replayed_request_id():
    respx.post("https://www.moltbook.com/api/v1/posts").mock(return_value=Response(200, json={"id": "123"}))
    rid = str(uuid.uuid4())
    payload = _build_payload(request_id=rid)
    
    r1 = client.post("/outbound/moltbook", json=payload)
    r2 = client.post("/outbound/moltbook", json=payload)
    assert r1.status_code == 200
    assert r2.status_code == 409
    assert "Replay attack" in r2.json()["detail"]

def test_rejects_stale_timestamp():
    old_ts = "2026-01-01T00:00:00+00:00"
    payload = _build_payload(ts=old_ts)
    resp = client.post("/outbound/moltbook", json=payload)
    assert resp.status_code == 400
    assert "expired" in resp.json()["detail"]

def test_rejects_submolt_not_in_allowlist():
    payload = _build_payload(submolt="evilsubmolt")
    resp = client.post("/outbound/moltbook", json=payload)
    assert resp.status_code == 403
    assert "submolt_not_allowed" in resp.json()["detail"]

def test_rejects_title_over_200():
    payload = _build_payload(title="x" * 201)
    resp = client.post("/outbound/moltbook", json=payload)
    assert resp.status_code == 400
    assert "title_invalid_length" in resp.json()["detail"]

def test_rejects_content_over_4000():
    payload = _build_payload(content="x" * 4001)
    resp = client.post("/outbound/moltbook", json=payload)
    assert resp.status_code == 400
    assert "content_too_long" in resp.json()["detail"]

def test_rejects_comment_without_post_id():
    payload = _build_payload(kind="comment")
    if "post_id" in payload["payload"]:
        del payload["payload"]["post_id"]
    resp = client.post("/outbound/moltbook", json=payload)
    assert resp.status_code == 400
    assert "post_id_required" in resp.json()["detail"]

def test_rejects_content_containing_api_key_pattern():
    payload = _build_payload(content="Check this out: sk-proj-abc123def456789...")
    resp = client.post("/outbound/moltbook", json=payload)
    assert resp.status_code == 400
    assert "content_contains_secret" in resp.json()["detail"]

def test_rejects_content_containing_moltbook_key_pattern():
    payload = _build_payload(content="Token: moltbook_sk_12345678901234567890")
    resp = client.post("/outbound/moltbook", json=payload)
    assert resp.status_code == 400
    assert "content_contains_secret" in resp.json()["detail"]

@respx.mock
def test_happy_path_post_returns_moltbook_id():
    respx.post("https://www.moltbook.com/api/v1/posts").mock(return_value=Response(200, json={"id": "post_abc123"}))
    payload = _build_payload(submolt="tech")
    resp = client.post("/outbound/moltbook", json=payload)
    assert resp.status_code == 200
    assert resp.json()["moltbook_id"] == "post_abc123"


