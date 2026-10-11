"""Automated tests for VaultSync desktop API client."""

import pytest
import httpx

from vaultsync_desktop.api_client import (
    ApiClient,
    AuthenticationError,
    ConflictError,
    InsecureConnectionError,
    MigrationRequiredError,
    NetworkConnectionError,
    RateLimitError,
)


def test_base_url_security_validation():
    """Verify that loopback HTTP is accepted while remote plain HTTP is strictly rejected."""
    # Permitted loopback URLs
    ApiClient("http://127.0.0.1:8000")
    ApiClient("http://localhost:8000")
    ApiClient("http://[::1]:8000")
    ApiClient("https://remote.vaultsync.internal:8443")

    # Rejected non-loopback HTTP URLs
    with pytest.raises(InsecureConnectionError) as exc_remote:
        ApiClient("http://192.168.1.50:8000")
    assert "Plain HTTP connection to '192.168.1.50' rejected" in str(exc_remote.value)

    with pytest.raises(InsecureConnectionError):
        ApiClient("http://vault.example.com")

    # Rejected invalid schemes
    with pytest.raises(InsecureConnectionError):
        ApiClient("ftp://127.0.0.1:8000")


@pytest.mark.anyio
async def test_registration_does_not_transmit_master_password_or_keys(monkeypatch):
    """Verify that register() transmits only account_password and wrapped envelope,

    and never leaks vault_master_password or raw keys.
    """
    captured_requests = []

    class MockTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            captured_requests.append(request)
            return httpx.Response(
                201,
                json={
                    "account_id": "acc-123",
                    "username": "alice",
                    "kdf_salt": "MDEyMzQ1Njc4OWFiY2RlZg==",
                    "created_at": "2026-10-12T00:00:00Z",
                },
            )

    client = ApiClient("http://127.0.0.1:8000")
    orig_client = httpx.AsyncClient
    monkeypatch.setattr(
        "httpx.AsyncClient",
        lambda *args, **kwargs: orig_client(*args, transport=MockTransport(), **{k: v for k, v in kwargs.items() if k != "transport"}),
    )

    salt_b64 = "MDEyMzQ1Njc4OWFiY2RlZg=="
    wrapped_key_json = '{"version":1,"ciphertext":"wrapped-data"}'
    account_pwd = "MyServerAccountPassword2026!"

    res = await client.register(
        username="alice",
        account_password=account_pwd,
        kdf_salt=salt_b64,
        wrapped_vault_key=wrapped_key_json,
    )
    assert res["account_id"] == "acc-123"

    assert len(captured_requests) == 1
    req = captured_requests[0]
    import json
    body = json.loads(req.content.decode("utf-8"))

    # Assert exactly the required fields are present
    assert set(body.keys()) == {"username", "account_password", "kdf_salt", "wrapped_vault_key"}
    assert body["username"] == "alice"
    assert body["account_password"] == account_pwd
    assert body["kdf_salt"] == salt_b64
    assert body["wrapped_vault_key"] == wrapped_key_json

    # Explicit negative check: ensure no leak of master_password, kek, or raw_vek
    body_str = req.content.decode("utf-8").lower()
    assert "master_password" not in body_str
    assert "kek" not in body_str
    assert "raw_vek" not in body_str


@pytest.mark.anyio
async def test_api_client_error_mappings(monkeypatch):
    """Verify that HTTP response codes map to typed exceptions."""
    responses_queue = [
        httpx.Response(401, json={"detail": "Invalid credentials"}),
        httpx.Response(403, json={"detail": "Account requires password migration."}),
        httpx.Response(409, json={"detail": "Conflict: expected revision 1, but current revision is 2"}),
        httpx.Response(429, json={"detail": "Too many failed login attempts."}),
    ]

    class MockTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            return responses_queue.pop(0)

    orig_client = httpx.AsyncClient
    monkeypatch.setattr(
        "httpx.AsyncClient",
        lambda *args, **kwargs: orig_client(*args, transport=MockTransport(), **{k: v for k, v in kwargs.items() if k != "transport"}),
    )

    client = ApiClient("http://127.0.0.1:8000")

    # 401
    with pytest.raises(AuthenticationError) as exc_401:
        await client.login("alice", "wrong_pwd")
    assert "Invalid credentials" in str(exc_401.value)

    # 403 Migration
    with pytest.raises(MigrationRequiredError) as exc_403:
        await client.login("alice", "pwd")
    assert "migration" in str(exc_403.value).lower()

    # 409 Conflict
    with pytest.raises(ConflictError) as exc_409:
        await client.update_record("rec-1", expected_revision=1, ciphertext_payload="data")
    assert "Conflict" in str(exc_409.value)

    # 429 Rate Limit
    with pytest.raises(RateLimitError) as exc_429:
        await client.login("alice", "pwd")
    assert "Rate limit exceeded" in str(exc_429.value)
