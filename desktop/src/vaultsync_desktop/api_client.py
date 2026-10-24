"""VaultSync Desktop API client.

Handles asynchronous HTTP communication with the backend service.
Enforces loopback-HTTP or remote-HTTPS validation, injects bearer tokens,
and maps HTTP status codes to typed exceptions.
"""

import logging
import urllib.parse
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)


class ApiError(Exception):
    """Base exception for API communication errors."""
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class NetworkConnectionError(ApiError):
    """Raised when server connection fails or times out."""


class InsecureConnectionError(ApiError):
    """Raised when attempting unencrypted HTTP over a non-loopback network."""


class AuthenticationError(ApiError):
    """Raised on 401 Unauthorized (invalid credentials or expired session)."""


class MigrationRequiredError(ApiError):
    """Raised on 403 Forbidden when a legacy single-credential account requires migration."""


class ConflictError(ApiError):
    """Raised on 409 Conflict (optimistic concurrency version collision)."""
    def __init__(self, message: str, record_id: str = ""):
        super().__init__(message, status_code=409)
        self.record_id = record_id


class RateLimitError(ApiError):
    """Raised on 429 Too Many Requests."""


class NotFoundError(ApiError):
    """Raised on 404 Not Found."""


class ApiClient:
    """HTTP client interacting with the VaultSync REST API."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        timeout: float = 10.0,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.transport = transport
        self.session_token: Optional[str] = None
        self._validate_base_url(self.base_url)

    @classmethod
    def _validate_base_url(cls, url: str) -> None:
        """Enforce loopback HTTP or remote HTTPS."""
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise InsecureConnectionError("Invalid server URL. Protocol and host are required.")

        hostname = (parsed.hostname or "").lower()
        is_loopback = hostname in ("127.0.0.1", "localhost", "::1")

        if parsed.scheme == "http" and not is_loopback:
            raise InsecureConnectionError(
                f"Plain HTTP connection to '{hostname}' rejected. "
                "Remote connections require authenticated HTTPS."
            )
        elif parsed.scheme not in ("http", "https"):
            raise InsecureConnectionError(f"Unsupported protocol scheme '{parsed.scheme}'.")

    def set_session_token(self, token: Optional[str]) -> None:
        """Set the active bearer token for authenticated requests."""
        self.session_token = token

    def _get_headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if self.session_token:
            headers["Authorization"] = f"Bearer {self.session_token}"
        return headers

    async def _request(
        self,
        method: str,
        path: str,
        json_data: Optional[dict[str, Any]] = None,
        params: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Perform an HTTP request and map responses to typed errors."""
        url = f"{self.base_url}{path}"
        try:
            async with httpx.AsyncClient(transport=self.transport, timeout=self.timeout) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    json=json_data,
                    params=params,
                    headers=self._get_headers(),
                )
        except httpx.RequestError as exc:
            logger.warning("Network request to %s failed: %s", path, type(exc).__name__)
            raise NetworkConnectionError(f"Failed to connect to server: {exc}") from exc

        if response.status_code == 200 or response.status_code == 201:
            return response.json() if response.content else {}

        # Handle errors
        detail = "Unknown error"
        try:
            err_json = response.json()
            detail = err_json.get("detail", detail)
        except Exception:
            detail = response.text or detail

        detail_str = str(detail)
        if response.status_code == 401:
            raise AuthenticationError(detail_str, status_code=401)
        elif response.status_code == 403:
            if "migration" in detail_str.lower():
                raise MigrationRequiredError(detail_str, status_code=403)
            raise ApiError(f"Forbidden: {detail_str}", status_code=403)
        elif response.status_code == 404:
            raise NotFoundError(detail_str, status_code=404)
        elif response.status_code == 409:
            raise ConflictError(f"Conflict: {detail_str}")
        elif response.status_code == 429:
            raise RateLimitError(f"Rate limit exceeded: {detail_str}", status_code=429)
        else:
            raise ApiError(f"Server error ({response.status_code}): {detail_str}", status_code=response.status_code)

    # ------------------------------------------------------------------------
    # Public Endpoints
    # ------------------------------------------------------------------------

    async def check_health(self) -> dict[str, Any]:
        """Check server connectivity and status."""
        return await self._request("GET", "/api/v1/health")

    async def register(
        self,
        username: str,
        account_password: str,
        kdf_salt: str,
        wrapped_vault_key: str,
    ) -> dict[str, Any]:
        """Register a new account.
        
        The vault master password is NEVER transmitted.
        """
        payload = {
            "username": username,
            "account_password": account_password,
            "kdf_salt": kdf_salt,
            "wrapped_vault_key": wrapped_vault_key,
        }
        return await self._request("POST", "/api/v1/auth/register", json_data=payload)

    async def login(
        self,
        username: str,
        account_password: str,
        device_name: str = "Fedora Desktop",
        device_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Authenticate using account password and establish session."""
        payload = {
            "username": username,
            "account_password": account_password,
            "device_name": device_name,
            "device_id": device_id,
        }
        data = await self._request("POST", "/api/v1/auth/login", json_data=payload)
        token = data.get("session_token")
        if token:
            self.set_session_token(token)
        return data

    async def logout(self) -> dict[str, Any]:
        """Revoke the current session token."""
        try:
            res = await self._request("POST", "/api/v1/auth/logout")
        finally:
            self.set_session_token(None)
        return res

    async def change_account_password(
        self,
        current_password: str,
        new_password: str,
    ) -> dict[str, Any]:
        """Change server account password."""
        payload = {
            "current_password": current_password,
            "new_password": new_password,
        }
        return await self._request("PUT", "/api/v1/auth/password", json_data=payload)

    async def update_vault_key(
        self,
        wrapped_vault_key: str,
        kdf_salt: str,
        expected_version: int,
        current_password: str,
    ) -> dict[str, Any]:
        """Update wrapped vault key envelope and salt (master password rotation)."""
        payload = {
            "wrapped_vault_key": wrapped_vault_key,
            "kdf_salt": kdf_salt,
            "expected_version": expected_version,
            "current_password": current_password,
        }
        return await self._request("PUT", "/api/v1/auth/vault-key", json_data=payload)

    async def fetch_sync(
        self,
        since_cursor: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Fetch incremental record updates since cursor."""
        params = {"since_cursor": since_cursor, "limit": limit}
        return await self._request("GET", "/api/v1/sync", params=params)

    async def get_vault_key(self) -> dict[str, Any]:
        """Retrieve current wrapped vault key envelope and KDF salt for calling session."""
        return await self._request("GET", "/api/v1/auth/vault-key")

    async def get_user_salt(self, username: str) -> dict[str, Any]:
        """Fetch public KDF salt for a username."""
        return await self._request("GET", "/api/v1/auth/salt", params={"username": username})

    async def list_sessions(self) -> list[dict[str, Any]]:
        """List active device sessions."""
        res = await self._request("GET", "/api/v1/sessions")
        return res if isinstance(res, list) else []

    async def revoke_session(self, session_id: str) -> dict[str, Any]:
        """Revoke specific device session."""
        return await self._request("DELETE", f"/api/v1/sessions/{session_id}")

    async def get_record(self, record_id: str) -> dict[str, Any]:
        """Fetch single encrypted record by record_id."""
        return await self._request("GET", f"/api/v1/records/{record_id}")

    async def create_record(
        self,
        record_id: str,
        ciphertext_payload: str,
    ) -> dict[str, Any]:
        """Create new client-encrypted record on server."""
        payload = {
            "record_id": record_id,
            "ciphertext_payload": ciphertext_payload,
        }
        return await self._request("POST", "/api/v1/records", json_data=payload)

    async def update_record(
        self,
        record_id: str,
        expected_revision: int,
        ciphertext_payload: str,
    ) -> dict[str, Any]:
        """Update existing record with optimistic concurrency revision check."""
        payload = {
            "expected_revision": expected_revision,
            "ciphertext_payload": ciphertext_payload,
        }
        return await self._request("PUT", f"/api/v1/records/{record_id}", json_data=payload)

    async def delete_record(
        self,
        record_id: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        """Tombstone record on server for deletion propagation."""
        params = {"expected_revision": expected_revision}
        return await self._request("DELETE", f"/api/v1/records/{record_id}", params=params)
