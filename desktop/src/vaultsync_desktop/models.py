"""VaultSync Desktop data models."""

from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class VaultItem(BaseModel):
    """Plaintext representation of an encrypted vault entry stored in memory only when unlocked."""

    id: str = Field(default_factory=lambda: str(uuid4()))

    @field_validator("id", mode="before")
    @classmethod
    def validate_id(cls, v: Any) -> str:
        """Ensure record ID defaults to a generated UUID4 if None, empty, or whitespace."""
        if v is None or (isinstance(v, str) and not v.strip()):
            return str(uuid4())
        if not isinstance(v, str):
            return str(v)
        return v.strip()
    title: str = Field(..., min_length=1, max_length=256)
    username: str = Field(default="", max_length=256)
    password: str = Field(default="", max_length=1024)
    url: str = Field(default="", max_length=2048)
    notes: str = Field(default="", max_length=65536)
    revision: int = Field(default=1, ge=1)
    is_deleted: bool = Field(default=False)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_secret_json(self) -> str:
        """Serialize item confidential fields for client-side encryption.
        
        The resulting JSON is the plaintext payload encrypted via AES-256-GCM
        into an EncryptedRecordEnvelope.
        """
        payload = {
            "title": self.title,
            "username": self.username,
            "password": self.password,
            "url": self.url,
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
        import json
        return json.dumps(payload, separators=(",", ":"))

    @classmethod
    def from_secret_json(cls, record_id: str, revision: int, secret_json: str) -> "VaultItem":
        """Reconstruct VaultItem from decrypted plaintext payload."""
        import json
        data = json.loads(secret_json)
        return cls(
            id=record_id,
            title=data.get("title") or "Untitled",
            username=data.get("username", ""),
            password=data.get("password", ""),
            url=data.get("url", ""),
            notes=data.get("notes", ""),
            revision=revision,
            is_deleted=False,
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            updated_at=data.get("updated_at", datetime.now(timezone.utc).isoformat()),
        )


class ServerConnectionConfig(BaseModel):
    """Server connection configuration and validation."""

    server_url: str = Field(default="http://127.0.0.1:8000")

    def validate_url(self) -> tuple[bool, str]:
        """Validate server URL and enforce loopback-HTTP or remote-HTTPS."""
        import urllib.parse
        parsed = urllib.parse.urlparse(self.server_url)
        if not parsed.scheme or not parsed.netloc:
            return False, "Invalid server URL. Please include protocol (e.g., http://127.0.0.1:8000)."

        hostname = (parsed.hostname or "").lower()
        is_loopback = hostname in ("127.0.0.1", "localhost", "::1")

        if parsed.scheme == "http":
            if not is_loopback:
                return False, "Plain HTTP is only permitted on loopback (127.0.0.1). Remote servers require HTTPS."
        elif parsed.scheme != "https":
            return False, f"Unsupported protocol '{parsed.scheme}'. Only HTTPS (or local HTTP) is permitted."

        return True, ""
