"""Clean sample demonstrating proper secret handling via environment variables."""

import os
from typing import Optional

class SecureService:
    def __init__(self, api_key: Optional[str] = None):
        # Good practice: read secrets strictly from environment
        self.api_key = api_key or os.environ.get("SERVICE_API_KEY", "")
        self.endpoint = "https://api.example.com/v1"

    def is_configured(self) -> bool:
        return bool(self.api_key)
