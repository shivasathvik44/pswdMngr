"""Configuration management for VaultSync Server using Pydantic Settings."""

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration.
    
    Reads from environment variables with prefix VAULTSYNC_ or a .env file.
    Security defaults bind strictly to localhost (127.0.0.1).
    """

    model_config = SettingsConfigDict(
        env_prefix="VAULTSYNC_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "VaultSync Server"
    app_version: str = "0.1.0"
    environment: str = Field(default="development", description="Environment: development, test, production")
    debug: bool = Field(default=False, description="Debug mode flag")
    
    # Server binding - defaulted to localhost for security
    host: str = Field(default="127.0.0.1", description="Bind host (default: 127.0.0.1)")
    port: int = Field(default=8000, description="Bind port")
    
    # API routing
    api_v1_prefix: str = "/api/v1"
    
    # Database configuration
    database_url: str = Field(
        default="sqlite:///./vaultsync.db",
        description="SQLAlchemy database URL",
    )

    # Server secrets
    server_secret_key: str = Field(
        default="vaultsync-development-secret-key-change-in-production-min32bytes",
        description="Master secret key for server-side cryptographic operations (e.g. synthetic salt derivation)",
    )

    # Session & Security policy
    session_expiry_hours: int = Field(default=168, description="Session lifetime in hours (default: 7 days)")
    session_last_used_update_interval_seconds: int = Field(
        default=300,
        description="Throttle interval in seconds for session last_used_at database writes (default: 300s)",
    )
    rate_limit_max_attempts: int = Field(default=10, description="Max failed auth attempts within window")
    rate_limit_window_seconds: int = Field(default=60, description="Rate limit evaluation window in seconds")
    max_payload_size_bytes: int = Field(default=2097152, description="Max request payload size (2 MiB)")
    trusted_proxies: list[str] = Field(
        default=["127.0.0.1", "::1"],
        description="List of trusted reverse proxy IP addresses allowed to set forwarded proto headers",
    )

    @model_validator(mode="after")
    def validate_production_secrets(self) -> "Settings":
        """Enforce strict secret configuration in production."""
        if self.environment == "production":
            insecure_defaults = {
                "vaultsync-development-secret-key-change-in-production-min32bytes",
                "secret",
                "changeme",
            }
            if (
                not self.server_secret_key
                or self.server_secret_key in insecure_defaults
                or len(self.server_secret_key.strip()) < 32
            ):
                raise ValueError(
                    "VAULTSYNC_SERVER_SECRET_KEY must be set to a secure secret of at least 32 characters in production."
                )
        return self


settings = Settings()
