"""Configuration management for VaultSync Server using Pydantic Settings."""

from pydantic import Field
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

    # Session & Security policy
    session_expiry_hours: int = Field(default=168, description="Session lifetime in hours (default: 7 days)")
    rate_limit_max_attempts: int = Field(default=10, description="Max failed auth attempts within window")
    rate_limit_window_seconds: int = Field(default=60, description="Rate limit evaluation window in seconds")
    max_payload_size_bytes: int = Field(default=2097152, description="Max request payload size (2 MiB)")


settings = Settings()
