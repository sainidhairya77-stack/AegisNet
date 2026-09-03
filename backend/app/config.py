"""
AegisNet Configuration Module

Handles environment-based configuration for the application.
Uses pydantic-settings for environment variable management.
"""

from typing import List
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""

    # Database
    database_url: str = "postgresql://aegisnet:aegisnet_password@localhost:5432/aegisnet"

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_title: str = "AegisNet API"
    api_version: str = "1.0.0"

    # JWT / Authentication
    jwt_secret: str = "your-super-secret-jwt-key-change-this-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expiration_hours: int = 24

    # CORS
    cors_origins: List[str] = ["http://localhost:3000", "http://localhost:5173"]

    # OpenAI Configuration
    openai_api_key: str = ""
    openai_model: str = "gpt-4o"
    openai_max_tokens: int = 2000

    # File Upload
    max_upload_size_mb: int = 1000
    upload_dir: str = "./data/uploads"
    allowed_file_extensions: str = "pcap,pcapng"

    # Firewall
    firewall_mode: str = "mock"  # mock or linux
    firewall_connector_url: str = "http://firewall-connector:8001"
    firewall_connector_secret: str = "firewall-connector-secret-key"

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"

    # Environment
    environment: str = "development"  # development, staging, production

    # Demo Mode
    demo_mode: bool = False
    demo_data_dir: str = "./data/samples"

    class Config:
        env_file = ".env"
        case_sensitive = False

    @property
    def max_upload_size_bytes(self) -> int:
        """Convert max upload size from MB to bytes"""
        return self.max_upload_size_mb * 1024 * 1024

    @property
    def allowed_extensions_list(self) -> List[str]:
        """Get list of allowed file extensions"""
        return [ext.strip() for ext in self.allowed_file_extensions.split(",")]

    @property
    def is_production(self) -> bool:
        """Check if running in production"""
        return self.environment == "production"

    @property
    def is_development(self) -> bool:
        """Check if running in development"""
        return self.environment == "development"

    @property
    def firewall_is_mock(self) -> bool:
        """Check if using mock firewall"""
        return self.firewall_mode == "mock"

    @property
    def firewall_is_linux(self) -> bool:
        """Check if using Linux firewall"""
        return self.firewall_mode == "linux"

    @property
    def openai_configured(self) -> bool:
        """Check if OpenAI API is configured"""
        return bool(self.openai_api_key)


@lru_cache()
def get_settings() -> Settings:
    """
    Get application settings (cached).
    Uses dependency injection with FastAPI.
    """
    return Settings()
