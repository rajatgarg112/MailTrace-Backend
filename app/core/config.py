from typing import List, Union
import json
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """MailTrace-AI Backend Configuration Settings."""
    
    APP_NAME: str = "MailTrace-AI"
    APP_ENV: str = "development"
    DEBUG: bool = True
    PORT: int = 8000
    HOST: str = "0.0.0.0"
    
    DATABASE_URL: str = "sqlite:///./database/mailtrace.db"
    
    API_SECRET_KEY: str = "dev_secret_key_change_in_production"
    CORS_ORIGINS: Union[List[str], str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:5174",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]
    
    ANALYZER_TIMEOUT_SECONDS: float = 10.0
    
    # Ingestion Limits
    MAX_RAW_EMAIL_BYTES: int = 10 * 1024 * 1024  # 10 MB
    MAX_MIME_PARTS: int = 100
    MAX_EXTRACTED_URLS: int = 100
    MAX_ATTACHMENTS: int = 50


    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                return json.loads(v)
            return [i.strip() for i in v.split(",") if i.strip()]
        return v


settings = Settings()
