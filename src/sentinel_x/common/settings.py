"""Application settings loaded from environment / .env file."""

from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database
    database_url: str = (
        "postgresql+asyncpg://sentinel:sentinel_dev_password@localhost:5432/sentinelx"
    )
    database_url_sync: str = (
        "postgresql+psycopg://sentinel:sentinel_dev_password@localhost:5432/sentinelx"
    )

    # Redis (host port 6380 mapped to container 6379 to avoid conflicts)
    redis_url: str = "redis://localhost:6380/0"

    # MLflow
    mlflow_tracking_uri: str = "http://localhost:5000"
    mlflow_experiment_name: str = "sentinel-x"

    # Ollama LLM
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:3b-instruct-q4_K_M"

    # Embeddings
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    reranker_model: str = "cross-encoder/ms-marco-MiniLM-L-6-v2"
    embedding_dim: int = 384

    # API security
    # NOTE: the default exists only so local development boots; production
    # MUST set SECRET_KEY (>= 32 bytes) via the environment.
    secret_key: SecretStr = Field(
        default=SecretStr("insecure-development-secret-change-me-0123456789")
    )
    access_token_expire_minutes: int = 60


@lru_cache
def get_settings() -> Settings:
    return Settings()
