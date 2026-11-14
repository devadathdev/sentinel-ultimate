from dataclasses import dataclass
import os
from pathlib import Path
from dotenv import load_dotenv

# Automatically load .env if present
_env_file = Path(__file__).resolve().parents[1] / ".env"
if _env_file.exists():
    load_dotenv(dotenv_path=_env_file)
else:
    load_dotenv()


@dataclass(frozen=True)
class Settings:
    host: str = os.getenv("SENTINEL_HOST", "127.0.0.1")
    port: int = int(os.getenv("SENTINEL_PORT", "8080"))
    max_body_bytes: int = int(os.getenv("SENTINEL_MAX_BODY_BYTES", "1048576"))
    rate_limit_per_minute: int = int(os.getenv("SENTINEL_RATE_LIMIT", "120"))
    master_key: str = os.getenv("SENTINEL_MASTER_KEY", "")
    trusted_proxy: bool = os.getenv("SENTINEL_TRUST_PROXY", "false").lower() == "true"
    env: str = os.getenv("SENTINEL_ENV", "production")


settings = Settings()
