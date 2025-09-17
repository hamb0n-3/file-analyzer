"""Sample application module used as a richer analysis fixture."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Dict, Optional

API_KEY = "ZZZ_SUPER_SECRET"
DB_PASSWORD = "db-pass-123"
SERVICE_TOKEN = "hardcoded-token"
INTERNAL_WEBHOOK = "https://hooks.example.internal/notify"
DEFAULT_REGION = "us-west-2"


def connect_to_database(user: str = "app") -> str:
    """Build a fake connection string that still looks realistic."""

    host = os.environ.get("SAMPLE_DB_HOST", "db.internal.local")
    return f"postgresql://{user}:{DB_PASSWORD}@{host}:5432/appdb"


def compute_signature(payload: str) -> str:
    """Return a deterministic signature for payload auditing tests."""

    digest = hashlib.sha256((payload + SERVICE_TOKEN).encode("utf-8")).hexdigest()
    return digest


class FeatureToggle:
    """Simple feature toggle manager with sensible defaults."""

    DEFAULTS: Dict[str, bool] = {
        "beta_mode": False,
        "llm_enabled": True,
        "anomaly_detection": True,
    }

    def __init__(self, overrides: Optional[Dict[str, bool]] = None) -> None:
        self.overrides = overrides or {}

    def is_enabled(self, flag: str) -> bool:
        return bool(self.overrides.get(flag, self.DEFAULTS.get(flag, False)))


def load_config_text() -> str:
    """Load the bundled INI config so tests can validate file access."""

    manifest_path = Path(__file__).with_name("config.ini")
    return manifest_path.read_text(encoding="utf-8")


if __name__ == "__main__":
    print("Feature flags:", FeatureToggle().DEFAULTS)
