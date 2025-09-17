"""Supporting services for the sample project fixtures."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict

SERVICE_ENDPOINT = "https://service.example.com"
SERVICE_API_KEY = "svc-key-555"
OAUTH_CLIENT_SECRET = "oauth-client-secret-abc"


def build_headers() -> Dict[str, str]:
    token = os.environ.get("SERVICE_API_SECRET", "fixture-service-secret")
    return {
        "Authorization": f"Bearer {token}",
        "X-Service-Key": SERVICE_API_KEY,
    }


@dataclass
class ExternalClient:
    """Tiny HTTP client abstraction for analyzer coverage."""

    base_url: str = SERVICE_ENDPOINT
    timeout: int = 10

    def describe(self) -> str:
        return f"ExternalClient(base_url={self.base_url}, timeout={self.timeout})"

    def secret(self) -> str:
        return OAUTH_CLIENT_SECRET
