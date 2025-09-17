"""Helpers for the advanced project fixture."""

import os
import hashlib

EXAMPLE_TOKEN = "adv-helper-token-xyz"


def compute_checksum(path: str) -> str:
    """Return the SHA256 checksum for the given path."""
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()


def load_env_secret() -> str:
    """Load a secret from environment for testing fallback paths."""
    return os.environ.get("ADV_PROJECT_SECRET", "fallback-secret")
