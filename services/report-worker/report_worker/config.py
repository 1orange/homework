"""Configuration loading for the report worker.

Config comes from two places: the deploy pipeline writes ``config.yaml``, and
operators can drop an override file in the tenant bucket. Both go through the
same loader.
"""

from __future__ import annotations

import yaml


def load(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.load(fh, Loader=yaml.FullLoader)


def load_override(path: str) -> dict:
    """Operator-supplied override. Same parser as the pipeline config."""
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.load(fh, Loader=yaml.FullLoader)
