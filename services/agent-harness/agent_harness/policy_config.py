"""Strict, immutable policy configuration and its checked-in loader."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from pydantic import ConfigDict, Field, field_validator, model_validator

from agent_harness.models import StrictModel


class BoundedSourcePath(StrictModel):
    """A source transformation and the exact paths it may inspect or edit."""

    model_config = ConfigDict(
        extra="forbid", strict=True, hide_input_in_errors=True, frozen=True
    )

    transformation_id: str = Field(min_length=1, max_length=128)
    paths: tuple[str, ...] = Field(min_length=1, max_length=128)

    @field_validator("paths")
    @classmethod
    def unique_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("bounded source paths must be unique")
        if any(
            not path
            or "\\" in path
            or not path.startswith("services/")
            or re.match(r"^[A-Za-z]:[\\/]", path)
            or any(part in {"", ".", ".."} for part in path.split("/"))
            for path in value
        ):
            raise ValueError("bounded source paths must be normalized")
        return value


class PolicyConfig(StrictModel):
    """The complete authorization allowlist used by one policy evaluation.

    The model and all of its nested values are immutable.  ``bounded_source_paths``
    is represented as tuples rather than a mutable mapping so ``frozen=True``
    remains a deep immutability guarantee at the configuration seam.
    """

    model_config = ConfigDict(
        extra="forbid", strict=True, hide_input_in_errors=True, frozen=True
    )

    registered_transformations: tuple[str, ...] = Field(min_length=1, max_length=128)
    required_verification_gates: tuple[str, ...] = Field(min_length=1, max_length=64)
    review_only_transformations: tuple[str, ...] = Field(max_length=128)
    bounded_source_paths: tuple[BoundedSourcePath, ...] = Field(max_length=128)

    @field_validator(
        "registered_transformations",
        "required_verification_gates",
        "review_only_transformations",
    )
    @classmethod
    def unique_names(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item or len(item) > 128 for item in value):
            raise ValueError("policy identifiers must be non-empty")
        if len(value) != len(set(value)):
            raise ValueError("policy identifiers must be unique")
        return value

    @field_validator("bounded_source_paths")
    @classmethod
    def unique_transformations(
        cls, value: tuple[BoundedSourcePath, ...]
    ) -> tuple[BoundedSourcePath, ...]:
        identifiers = [item.transformation_id for item in value]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("bounded source transformations must be unique")
        return value

    @model_validator(mode="after")
    def validate_relationships(self) -> "PolicyConfig":
        bounded_ids = {item.transformation_id for item in self.bounded_source_paths}
        if not bounded_ids <= set(self.registered_transformations):
            raise ValueError("bounded source transformation is not registered")
        if set(self.review_only_transformations) & set(self.registered_transformations):
            raise ValueError("review-only transformation is registered")
        return self

    @classmethod
    def from_json(cls, value: Any) -> "PolicyConfig":
        """Validate untrusted JSON data, converting all failures to ``ValueError``."""

        try:
            if not isinstance(value, dict):
                raise ValueError("policy document must be an object")
            # JSON has arrays, while the in-memory contract deliberately uses
            # tuples so the frozen model is deeply immutable.
            normalized = dict(value)
            for field_name in (
                "registered_transformations",
                "required_verification_gates",
                "review_only_transformations",
            ):
                field_value = normalized.get(field_name)
                if isinstance(field_value, list):
                    normalized[field_name] = tuple(field_value)
            bounded = normalized.get("bounded_source_paths")
            if isinstance(bounded, list):
                normalized["bounded_source_paths"] = tuple(
                    {
                        **item,
                        "paths": tuple(item["paths"])
                        if isinstance(item, dict) and isinstance(item.get("paths"), list)
                        else item.get("paths") if isinstance(item, dict) else None,
                    }
                    if isinstance(item, dict) else item
                    for item in bounded
                )
            config = cls.model_validate(normalized)
            return config
        except Exception as exc:
            # Do not leak malformed policy values in a boundary error.
            raise ValueError("invalid policy configuration") from exc

    @property
    def digest(self) -> str:
        """Return the SHA-256 digest of the canonical policy document.

        Allowlist collections are semantically unordered during evaluation,
        so their source-file ordering does not create a false policy change.
        """

        document = self.model_dump(mode="json")
        document["registered_transformations"] = sorted(
            document["registered_transformations"]
        )
        document["required_verification_gates"] = sorted(
            document["required_verification_gates"]
        )
        document["review_only_transformations"] = sorted(
            document["review_only_transformations"]
        )
        document["bounded_source_paths"] = sorted(
            (
                {
                    **item,
                    "paths": sorted(item["paths"]),
                }
                for item in document["bounded_source_paths"]
            ),
            key=lambda item: item["transformation_id"],
        )

        encoded = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def paths_for(self, transformation_id: str) -> frozenset[str]:
        """Return the immutable bounded path set for one transformation."""

        for rule in self.bounded_source_paths:
            if rule.transformation_id == transformation_id:
                return frozenset(rule.paths)
        return frozenset()


def load_policy(path: Path) -> PolicyConfig:
    """Load and strictly validate one policy document, failing closed."""

    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("invalid policy configuration") from exc
    return PolicyConfig.from_json(value)


def default_policy_path() -> Path:
    return Path(__file__).resolve().parent.parent / "policies" / "default.json"


def load_default_policy() -> PolicyConfig:
    return load_policy(default_policy_path())


def policy_digest(policy: PolicyConfig) -> str:
    """Return a canonical digest for a validated policy configuration."""

    if not isinstance(policy, PolicyConfig):
        raise ValueError("invalid policy configuration")
    return policy.digest


load_policy_config = load_policy


__all__ = [
    "BoundedSourcePath",
    "PolicyConfig",
    "default_policy_path",
    "load_default_policy",
    "load_policy",
    "load_policy_config",
    "policy_digest",
]
