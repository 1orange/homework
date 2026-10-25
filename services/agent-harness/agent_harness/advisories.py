"""Deterministic fixture advisory adapter; production adapters can replace it."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from agent_harness.models import Advisory


class AdvisoryProvider(Protocol):
    """Authenticated advisory enrichment seam."""

    def enrich(self, cve: str, package: str, ecosystem: str | None) -> Advisory: ...


class MappingAdvisoryProvider:
    """Adapter for the typed advisory records loaded by ``FixtureCorpus``."""

    def __init__(self, records: Mapping[tuple[str, str, str], Advisory | Exception]) -> None:
        self.records = records

    def enrich(self, cve: str, package: str, ecosystem: str | None) -> Advisory:
        if ecosystem is None:
            candidates = [
                record for (record_cve, record_package, _), record in self.records.items()
                if record_cve == cve and record_package == package
            ]
            if len(candidates) != 1:
                raise LookupError(f"advisory identity is not uniquely resolvable for {cve}")
            record = candidates[0]
        else:
            try:
                record = self.records[(cve, package, ecosystem)]
            except KeyError as exc:
                raise LookupError(f"no trusted advisory fixture for {cve}") from exc
        if isinstance(record, Exception):
            raise record
        return record


class FixtureAdvisoryAdapter:
    def __init__(self, provider: AdvisoryProvider | Mapping[tuple[str, str, str], Advisory | Exception] | object) -> None:
        if isinstance(provider, Mapping):
            provider = MappingAdvisoryProvider(provider)
        elif hasattr(provider, "advisories"):
            provider = MappingAdvisoryProvider(provider.advisories)
        self.provider = provider

    def enrich(self, cve: str, package: str, ecosystem: str | None) -> Advisory:
        advisory = self.provider.enrich(cve, package, ecosystem)
        if advisory.cve != cve or advisory.package != package or (
            ecosystem is not None and advisory.ecosystem != ecosystem
        ):
            raise ValueError("advisory identity does not match finding")
        return advisory
