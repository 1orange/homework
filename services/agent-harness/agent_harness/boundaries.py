"""Replaceable input boundaries for fixtures and future trusted adapters."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Protocol

from pydantic import ValidationError

from agent_harness.models import Advisory, Finding, FindingFeed, InvalidFinding, Provenance, ScannerEnvelope


class ProvenanceVerifier(Protocol):
    def verify(self, payload: dict) -> Provenance: ...


class AdvisoryAdapter(Protocol):
    def enrich(self, cve: str, package: str, ecosystem: str | None) -> Advisory: ...


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


class FixtureProvenanceVerifier:
    """Offline verifier. It authenticates only the known fixture envelope."""

    _known_digests = frozenset({
        # Canonical digests of the unchanged supplied feed and safe fixture.
        "c858d59e25b033171fd75a0b507f235b6f2d3047dc7af0fa72be24d6981d54a9",
        "d678ee3f1bec30ef95691afbe158b44617765e7d284e136ce2e8ee086c9c53cf",
        "f52c676d94ee37cd26ebf3387906f7bd4f6e3de48b56eec07d402962e7bd1120",
    })

    def __init__(self, *, allowed_scanners: tuple[str, ...] = ("internal-composition-scan",), known_digests: frozenset[str] | None = None) -> None:
        self.allowed_scanners = allowed_scanners
        self.known_digests = known_digests or self._known_digests

    def verify(self, payload: dict) -> Provenance:
        scanner = payload.get("scanner")
        generated = payload.get("generated")
        if scanner not in self.allowed_scanners or not isinstance(generated, str) or not generated:
            raise ValueError("fixture provenance claims are not recognized")
        digest = sha256_json(payload)
        if digest not in self.known_digests:
            raise ValueError("fixture payload is not an authenticated recorded fixture")
        return Provenance(
            source="fixture://scanner-feed",
            digest=digest,
            verified=True,
            claims=("offline-fixture", "scanner-envelope", "offline-digest"),
        )


def load_feed(path: Path) -> tuple[dict, FindingFeed]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        envelope = ScannerEnvelope.model_validate(payload)

        # Authenticate/parse the envelope as a whole, but isolate schema
        # failures to one item.  Raw values are intentionally discarded after
        # their digest is calculated; only the private feed binding retains
        # them long enough to prove that the verified payload was processed.
        findings: list[Finding | InvalidFinding] = []
        for index, raw in enumerate(envelope.findings):
            try:
                findings.append(Finding.model_validate(raw))
            except ValidationError:
                input_hash = sha256_json(raw)
                findings.append(InvalidFinding(
                    finding_id=f"invalid-finding-{index:06d}-{input_hash[:16]}",
                    input_hash=input_hash,
                    source_index=index,
                ))
        feed = FindingFeed(
            generated=envelope.generated,
            scanner=envelope.scanner,
            findings=findings,
        )
        feed._raw_findings = tuple(envelope.findings)
        return payload, feed
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise ValueError("invalid findings input") from exc
