"""Command-line entry point for the offline fixture evaluation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agent_harness.boundaries import FixtureProvenanceVerifier, load_feed
from agent_harness.fixture_corpus import FixtureCorpus, build_fixture_harness
from agent_harness.policy_config import load_default_policy


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-harness", description="Evaluate dependency findings with deterministic policy")
    parser.add_argument("--findings", type=Path, help="scanner feed JSON or aggregate fixture directory")
    parser.add_argument("--fixture-corpus", type=Path, help="explicit aggregate fixture directory (alias for a directory passed to --findings)")
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        source = args.fixture_corpus or args.findings
        if source is None:
            parser.error("one of --findings or --fixture-corpus is required")
        if source.is_dir():
            corpus = FixtureCorpus.load(source)
            run = build_fixture_harness(
                corpus, policy=load_default_policy()
            ).run(corpus.payload, corpus.feed, args.output_dir)
        else:
            payload, feed = load_feed(source)
            demo = FixtureCorpus.load(Path(__file__).parents[1] / "fixtures" / "demo")
            run = build_fixture_harness(
                demo,
                verifier=FixtureProvenanceVerifier(),
                policy=load_default_policy(),
            ).run(payload, feed, args.output_dir)
    except SystemExit as exc:
        # Keep the public function useful to callers embedding the CLI while
        # preserving argparse's conventional process status under __main__.
        return int(exc.code) if isinstance(exc.code, int) else 2
    except (ValueError, OSError) as exc:
        print(json.dumps({"status": "invalid_input", "error": type(exc).__name__}, sort_keys=True), file=sys.stderr)
        return 2
    for finding in run.findings:
        print(json.dumps({
            "finding_id": finding.finding_id,
            "run_status": finding.run_status,
            "decision": finding.decision.value if finding.decision else None,
            "primary_reason": finding.primary_reason,
            "priority": finding.priority,
            "error": finding.error,
            "ledger_path": run.ledger_path,
            "ledger_final_hash": run.ledger_final_hash,
            "ledger_event_count": run.ledger_event_count,
            "attestation_path": str(args.output_dir / "attestations" / f"{finding.finding_id}.json"),
        }, sort_keys=True))
    return 1 if run.run_status == "error" else 0


if __name__ == "__main__":
    raise SystemExit(main())
