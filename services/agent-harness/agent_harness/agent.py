"""Deterministic proposal agent with a bounded PydanticAI function-model boundary."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Protocol

from agent_harness.models import Proposal, ProposalContext


class ProposalProvider(Protocol):
    """Lookup seam for the one immutable proposal returned by the agent."""

    def proposal_for(self, finding_id: str) -> Proposal: ...


class MappingProposalProvider:
    """Typed adapter around a catalog mapping keyed by finding ID."""

    def __init__(self, records: Mapping[str, Proposal]) -> None:
        self.records = records

    def proposal_for(self, finding_id: str) -> Proposal:
        try:
            return self.records[finding_id]
        except KeyError as exc:
            raise LookupError(f"no deterministic proposal for {finding_id}") from exc


class DeterministicProposalAgent:
    """Returns one immutable typed proposal through the local FunctionModel."""

    def __init__(self, provider: ProposalProvider | Mapping[str, Proposal] | object) -> None:
        if isinstance(provider, Mapping):
            provider = MappingProposalProvider(provider)
        elif hasattr(provider, "proposals"):
            provider = MappingProposalProvider(provider.proposals)
        self.provider = provider
        self.model_name = "pydantic-ai-slim.FunctionModel"
        # Import lazily because this is an install-time boundary. It remains
        # required at runtime: silently selecting the lookup fallback would
        # make a broken FunctionModel installation look like a passing test.
        try:
            from pydantic_ai import Agent
            from pydantic_ai.messages import ModelResponse, ToolCallPart
            from pydantic_ai.models.function import FunctionModel
        except Exception as exc:  # pragma: no cover - exercised by packaging checks
            raise RuntimeError("pydantic-ai-slim FunctionModel is unavailable") from exc

        def function_model(messages, agent_info):
            prompt = messages[-1].parts[0].content
            match = re.search(r'"id"\s*:\s*"([^"]+)"', prompt)
            if not match:
                raise ValueError("bounded context did not contain a finding ID")
            try:
                proposal = self.provider.proposal_for(match.group(1))
            except (KeyError, LookupError) as exc:
                raise LookupError(f"no deterministic proposal for {match.group(1)}") from exc
            # pydantic-ai renamed result_tools to output_tools. Accept both
            # while the lock pins the known-compatible runtime.
            result_tools = getattr(agent_info, "output_tools", None)
            if result_tools is None:
                result_tools = getattr(agent_info, "result_tools", None)
            if not result_tools:
                raise RuntimeError("FunctionModel did not expose a Proposal output tool")
            result_tool = result_tools[0]
            return ModelResponse(parts=[ToolCallPart(
                tool_name=result_tool.name,
                args=proposal.model_dump_json(),
                tool_call_id="deterministic-proposal",
            )])

        try:
            self._function_model = FunctionModel(function=function_model, model_name=self.model_name)
            self._agent = Agent(self._function_model, output_type=Proposal)
        except Exception as exc:  # pragma: no cover - exercised by packaging checks
            raise RuntimeError("pydantic-ai-slim FunctionModel initialization failed") from exc

    def propose(self, context: ProposalContext) -> Proposal:
        # The context is the sole input. The local FunctionModel receives only
        # this JSON and cannot access filesystem, shell, Git, network, or creds.
        if self._agent is not None:
            prompt = json.dumps(context.model_dump(mode="json"), sort_keys=True)
            result = self._agent.run_sync(prompt)
            proposal = getattr(result, "data", None) or getattr(result, "output", None)
            if isinstance(proposal, Proposal):
                if proposal.finding_id != context.finding.id:
                    raise ValueError("deterministic proposal selected a different finding")
                return proposal
        raise RuntimeError("FunctionModel returned an invalid Proposal result")
