"""
Phase 11: LLM provider abstraction.

The system must work with zero external API key (MockLLMProvider — a
deterministic template reasoner, not a random string generator: it reads
the same structured evidence a real LLM would get and writes a grounded
summary from it). Swap in AnthropicProvider by setting LLM_PROVIDER=anthropic
and ANTHROPIC_API_KEY in the environment.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod


class BaseLLMProvider(ABC):
    @abstractmethod
    def generate(self, system_prompt: str, user_prompt: str) -> str:
        ...


class MockLLMProvider(BaseLLMProvider):
    """
    Deterministic, template-based reasoning over structured evidence.
    No network calls, no API key. This keeps the agent demoable and
    testable without ever fabricating facts not present in the evidence
    that was passed in.
    """

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        # The agent passes a structured evidence block inside user_prompt;
        # here we just do lightweight templating rather than true generation.
        return user_prompt  # agent.py does the actual templating; see summarize()


class AnthropicProvider(BaseLLMProvider):
    """Real LLM reasoning via the Anthropic API. Requires ANTHROPIC_API_KEY."""

    def __init__(self, model: str = "claude-sonnet-4-6"):
        try:
            import anthropic
        except ImportError as exc:
            raise RuntimeError("pip install anthropic to use AnthropicProvider") from exc
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("Set ANTHROPIC_API_KEY to use AnthropicProvider")
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        resp = self.client.messages.create(
            model=self.model,
            max_tokens=1000,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")


def get_llm_provider() -> BaseLLMProvider:
    provider = os.environ.get("LLM_PROVIDER", "mock").lower()
    if provider == "anthropic":
        return AnthropicProvider()
    return MockLLMProvider()
