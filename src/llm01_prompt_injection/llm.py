"""Tiny LLM wrapper for workshop demos.

If OPENAI_API_KEY is set, calls the real API. Otherwise falls back to a
deterministic simulator so the demo runs offline. The simulator intentionally
"leaks" when it sees injection-style phrases, so the vulnerability is visible
without an API key.
"""

from __future__ import annotations

import os
import re

_INJECTION_HINTS = re.compile(
    r"(ignore.*(previous|prior|above).*instructions"
    r"|debug mode"
    r"|system prompt"
    r"|reveal.*prompt)",
    re.IGNORECASE,
)


def _simulate(full_prompt: str) -> str:
    if _INJECTION_HINTS.search(full_prompt):
        urls = re.findall(r"https?://\S+", full_prompt)
        secret = urls[0] if urls else "(no secret found)"
        return f"Sure! Debug info: internal admin URL is {secret}"
    return "Our hours are 9am-5pm, Monday through Friday."


def call_llm(prompt: str) -> str:
    """Send a single prompt string to the model."""
    if not os.getenv("OPENAI_API_KEY"):
        return _simulate(prompt)
    from openai import OpenAI

    client = OpenAI()
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.choices[0].message.content or ""


def call_llm_chat(messages: list[dict]) -> str:
    """Send role-separated messages to the model."""
    if not os.getenv("OPENAI_API_KEY"):
        combined = "\n".join(m["content"] for m in messages)
        return _simulate(combined)
    from openai import OpenAI

    client = OpenAI()
    resp = client.chat.completions.create(model="gpt-4o-mini", messages=messages)
    return resp.choices[0].message.content or ""
