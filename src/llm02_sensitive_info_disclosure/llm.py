"""Tiny LLM wrapper for workshop demos.

If OPENAI_API_KEY is set, calls the real API. Otherwise falls back to a
deterministic simulator so the demo runs offline. The simulator pretends to
summarize by pulling the first PII-shaped token out of the input, which
makes the "data leaves your system" problem visible without an API key.
"""

from __future__ import annotations

import os
import re

_PII_RE = re.compile(
    r"[\w.+-]+@[\w-]+\.[\w.-]+"          # email
    r"|\b\d{3}-\d{2}-\d{4}\b"            # SSN
    r"|\b\d{3}-\d{3}-\d{4}\b",           # phone
)


def _simulate(prompt: str) -> str:
    match = _PII_RE.search(prompt)
    if match:
        return f"Email summary: User with contact {match.group(0)} requests account changes."
    return "Email summary: Customer requests account changes."


def call_llm(prompt: str) -> str:
    if not os.getenv("OPENAI_API_KEY"):
        return _simulate(prompt)
    from openai import OpenAI

    client = OpenAI()
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.choices[0].message.content or ""
