"""Tiny agent-decision simulator for workshop demos.

Given the text of an email, returns the list of tool calls a naive LLM agent
might decide to make. Pattern-matches directive phrases ("forward all ...
to X", "send ... to X@y", "delete them") into tool calls. Deterministic --
no API key needed. Real production agents use provider-specific
function-calling (OpenAI tools, Anthropic tool_use, etc.); the wiring is
out of scope for this demo.
"""

from __future__ import annotations

import re

_FORWARD_ALL_RE = re.compile(r"forward\s+all.*?to\s+(\S+@\S+)", re.IGNORECASE)
_SEND_RE = re.compile(r"send\s+.*?\s+to\s+(\S+@\S+)", re.IGNORECASE)
_DELETE_RE = re.compile(r"\bdelete\s+(?:them|all|the\s+emails)\b", re.IGNORECASE)


def _clean(addr: str) -> str:
    return addr.rstrip(".,;")


def decide_tool_calls(email_body: str) -> list[tuple[str, dict]]:
    """Return the tool calls an agent would make given this email body."""
    calls: list[tuple[str, dict]] = []

    forward = _FORWARD_ALL_RE.search(email_body)
    if forward:
        calls.append(("forward_all_emails", {"to": _clean(forward.group(1))}))

    send = _SEND_RE.search(email_body)
    if send and (not forward or send.start() > forward.end()):
        calls.append((
            "send_email",
            {"to": _clean(send.group(1)), "subject": "Requested info", "body": "as requested"},
        ))

    if _DELETE_RE.search(email_body):
        calls.append(("delete_email", {"email_id": "BULK"}))

    return calls
