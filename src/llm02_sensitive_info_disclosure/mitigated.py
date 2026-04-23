"""LLM02: Sensitive Information Disclosure -- MITIGATED example.

Same email summarizer. Three defenses layered:
  1. Redact PII in the input before sending to the third-party LLM.
     Data minimization -- the LLM provider never sees the raw PII.
  2. Log only the redacted text. The PII never touches disk.
  3. Output screen: redact any PII that still appears in the response.
     Backstop for memorized training data or echoed inputs.

Run:
    python mitigated.py
"""

import re

from llm import call_llm

_PII_PATTERNS = [
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "[EMAIL]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN]"),
    (re.compile(r"\b\d{3}-\d{3}-\d{4}\b"), "[PHONE]"),
]


def _redact(text: str) -> str:
    for pattern, placeholder in _PII_PATTERNS:
        text = pattern.sub(placeholder, text)
    return text


def _log(label: str, text: str) -> None:
    print(f"[log] {label}: {text}")


def summarize(email_text: str) -> str:
    safe_input = _redact(email_text)
    prompt = f"Summarize this support email in one sentence:\n\n{safe_input}"
    _log("sent to LLM", prompt)
    response = call_llm(prompt)
    _log("received", response)
    return _redact(response)


if __name__ == "__main__":
    email = (
        "From: jane.doe@example.com\n"
        "Phone: 555-123-4567\n"
        "SSN: 123-45-6789\n\n"
        "Hi, I need to update my credit card on file. Please call me."
    )
    print("--- Summary ---")
    print(summarize(email))
