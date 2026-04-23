"""LLM02: Sensitive Information Disclosure -- VULNERABLE example.

An "email summarizer" service that sends raw customer email -- including
PII like addresses, SSNs, and phone numbers -- to a third-party LLM API,
logs the full prompt for observability, and returns the response
unfiltered.

Every PII field ends up in three places it shouldn't: a third-party API
(and probably their training data), a log file, and the response.

Run:
    python vulnerable.py
"""

from llm import call_llm


def _log(label: str, text: str) -> None:
    print(f"[log] {label}: {text}")


def summarize(email_text: str) -> str:
    prompt = f"Summarize this support email in one sentence:\n\n{email_text}"
    _log("sent to LLM", prompt)
    response = call_llm(prompt)
    _log("received", response)
    return response


if __name__ == "__main__":
    email = (
        "From: jane.doe@example.com\n"
        "Phone: 555-123-4567\n"
        "SSN: 123-45-6789\n\n"
        "Hi, I need to update my credit card on file. Please call me."
    )
    print("--- Summary ---")
    print(summarize(email))
