# LLM02: Sensitive Information Disclosure

OWASP LLM Top 10 (2025), risk #2. [Official spec](https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/).

## The vulnerability in one sentence

Anything you send to an LLM may end up in the provider's logs, future
training data, your own logs, your response -- or all four. Naive
integrations leak PII, secrets, or proprietary data across every boundary.

## Run it

```bash
python vulnerable.py   # PII flows to LLM prompt, to logs, and back out in the summary
python mitigated.py    # PII redacted at input, so logs and response are clean too
```

No API key required -- each demo includes a deterministic simulator that
makes the leak visible offline. Set `OPENAI_API_KEY` to run against a real
model.

## Workshop walkthrough

The scenario: a support tool that "summarizes this customer email." The
same email enters multiple systems -- LLM provider, application logs, the
response returned to the agent. Each is a separate disclosure surface.

Diff `vulnerable.py` against `mitigated.py`. Three defenses:

1. **Input-side redaction (data minimization).** Pattern-match PII before
   the prompt is built. The LLM provider never receives the raw data, so
   it cannot be logged by them, memorized, or exposed via future
   training-data leaks.
2. **Log redaction.** Log only the already-redacted prompt. PII never
   touches disk.
3. **Output-side redaction (backstop).** Even a well-behaved LLM can echo
   memorized training data or repeat inputs verbatim. Re-run the redactor
   on the response before returning it.

## Honest caveat

Regex-based PII redaction catches common patterns (email, SSN, phone) and
misses everything else: names, addresses, account numbers, medical details,
free-form secrets. Production systems pair regex with entity recognition
(e.g., Microsoft Presidio, AWS Comprehend PII) and still assume the filter
will miss things -- which is why the output-side backstop matters.
