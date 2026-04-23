# LLM01: Prompt Injection

OWASP LLM Top 10 (2025), risk #1. [Official spec](https://genai.owasp.org/llmrisk/llm01-prompt-injection/).

## The vulnerability in one sentence

An LLM treats data as instructions. If user-supplied text reaches the model
alongside a system prompt, a determined user can override the system prompt.

## Run it

```bash
python vulnerable.py   # leaks the secret admin URL
python mitigated.py    # refuses the same attack
```

No API key required -- both scripts fall back to a deterministic simulator
that makes the vulnerability visible offline. Set `OPENAI_API_KEY` to run
against a real model.

## Workshop walkthrough

Diff `vulnerable.py` against `mitigated.py`. Three defenses, none of which
is sufficient alone:

1. **Role separation.** `{role: system}` and `{role: user}` instead of
   string concatenation. Reduces injection success rate; does not eliminate it.
2. **Input screening.** Reject prompts matching known override patterns.
   Pattern-based and bypassable with creative phrasing or encoding.
3. **Output screening.** Redact sensitive substrings before returning.
   The backstop: assume the earlier defenses will fail.

## Honest caveat

At the current state of the art you cannot make an LLM fully
prompt-injection-proof. The correct posture is to assume the LLM will be
injected and constrain what the surrounding system allows its output to
*do* -- which is the next risk, [LLM06 Excessive Agency](../llm06_excessive_agency/).
