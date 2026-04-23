# LLM06: Excessive Agency

OWASP LLM Top 10 (2025), risk #6. [Official spec](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/).

## The vulnerability in one sentence

The LLM can be tricked (LLM01). The damage comes from what the
surrounding agent was *allowed* to do on the LLM's behalf.

## Run it

```bash
python vulnerable.py   # attacker email triggers exfiltration + deletion
python mitigated.py    # same email, every dangerous call refused
```

No API key required -- a deterministic simulator stands in for the LLM's
tool-selection step. Real agents use provider function-calling (OpenAI
tools, Anthropic tool_use, etc.); the wiring is out of scope for the
demo, but the lessons apply to both.

## Workshop walkthrough

Scenario: an inbox-triage agent. The LLM reads each email and decides
which tools to call. One of those emails is a prompt-injection attempt.

Diff `vulnerable.py` against `mitigated.py`. The defenses line up with
OWASP's three sub-categories:

1. **Excessive functionality -> remove the tool.**
   `forward_all_emails` is gone. No user flow actually needed it; it was
   added "just in case." Nonexistent tools can't be invoked.
2. **Excessive permissions -> scope the tool.**
   `send_email` accepts any recipient in the vulnerable version.
   Mitigated: only known contacts. The normal reply channel stops being
   an exfiltration channel.
3. **Excessive autonomy -> require human-in-the-loop.**
   `delete_email` executes immediately in the vulnerable version.
   Mitigated: refuses unless `user_confirmed=True`. Destructive actions
   ask a person.

## The key mental shift

You cannot reliably prevent an LLM from being tricked. The mitigation
isn't "make the LLM smarter" -- it's "make the blast radius small when
the LLM does the wrong thing." Every tool the agent can call is a
capability you've granted to anyone who can put text in front of it
(email senders, document authors, web page scrapers, and so on).

Design rule of thumb: if a human employee wouldn't be allowed to do
something without approval, the agent shouldn't be either.
