# Running these demos in a workshop

Suggested pairings for a 30-35 minute lab slot. Each pairing covers two
risks that share a natural narrative, so the second demo builds on the
setup you did for the first.

## Lab A -- The agent loop (LLM01 + LLM06)

**The through-line:** you can't make an LLM immune to prompt injection
(LLM01). So design the agent around it so trickery doesn't translate
into real-world damage (LLM06).

**Runsheet (35 min):**

| Minutes | Segment |
|---|---|
| 0-5   | Set the scene: attacker text arrives via user input, email, document, web page. |
| 5-13  | [LLM01](src/llm01_prompt_injection/) -- run `vulnerable.py` live, then `mitigated.py`. Diff both. Point out that every defense is bypassable. |
| 13-18 | Bridge: *"So if the LLM can always be tricked, how do we make that not matter?"* |
| 18-30 | [LLM06](src/llm06_excessive_agency/) -- run `vulnerable.py` (show the `EXFILTRATED` line), then `mitigated.py` (three `REFUSED` lines). Walk through the three defenses. |
| 30-35 | Wrap: design rule -- if a human employee couldn't do it without approval, the agent shouldn't either. |

**Key diffs to pull up on screen:**

- `llm01_prompt_injection/mitigated.py` lines for `_looks_like_injection` and `_redact_secrets`.
- `llm06_excessive_agency/mitigated.py` -- `KNOWN_CONTACTS` check, `user_confirmed` gate, and the missing `forward_all_emails` tool.

## Lab B -- The RAG pipeline (LLM02 + LLM08)

**The through-line:** data you hand an LLM flows in both directions --
user input flowing *in* to providers and logs (LLM02), retrieved
documents flowing *out* of the vector store into the prompt (LLM08).
Both boundaries need access discipline.

**Runsheet (35 min):**

| Minutes | Segment |
|---|---|
| 0-5   | Set the scene: a "summarize this" assistant plus a "ask the knowledge base" assistant. Same ingredients, two different leak directions. |
| 5-17  | [LLM02](src/llm02_sensitive_info_disclosure/) -- run `vulnerable.py`. Show the `[log]` line containing PII. Run `mitigated.py`. Point out that one redactor covers three distinct disclosure surfaces (provider, logs, response). |
| 17-22 | Bridge: *"That was data going **into** the LLM. What about data coming **out** of retrieval?"* |
| 22-32 | [LLM08](src/llm08_vector_embedding_weaknesses/) -- run `vulnerable.py`, show `[access levels] ['hr_only', 'public']`, then run `mitigated.py` and show the HR doc never gets retrieved. |
| 32-35 | Wrap: retrieval is a *search*, not a *read*. Put ACLs at the retrieval boundary, not in the LLM prompt. |

**Key diffs to pull up on screen:**

- `llm02_sensitive_info_disclosure/mitigated.py` -- `_redact` applied to input and to output; log line shows redacted text.
- `llm08_vector_embedding_weaknesses/mitigated.py` -- the `visible = [...]` filter one line before `retrieve(...)`.

## Tips

- **Always run the vulnerable demo first.** Attendees need to *see* the
  leak before they care about the fix.
- **Don't explain the simulator.** It's a stand-in so the demo works
  offline. Treat it like the real LLM; the security point is identical.
- **Set `OPENAI_API_KEY`** if you want the real-model version for labs
  A and B. LLM06 and LLM08 stay on the simulator either way (real
  function-calling and real embeddings are out of scope).
- **Each demo is self-contained.** Attendees can `cd` into any
  `src/llmXX_*/` folder, copy it into their own project, and the code
  still runs.
