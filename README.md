# OWASP LLM Top 10 -- Workshop Demos

[![CI](https://github.com/PaulDuvall/owasp_llm_top10/actions/workflows/ci.yml/badge.svg)](https://github.com/PaulDuvall/owasp_llm_top10/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.11-blue.svg)

Minimal, runnable examples of risks from the
[OWASP LLM Top 10 (2025)](https://genai.owasp.org/llm-top-10/), built for
live workshops. Each risk has a `vulnerable.py` and a `mitigated.py` that
differ by a small, teachable diff.

This is a **teaching artifact**, not a scanner. For production red-teaming
use [garak](https://github.com/NVIDIA/garak) or
[promptfoo](https://github.com/promptfoo/promptfoo).

## Risks covered

- [LLM01 -- Prompt Injection](src/llm01_prompt_injection/)
- [LLM02 -- Sensitive Information Disclosure](src/llm02_sensitive_info_disclosure/)
- [LLM06 -- Excessive Agency](src/llm06_excessive_agency/)
- [LLM08 -- Vector and Embedding Weaknesses](src/llm08_vector_embedding_weaknesses/)

## Quickstart

```bash
pip install -r requirements.txt
python src/llm01_prompt_injection/vulnerable.py
python src/llm01_prompt_injection/mitigated.py
```

No API key required -- each demo includes a deterministic simulator. Set
`OPENAI_API_KEY` and install `openai` to run against a real model.

## Run the tests

```bash
pytest
```

## Workshop format

See [WORKSHOP.md](WORKSHOP.md) for suggested 35-minute lab pairings
(agent-loop lab: LLM01+LLM06; RAG lab: LLM02+LLM08) with runsheets.

## Course

These demos back the O'Reilly Live Training course *AI-Native DevSecOps:
Shipping Secure AI-Generated Code Through a CI/CD Pipeline*. Instructor:
Paul Duvall.
