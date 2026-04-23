# LLM08: Vector and Embedding Weaknesses

OWASP LLM Top 10 (2025), risk #8. [Official spec](https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/).

## The vulnerability in one sentence

A RAG system with no retrieval-time access control will hand confidential
documents to whoever asks the right semantically-similar question.

## Run it

```bash
python vulnerable.py   # employee query pulls HR salary doc into the LLM's context
python mitigated.py    # ACL filter at retrieval; HR doc never enters the pipeline
```

No API key required -- the demo ships with a tiny bag-of-words vector
store and a deterministic response simulator. Real systems use proper
embeddings (OpenAI, Cohere, sentence-transformers) in a real vector DB
(pgvector, Pinecone, Weaviate); the access-control lesson is identical.

## Workshop walkthrough

Scenario: a company Q&A bot backed by a mixed knowledge base. Office
hours and password reset are public. One doc holds engineer salary
bands -- HR only.

An ordinary employee asks *"What pay ranges does the company offer for
engineers?"* The salary doc is the most semantically relevant hit. In
the vulnerable version it goes straight into the LLM's context and the
LLM summarizes it to someone with no right to see it.

Diff `vulnerable.py` against `mitigated.py`. One defense:

**Filter the corpus by the user's entitlements *before* the similarity
search, not after.** If the document isn't visible to the user, the
retriever shouldn't be able to surface it. Relying on the LLM to refuse
is LLM01 territory -- an unreliable last line.

## Other LLM08 risks not shown here

OWASP groups several distinct failure modes under this heading. We
picked the most common one. The others:

* **Embedding inversion.** Attackers reconstruct source text from stolen
  embeddings. Defense: treat embedding stores as sensitive data.
* **Poisoned documents.** An attacker inserts a doc whose contents carry
  a prompt-injection payload. On retrieval, the payload reaches the LLM.
  Defense: treat retrieved text as untrusted input (see LLM01).
* **Cross-tenant bleed.** A shared vector index across tenants without
  metadata filtering. Same root cause as this demo: retrieval-time ACLs.

## The key mental shift

Retrieval is not a read of a database row you already had permission to
see. It's a search across a shared index. Apply permission checks at the
*retrieval boundary*, not downstream in the LLM prompt.
