"""Tiny vector store + LLM for workshop demos.

Uses bag-of-words Jaccard similarity instead of real embeddings to keep
the retrieval step visible and dependency-free. Real systems use proper
embeddings (OpenAI, Cohere, sentence-transformers) over a real vector DB
(pgvector, Pinecone, Weaviate); the access-control lesson is identical.
"""

from __future__ import annotations

import os
import re


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"\w+", text.lower()))


def _similarity(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def retrieve(query: str, docs: list[dict], k: int = 2) -> list[dict]:
    """Return the top-k docs by Jaccard similarity to the query."""
    qvec = _tokens(query)
    scored = sorted(
        ((_similarity(qvec, _tokens(d["text"])), d) for d in docs),
        key=lambda pair: pair[0],
        reverse=True,
    )
    return [d for score, d in scored[:k] if score > 0]


def _simulate(context: list[dict]) -> str:
    if not context:
        return "I don't have information on that."
    return f"Based on our docs: {context[0]['text']}"


def generate(query: str, context: list[dict]) -> str:
    if not os.getenv("OPENAI_API_KEY"):
        return _simulate(context)
    from openai import OpenAI

    client = OpenAI()
    joined = "\n\n".join(d["text"] for d in context)
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "Answer strictly from the provided context."},
            {"role": "user", "content": f"Context:\n{joined}\n\nQuestion: {query}"},
        ],
    )
    return resp.choices[0].message.content or ""
