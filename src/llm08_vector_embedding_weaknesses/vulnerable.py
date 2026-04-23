"""LLM08: Vector and Embedding Weaknesses -- VULNERABLE example.

A RAG-backed Q&A bot. The vector store contains both public docs (office
hours, password reset) and an HR-confidential doc (salary bands).
Retrieval ranks purely on similarity -- no access-control filter. An
ordinary employee's question about pay pulls the HR doc into the LLM's
context, and the LLM dutifully summarizes it.

Run:
    python vulnerable.py
"""

from llm import generate, retrieve

KNOWLEDGE_BASE = [
    {"id": 1, "access": "public",
     "text": "Company hours: 9am-5pm Monday through Friday."},
    {"id": 2, "access": "public",
     "text": "Password reset: click 'Forgot Password' on the login screen."},
    {"id": 3, "access": "hr_only",
     "text": (
         "Employee salary bands for engineers: "
         "Engineer I $120k, Engineer II $150k, "
         "Senior Engineer $180k, Staff Engineer $240k."
     )},
    {"id": 4, "access": "public",
     "text": "Our office is at 123 Main Street. Visitor parking is in lot B."},
]


def ask(query: str) -> str:
    docs = retrieve(query, KNOWLEDGE_BASE)
    print(f"[retrieved ids] {[d['id'] for d in docs]}")
    print(f"[access levels] {[d['access'] for d in docs]}")
    return generate(query, docs)


if __name__ == "__main__":
    question = "What pay ranges does the company offer for engineers?"
    print(f"Q: {question}")
    print(f"A: {ask(question)}")
