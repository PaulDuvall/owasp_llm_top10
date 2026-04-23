"""LLM08: Vector and Embedding Weaknesses -- MITIGATED example.

Same knowledge base, same query, same user. One defense:

  Filter by the user's entitlements *before* the similarity search, not
  after. If the user can't see a document, the retriever shouldn't be
  able to find it either. The LLM never receives the HR doc, so it can't
  leak it -- no prompt engineering on top of the model can save you here.

Run:
    python mitigated.py
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


def _allowed(doc: dict, user_roles: set[str]) -> bool:
    return doc["access"] == "public" or doc["access"] in user_roles


def ask(query: str, user_roles: set[str]) -> str:
    visible = [d for d in KNOWLEDGE_BASE if _allowed(d, user_roles)]
    docs = retrieve(query, visible)
    print(f"[retrieved ids] {[d['id'] for d in docs]}")
    print(f"[access levels] {[d['access'] for d in docs]}")
    return generate(query, docs)


if __name__ == "__main__":
    question = "What pay ranges does the company offer for engineers?"
    print(f"Q: {question}")
    print(f"(user roles: {{'employee'}} -- no HR access)")
    print(f"A: {ask(question, user_roles={'employee'})}")
