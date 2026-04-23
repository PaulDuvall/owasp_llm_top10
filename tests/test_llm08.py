"""End-to-end tests for LLM08 vector/embedding demos."""

import os
import subprocess
import sys
from pathlib import Path

MODULE_DIR = (
    Path(__file__).resolve().parents[1] / "src" / "llm08_vector_embedding_weaknesses"
)
SALARY_FIGURE = "180k"


def _run(script: str) -> str:
    env = {k: v for k, v in os.environ.items() if k != "OPENAI_API_KEY"}
    result = subprocess.run(
        [sys.executable, script],
        capture_output=True,
        text=True,
        check=True,
        cwd=MODULE_DIR,
        env=env,
    )
    return result.stdout


def test_vulnerable_leaks_hr_salary_data():
    out = _run("vulnerable.py")
    assert SALARY_FIGURE in out
    assert "'hr_only'" in out


def test_mitigated_excludes_hr_doc_before_retrieval():
    out = _run("mitigated.py")
    assert SALARY_FIGURE not in out
    assert "'hr_only'" not in out
