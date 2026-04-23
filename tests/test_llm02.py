"""End-to-end tests for LLM02 sensitive-information-disclosure demos."""

import os
import subprocess
import sys
from pathlib import Path

MODULE_DIR = (
    Path(__file__).resolve().parents[1] / "src" / "llm02_sensitive_info_disclosure"
)
PII_EMAIL = "jane.doe@example.com"
PII_SSN = "123-45-6789"


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


def test_vulnerable_leaks_pii_to_logs_and_response():
    out = _run("vulnerable.py")
    assert PII_EMAIL in out
    assert PII_SSN in out


def test_mitigated_redacts_pii_everywhere():
    out = _run("mitigated.py")
    assert PII_EMAIL not in out
    assert PII_SSN not in out
    assert "[EMAIL]" in out
    assert "[SSN]" in out
