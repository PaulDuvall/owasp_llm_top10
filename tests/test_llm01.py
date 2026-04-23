"""End-to-end tests for LLM01 prompt-injection demos.

Tests run both scripts as subprocesses and assert on their stdout. This
matches how workshop attendees run them: `python vulnerable.py`.
"""

import os
import subprocess
import sys
from pathlib import Path

MODULE_DIR = (
    Path(__file__).resolve().parents[1] / "src" / "llm01_prompt_injection"
)
SECRET_URL = "https://internal.acme.corp/admin"


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


def test_vulnerable_leaks_secret_url():
    assert SECRET_URL in _run("vulnerable.py")


def test_mitigated_does_not_leak_secret_url():
    assert SECRET_URL not in _run("mitigated.py")
