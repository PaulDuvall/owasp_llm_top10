"""End-to-end tests for LLM06 excessive-agency demos."""

import os
import subprocess
import sys
from pathlib import Path

MODULE_DIR = (
    Path(__file__).resolve().parents[1] / "src" / "llm06_excessive_agency"
)


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


def test_vulnerable_exfiltrates_and_deletes():
    out = _run("vulnerable.py")
    assert "EXFILTRATED" in out
    assert "forward_all_emails" in out
    assert "delete_email(id='BULK')" in out


def test_mitigated_refuses_every_dangerous_call():
    out = _run("mitigated.py")
    # Tool removed -> call refused.
    assert "forward_all_emails REFUSED" in out
    assert "EXFILTRATED" not in out
    # Scoped -> external send refused.
    assert "send_email REFUSED" in out
    # Autonomy -> destructive action refused.
    assert "delete_email REFUSED" in out
    # Confirm nothing actually executed.
    assert "delete_email(id='BULK')" not in out
