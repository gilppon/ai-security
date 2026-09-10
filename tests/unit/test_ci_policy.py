import re
from pathlib import Path


WORKFLOW = Path(".github/workflows/security-regression.yml")


def test_security_workflow_uses_pinned_actions_and_safe_events() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "pull_request_target" not in workflow
    action_refs = re.findall(r"uses:\s*[^@\s]+@([^\s#]+)", workflow)
    assert action_refs
    assert all(re.fullmatch(r"[0-9a-f]{40}", reference) for reference in action_refs)
    assert "permissions:\n  contents: read" in workflow


def test_every_test_file_is_assigned_to_a_phase_regression_job() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8").replace("\\", "/")
    test_files = {
        path.as_posix()
        for path in Path("tests").rglob("test_*.py")
    }

    missing = sorted(path for path in test_files if path not in workflow)

    assert missing == []


def test_workflow_uploads_only_allowlisted_phase11_evidence() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "*> $capturedLog" in workflow
    assert "path: .artifacts/phase11/resilience-evidence.json" in workflow
    assert "path: $capturedLog" not in workflow
