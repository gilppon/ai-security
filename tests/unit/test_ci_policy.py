import re
import os
from pathlib import Path
import subprocess
import sys

from policy.signing import PolicySignatureVerifier
from policy.storage import DurablePolicyBundleStore, PolicyApprovalVerifier


WORKFLOW = Path(".github/workflows/security-regression.yml")
DOCKERFILE = Path("Dockerfile")
COMPOSE = Path("docker-compose.yml")
DEPLOYMENT_RUNBOOK = Path("docs/production_deployment_runbook.md")


def test_security_workflow_uses_pinned_actions_and_safe_events() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "pull_request_target" not in workflow
    action_refs = re.findall(r"uses:\s*[^@\s]+@([^\s#]+)", workflow)
    assert action_refs
    assert all(re.fullmatch(r"[0-9a-f]{40}", reference) for reference in action_refs)
    assert "permissions:\n  contents: read" in workflow
    assert "runner: windows-11-arm" in workflow
    assert "runs-on: ${{ matrix.runner || 'windows-latest' }}" in workflow


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
    assert "failed targets:" in workflow
    assert "$failedTargets += $testTarget" in workflow
    assert "AISCP_SAFE_DIAGNOSTIC: decision=[A-Z_]+" in workflow
    assert "failure_stage=(none|[A-Z_]+)" in workflow
    assert "os_error_code=(none|[0-9]+)" in workflow
    assert "Write-Output $_.Value" in workflow
    assert "$env:GITHUB_STEP_SUMMARY" in workflow
    assert '"- $failedTarget"' in workflow
    assert "path: .artifacts/phase11/resilience-evidence.json" in workflow
    assert "path: $capturedLog" not in workflow


def test_release_container_controls_are_ci_enforced() -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    compose = COMPOSE.read_text(encoding="utf-8")
    workflow = WORKFLOW.read_text(encoding="utf-8")

    first_line = dockerfile.splitlines()[0]
    assert first_line == (
        "FROM python:3.13.15-slim-bookworm@sha256:"
        "ed86c82274b3c69b52fb5820f358f0bd7df0b603332063cb5c6e32bd220c3e6e"
    )
    assert "HEALTHCHECK" in dockerfile
    assert "http://127.0.0.1:8000/v1/health" in dockerfile
    assert "USER aisec" in dockerfile

    assert "AI_SECURITY_ENVIRONMENT: development" in compose
    assert "ai-security.environment: development-only" in compose
    assert "pids_limit:" in compose
    assert "mem_limit:" in compose
    assert "cpus:" in compose

    assert "release-container:" in workflow
    assert "runs-on: ubuntu-latest" in workflow
    assert "docker build --pull" in workflow
    assert "AI_SECURITY_ENVIRONMENT=production" in workflow
    assert "AI_SECURITY_REQUIRE_VERIFIED_POLICY=true" in workflow
    assert "ReadonlyRootfs" in workflow
    assert "anchore/sbom-action@3ad7283483fc7af8ff2b4ea19663c2d5ca935e26" in workflow
    assert "anchore/scan-action@27805bf3b4e84b4a5c980df22ed233c00390a439" in workflow
    assert "severity-cutoff: high" in workflow
    assert "only-fixed: true" in workflow


def test_live_r2_gate_requires_repository_secrets() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "r2-live:" in workflow
    for name in (
        "AI_SECURITY_R2_ENDPOINT",
        "AI_SECURITY_R2_BUCKET",
        "AI_SECURITY_R2_ACCESS_KEY_ID",
        "AI_SECURITY_R2_SECRET_ACCESS_KEY",
    ):
        assert f"{name}: ${{{{ secrets.{name} }}}}" in workflow
    assert "Required R2 secret is missing" in workflow


def test_production_deployment_runbook_defines_rollback_and_evidence() -> None:
    runbook = DEPLOYMENT_RUNBOOK.read_text(encoding="utf-8")

    for required in (
        "immutable image digest",
        "AI_SECURITY_REQUIRE_VERIFIED_POLICY=true",
        "required R2 replication",
        "Rollback",
        "previous image digest",
        "/v1/health",
        "SBOM",
    ):
        assert required in runbook


def test_ci_policy_fixture_creates_verifiable_store(tmp_path) -> None:
    signer_key = b"release-signer-key-material-00001"
    approver_key = b"release-approver-key-material-001"
    store_path = tmp_path / "policy.jsonl"
    environment = {
        **os.environ,
        "CI": "true",
        "AI_SECURITY_ENVIRONMENT": "production",
        "AI_SECURITY_REQUIRE_VERIFIED_POLICY": "true",
        "AI_SECURITY_POLICY_SIGNER_ID": "release-ci-signer",
        "AI_SECURITY_POLICY_SIGNING_KEY_HEX": signer_key.hex(),
        "AI_SECURITY_POLICY_APPROVER_ID": "release-ci-approver",
        "AI_SECURITY_POLICY_APPROVAL_KEY_HEX": approver_key.hex(),
        "AI_SECURITY_POLICY_STORE_PATH": str(store_path),
    }

    result = subprocess.run(
        [sys.executable, "scripts/create_ci_policy_fixture.py"],
        shell=False,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert result.returncode == 0
    assert "content_fingerprint" in result.stdout
    signed, approval = DurablePolicyBundleStore(store_path).load_latest()
    assert PolicySignatureVerifier({"release-ci-signer": signer_key}).verify(signed)
    assert PolicyApprovalVerifier({"release-ci-approver": approver_key}).verify(approval)
