from core.decisions.reasons import ReasonCode
from detection.models import Severity
from runtime.models import (
    RuntimeActivity,
    RuntimeFinding,
    RuntimeObservation,
    RuntimeOutcome,
)


class RuntimeSequenceCorrelator:
    def correlate(
        self,
        observations: tuple[RuntimeObservation, ...],
    ) -> tuple[RuntimeFinding, ...]:
        if not observations:
            return ()

        current = observations[-1]
        previous = observations[:-1]
        findings: list[RuntimeFinding] = []

        if current.activity in {
            RuntimeActivity.TOOL_CALL,
            RuntimeActivity.MCP_CALL,
            RuntimeActivity.PROCESS_START,
            RuntimeActivity.NETWORK_REQUEST,
        } and any(
            item.activity is RuntimeActivity.PROMPT
            and item.outcome is RuntimeOutcome.BLOCKED
            for item in previous
        ):
            findings.append(_finding(
                "RUNTIME_BLOCKED_PROMPT_BYPASS",
                ReasonCode.RUNTIME_BYPASS_SEQUENCE,
            ))

        if (
            current.activity is RuntimeActivity.NETWORK_REQUEST
            and current.outcome is RuntimeOutcome.ALLOWED
            and any(
                item.activity is RuntimeActivity.FILE_ACCESS
                and item.outcome is RuntimeOutcome.ALLOWED
                for item in previous
            )
        ):
            findings.append(_finding(
                "RUNTIME_FILE_TO_NETWORK_SEQUENCE",
                ReasonCode.RUNTIME_EXFILTRATION_SEQUENCE,
            ))

        return tuple(sorted(findings, key=lambda item: item.code))


def _finding(code: str, reason: ReasonCode) -> RuntimeFinding:
    return RuntimeFinding(
        code=code,
        severity=Severity.CRITICAL,
        risk_score=100,
        reason_code=reason.value,
    )
