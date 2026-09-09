from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode
from detection.redteam.models import (
    ProbeCategory,
    ProbeSuite,
    ProbeTarget,
    ProbeTemplate,
)
from detection.redteam.runner import ScenarioRunner


class StaticEvaluator:
    def __init__(self, action: DecisionAction) -> None:
        self._action = action

    def evaluate(self, probe: ProbeTemplate) -> SecurityDecision:
        return SecurityDecision(
            decision=self._action,
            risk_score=100 if self._action is DecisionAction.DENY else 0,
            reason_codes=(
                ReasonCode.EXPLICIT_DENY
                if self._action is DecisionAction.DENY
                else ReasonCode.EXPLICIT_ALLOW,
            ),
        )


def probe(
    probe_id: str,
    expected: DecisionAction,
) -> ProbeTemplate:
    return ProbeTemplate(
        probe_id=probe_id,
        category=ProbeCategory.TOOL_ABUSE,
        target=ProbeTarget.TOOL_FIREWALL,
        payload={"tool": "dangerous"},
        expected_decision=expected,
    )


def test_runner_scores_exact_expected_decisions_deterministically() -> None:
    suite = ProbeSuite(
        suite_id="suite-1",
        probes=(
            probe("probe-deny", DecisionAction.DENY),
            probe("probe-allow", DecisionAction.ALLOW),
        ),
    )
    runner = ScenarioRunner({
        ProbeTarget.TOOL_FIREWALL: StaticEvaluator(DecisionAction.DENY),
    })

    first = runner.run(suite)
    second = runner.run(suite)

    assert first.passed == second.passed == 1
    assert first.regression_score_bps == second.regression_score_bps == 5_000
    assert first.decision.decision is DecisionAction.DENY
    assert first.category_scores[0].block_rate_bps == 10_000
    assert first.category_scores[0].pass_rate_bps == 5_000
    assert first.results[1].harness_reason_code is ReasonCode.REDTEAM_EXPECTATION_MISMATCH
