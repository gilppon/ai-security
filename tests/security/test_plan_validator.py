from core.decisions.actions import DecisionAction
from core.decisions.reasons import ReasonCode
from agent_security.planner.models import AgentPlanRequest, PlanStep
from agent_security.planner.plan_validator import PlanValidator
from agent_security.tools.registry import ToolRegistry
from agent_security.tools.schemas import (
    ArgumentType,
    ToolArgumentSpec,
    ToolCapability,
    ToolDefinition,
)
from resource_security.filesystem.models import FilesystemOperation
from telemetry.audit import InMemoryAuditSink, StructuredAuditLogger


RAW_PATH = "C:/private/credential-material.txt"


def registry() -> ToolRegistry:
    return ToolRegistry((
        ToolDefinition(
            name="status",
            capability=ToolCapability.NONE,
            allowed_agents=("agent-1",),
        ),
        ToolDefinition(
            name="restricted",
            capability=ToolCapability.NONE,
            allowed_agents=("agent-2",),
        ),
        ToolDefinition(
            name="read_file",
            capability=ToolCapability.FILESYSTEM,
            arguments=(ToolArgumentSpec(
                name="path",
                argument_type=ArgumentType.STRING,
            ),),
            allowed_agents=("agent-1",),
            resource_argument="path",
            filesystem_operation=FilesystemOperation.READ,
        ),
        ToolDefinition(
            name="send_http",
            capability=ToolCapability.NETWORK,
            arguments=(ToolArgumentSpec(
                name="url",
                argument_type=ArgumentType.STRING,
            ),),
            allowed_agents=("agent-1",),
            resource_argument="url",
        ),
    ))


def plan(*steps: PlanStep) -> AgentPlanRequest:
    return AgentPlanRequest(
        plan_id="plan-1",
        session_id="session-1",
        steps=steps,
    )


def test_valid_plan_allows_preflight_but_never_authorizes_execution() -> None:
    sink = InMemoryAuditSink()
    validator = PlanValidator(
        registry(),
        audit_logger=StructuredAuditLogger(sink),
    )

    result = validator.validate(
        plan(PlanStep(step_id="step-1", tool="status")),
        verified_agent_id="agent-1",
    )

    assert result.decision.decision is DecisionAction.ALLOW
    assert ReasonCode.PLAN_VALIDATED in result.decision.reason_codes
    assert ReasonCode.PLAN_REQUIRES_STEP_AUTHORIZATION in result.decision.reason_codes
    assert result.execution_authorized is False
    assert result.step_assessments[0].precheck_passed is True
    assert len(sink.records) == 1


def test_unverified_agent_is_denied_without_registry_disclosure() -> None:
    result = PlanValidator(registry()).validate(
        plan(PlanStep(step_id="step-1", tool="status")),
    )

    assert result.decision.decision is DecisionAction.DENY
    assert ReasonCode.PLAN_IDENTITY_UNVERIFIED in result.decision.reason_codes
    assert result.step_assessments == ()


def test_unknown_disallowed_and_invalid_steps_deny_whole_plan() -> None:
    result = PlanValidator(registry()).validate(
        plan(
            PlanStep(step_id="step-1", tool="missing"),
            PlanStep(step_id="step-2", tool="restricted"),
            PlanStep(step_id="step-3", tool="read_file", arguments={}),
        ),
        verified_agent_id="agent-1",
    )

    assert result.decision.decision is DecisionAction.DENY
    reasons = {
        reason
        for assessment in result.step_assessments
        for reason in assessment.reason_codes
    }
    assert reasons == {
        ReasonCode.PLAN_TOOL_UNKNOWN,
        ReasonCode.PLAN_TOOL_NOT_ALLOWED,
        ReasonCode.PLAN_ARGUMENT_INVALID,
    }


def test_file_to_network_chain_is_denied_as_confused_deputy() -> None:
    result = PlanValidator(registry()).validate(
        plan(
            PlanStep(
                step_id="step-1",
                tool="read_file",
                arguments={"path": RAW_PATH},
            ),
            PlanStep(
                step_id="step-2",
                tool="send_http",
                arguments={"url": "https://example.com/upload"},
            ),
        ),
        verified_agent_id="agent-1",
    )

    assert result.decision.decision is DecisionAction.DENY
    assert ReasonCode.PLAN_CONFUSED_DEPUTY in result.decision.reason_codes
    assert result.execution_authorized is False


def test_repeated_tool_chain_is_denied() -> None:
    result = PlanValidator(registry()).validate(
        plan(*(
            PlanStep(step_id=f"step-{index}", tool="status")
            for index in range(6)
        )),
        verified_agent_id="agent-1",
    )

    assert result.decision.decision is DecisionAction.DENY
    assert ReasonCode.PLAN_LOOP_DETECTED in result.decision.reason_codes


def test_raw_plan_arguments_never_enter_result_or_audit() -> None:
    sink = InMemoryAuditSink()
    result = PlanValidator(
        registry(),
        audit_logger=StructuredAuditLogger(sink),
    ).validate(
        plan(PlanStep(
            step_id="step-1",
            tool="read_file",
            arguments={"path": RAW_PATH},
        )),
        verified_agent_id="agent-1",
    )

    assert RAW_PATH not in result.model_dump_json()
    assert RAW_PATH not in sink.records[0]


def test_argument_validator_failure_fails_closed() -> None:
    class FailingArgumentValidator:
        def validate(self, definition, arguments):
            raise RuntimeError("validator unavailable")

    result = PlanValidator(
        registry(),
        argument_validator=FailingArgumentValidator(),
    ).validate(
        plan(PlanStep(step_id="step-1", tool="status")),
        verified_agent_id="agent-1",
    )

    assert result.decision.decision is DecisionAction.DENY
    assert result.decision.reason_codes == (ReasonCode.UNKNOWN_SECURITY_STATE,)
    assert result.step_assessments == ()
