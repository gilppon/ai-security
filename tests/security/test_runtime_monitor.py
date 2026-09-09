from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode
from core.events.factory import SecurityEventFactory
from runtime.behavior.profiles import BehaviorProfile
from runtime.collector.agent import RuntimeCollector
from runtime.models import (
    RuntimeActivity,
    RuntimeEventRequest,
    RuntimeOutcome,
)
from runtime.monitor import RuntimeMonitor
from runtime.sessions.manager import SessionManager
from telemetry.audit import InMemoryAuditSink, StructuredAuditLogger


def profile(agent_id: str = "agent-1") -> BehaviorProfile:
    return BehaviorProfile(
        agent_id=agent_id,
        allowed_activities=frozenset(RuntimeActivity),
        max_events_per_window=10,
        max_denied_per_window=3,
        max_distinct_targets_per_window=5,
    )


def request(
    activity: RuntimeActivity = RuntimeActivity.PROMPT,
    *,
    session_id: str = "session-1",
    outcome: RuntimeOutcome = RuntimeOutcome.ALLOWED,
    target: str | None = None,
) -> RuntimeEventRequest:
    return RuntimeEventRequest(
        session_id=session_id,
        activity=activity,
        outcome=outcome,
        target_fingerprint=target,
    )


def test_unverified_and_unprofiled_events_are_denied_without_session() -> None:
    monitor = RuntimeMonitor((profile(),))

    unverified = monitor.observe(request())
    unprofiled = monitor.observe(request(session_id="session-2"), verified_agent_id="agent-2")
    unverified_session = monitor.inspect_session("session-1", verified_agent_id="agent-1")
    unprofiled_session = monitor.inspect_session("session-2", verified_agent_id="agent-2")

    assert ReasonCode.RUNTIME_IDENTITY_UNVERIFIED in unverified.decision.reason_codes
    assert ReasonCode.RUNTIME_PROFILE_MISSING in unprofiled.decision.reason_codes
    assert unverified_session.summary is None
    assert unprofiled_session.summary is None


def test_verified_event_is_stored_and_summary_exposes_only_aggregates() -> None:
    target = "a" * 16
    monitor = RuntimeMonitor((profile(),))

    observed = monitor.observe(request(target=target), verified_agent_id="agent-1")
    inspected = monitor.inspect_session("session-1", verified_agent_id="agent-1")

    assert observed.decision.decision is DecisionAction.ALLOW
    assert ReasonCode.RUNTIME_EVENT_ACCEPTED in observed.decision.reason_codes
    assert inspected.decision.decision is DecisionAction.ALLOW
    assert inspected.summary is not None
    assert inspected.summary.event_count == 1
    assert target not in inspected.model_dump_json()


def test_session_ownership_mismatch_is_denied_and_not_appended() -> None:
    monitor = RuntimeMonitor((profile("agent-1"), profile("agent-2")))
    monitor.observe(request(), verified_agent_id="agent-1")

    denied = monitor.observe(request(), verified_agent_id="agent-2")
    owner_view = monitor.inspect_session("session-1", verified_agent_id="agent-1")

    assert ReasonCode.RUNTIME_SESSION_OWNERSHIP_DENIED in denied.decision.reason_codes
    assert owner_view.summary is not None
    assert owner_view.summary.event_count == 1


def test_correlated_sequence_is_denied_and_audited() -> None:
    sink = InMemoryAuditSink()
    monitor = RuntimeMonitor(
        (profile(),),
        audit_logger=StructuredAuditLogger(sink),
    )
    monitor.observe(
        request(outcome=RuntimeOutcome.BLOCKED),
        verified_agent_id="agent-1",
    )

    result = monitor.observe(
        request(RuntimeActivity.PROCESS_START),
        verified_agent_id="agent-1",
    )

    assert result.decision.decision is DecisionAction.DENY
    assert ReasonCode.RUNTIME_BYPASS_SEQUENCE in result.decision.reason_codes
    assert len(sink.records) == 2


def test_session_storage_is_bounded_and_expires() -> None:
    now = [1.0]
    manager = SessionManager(
        max_sessions=1,
        max_events_per_session=2,
        idle_ttl_seconds=1,
        clock=lambda: now[0],
    )
    monitor = RuntimeMonitor((profile(),), session_manager=manager)
    for activity in (
        RuntimeActivity.PROMPT,
        RuntimeActivity.OUTPUT,
        RuntimeActivity.TOOL_SELECTION,
    ):
        monitor.observe(request(activity), verified_agent_id="agent-1")

    summary = monitor.inspect_session("session-1", verified_agent_id="agent-1")
    assert summary.summary is not None
    assert summary.summary.event_count == 2

    capacity = monitor.observe(
        request(session_id="session-2"),
        verified_agent_id="agent-1",
    )
    assert ReasonCode.RUNTIME_SESSION_CAPACITY in capacity.decision.reason_codes

    now[0] = 3.0
    replacement = monitor.observe(
        request(session_id="session-2"),
        verified_agent_id="agent-1",
    )
    assert replacement.decision.decision is DecisionAction.ALLOW


def test_failing_detector_does_not_create_empty_session() -> None:
    class FailingDetector:
        def detect(self, observations, active_profile):
            raise RuntimeError("detector unavailable")

    monitor = RuntimeMonitor(
        (profile(),),
        anomaly_detector=FailingDetector(),
    )

    result = monitor.observe(request(), verified_agent_id="agent-1")
    inspected = monitor.inspect_session("session-1", verified_agent_id="agent-1")

    assert result.decision.decision is DecisionAction.DENY
    assert ReasonCode.UNKNOWN_SECURITY_STATE in result.decision.reason_codes
    assert ReasonCode.RUNTIME_SESSION_NOT_FOUND in inspected.decision.reason_codes


def test_runtime_collector_maps_decision_without_copying_raw_event_data() -> None:
    monitor = RuntimeMonitor((profile(),))
    collector = RuntimeCollector(monitor)
    source = SecurityEventFactory().create(
        event_type="agent.tool.authorize",
        source="agent",
        session_id="session-1",
        agent_id="agent-1",
        data={
            "tool_fingerprint": "b" * 16,
            "raw_argument": "do not copy",
        },
    )
    decision = SecurityDecision(
        decision=DecisionAction.ALLOW,
        risk_score=0,
        reason_codes=(ReasonCode.EXPLICIT_ALLOW,),
    )

    result = collector.collect(
        source,
        decision,
        RuntimeActivity.TOOL_CALL,
        verified_agent_id="agent-1",
    )
    inspected = monitor.inspect_session("session-1", verified_agent_id="agent-1")

    assert result.decision.decision is DecisionAction.ALLOW
    assert inspected.summary is not None
    assert inspected.summary.activity_counts == {"tool_call": 1}
    assert "do not copy" not in result.model_dump_json()
    assert "b" * 16 not in inspected.model_dump_json()


def test_runtime_collector_denies_source_agent_identity_mismatch() -> None:
    monitor = RuntimeMonitor((profile(),))
    collector = RuntimeCollector(monitor)
    source = SecurityEventFactory().create(
        event_type="agent.tool.authorize",
        source="agent",
        session_id="session-1",
        agent_id="agent-2",
    )
    decision = SecurityDecision(
        decision=DecisionAction.ALLOW,
        risk_score=0,
        reason_codes=(ReasonCode.EXPLICIT_ALLOW,),
    )

    result = collector.collect(
        source,
        decision,
        RuntimeActivity.TOOL_CALL,
        verified_agent_id="agent-1",
    )
    inspected = monitor.inspect_session("session-1", verified_agent_id="agent-1")

    assert result.decision.decision is DecisionAction.DENY
    assert ReasonCode.RUNTIME_IDENTITY_UNVERIFIED in result.decision.reason_codes
    assert ReasonCode.RUNTIME_SESSION_NOT_FOUND in inspected.decision.reason_codes
