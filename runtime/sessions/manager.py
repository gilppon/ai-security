from collections.abc import Callable
from dataclasses import replace
import threading
import time

from core.decisions.reasons import ReasonCode
from runtime.models import (
    RuntimeFinding,
    RuntimeObservation,
    RuntimeOutcome,
    SessionRecord,
    SessionSummary,
)


ObservationEvaluator = Callable[
    [tuple[RuntimeObservation, ...]],
    tuple[RuntimeFinding, ...],
]


class SessionManager:
    def __init__(
        self,
        *,
        max_sessions: int = 10_000,
        max_events_per_session: int = 256,
        idle_ttl_seconds: float = 3600,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not 1 <= max_sessions <= 100_000:
            raise ValueError("max sessions is outside supported bounds")
        if not 2 <= max_events_per_session <= 10_000:
            raise ValueError("max events per session is outside supported bounds")
        if not 1 <= idle_ttl_seconds <= 86_400:
            raise ValueError("session TTL is outside supported bounds")
        self._max_sessions = max_sessions
        self._max_events_per_session = max_events_per_session
        self._idle_ttl_seconds = idle_ttl_seconds
        self._clock = clock
        self._sessions: dict[str, SessionRecord] = {}
        self._lock = threading.RLock()

    def observe(
        self,
        observation: RuntimeObservation,
        evaluator: ObservationEvaluator,
    ) -> tuple[tuple[RuntimeFinding, ...], int, ReasonCode | None]:
        with self._lock:
            now = self._clock()
            self._purge_expired(now)
            record = self._sessions.get(observation.session_id)
            is_new = record is None
            if record is None:
                if len(self._sessions) >= self._max_sessions:
                    return (), 0, ReasonCode.RUNTIME_SESSION_CAPACITY
                record = SessionRecord(
                    session_id=observation.session_id,
                    agent_id=observation.agent_id,
                    last_seen_monotonic=now,
                )
            elif record.agent_id != observation.agent_id:
                return (
                    (),
                    len(record.observations),
                    ReasonCode.RUNTIME_SESSION_OWNERSHIP_DENIED,
                )

            candidate = (*record.observations, observation)
            findings = evaluator(candidate)
            stored = replace(
                observation,
                reason_codes=tuple(finding.reason_code for finding in findings),
            )
            record.observations.append(stored)
            if len(record.observations) > self._max_events_per_session:
                del record.observations[:-self._max_events_per_session]
            record.last_seen_monotonic = now
            if is_new:
                self._sessions[observation.session_id] = record
            return findings, len(record.observations), None

    def inspect(
        self,
        session_id: str,
        agent_id: str,
    ) -> tuple[SessionSummary | None, ReasonCode | None]:
        with self._lock:
            now = self._clock()
            self._purge_expired(now)
            record = self._sessions.get(session_id)
            if record is None:
                return None, ReasonCode.RUNTIME_SESSION_NOT_FOUND
            if record.agent_id != agent_id:
                return None, ReasonCode.RUNTIME_SESSION_OWNERSHIP_DENIED
            record.last_seen_monotonic = now
            observations = tuple(record.observations)
            activity_counts = _counts(item.activity.value for item in observations)
            outcome_counts = _counts(item.outcome.value for item in observations)
            anomaly_counts = _counts(
                reason
                for item in observations
                for reason in item.reason_codes
            )
            return SessionSummary(
                session_id=record.session_id,
                agent_id=record.agent_id,
                event_count=len(observations),
                activity_counts=activity_counts,
                outcome_counts=outcome_counts,
                anomaly_counts=anomaly_counts,
                started_at=observations[0].timestamp,
                updated_at=observations[-1].timestamp,
            ), None

    def _purge_expired(self, now: float) -> None:
        expired = [
            session_id
            for session_id, record in self._sessions.items()
            if now - record.last_seen_monotonic > self._idle_ttl_seconds
        ]
        for session_id in expired:
            del self._sessions[session_id]


def _counts(values) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))
