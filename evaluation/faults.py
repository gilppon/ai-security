from __future__ import annotations

from enum import StrEnum
import threading


class FaultStage(StrEnum):
    NORMALIZE = "normalize"
    CONTEXT = "context"
    DETECT = "detect"
    RISK = "risk"
    POLICY = "policy"
    AUDIT = "audit"


class DeterministicFaultInjector:
    """Bounded, server-owned fault injection for resilience tests only."""

    def __init__(self, stages: frozenset[FaultStage] = frozenset()) -> None:
        self._stages = frozenset(stages)
        self._lock = threading.Lock()
        self._hits: dict[str, int] = {}

    def check(self, stage: str) -> None:
        if stage in self._stages:
            with self._lock:
                self._hits[stage] = self._hits.get(stage, 0) + 1
            raise RuntimeError("deterministic fault injected")

    def hits(self, stage: FaultStage) -> int:
        with self._lock:
            return self._hits.get(stage.value, 0)

