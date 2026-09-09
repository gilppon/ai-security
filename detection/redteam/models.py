import json
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode


MAX_PROBES_PER_SUITE = 1_000
MAX_PROBE_PAYLOAD_BYTES = 65_536


class ProbeCategory(StrEnum):
    PROMPT_INJECTION = "prompt_injection"
    RAG_POISON = "rag_poison"
    MCP_ESCALATION = "mcp_escalation"
    SECRET_LEAK = "secret_leak"
    TOOL_ABUSE = "tool_abuse"


class ProbeTarget(StrEnum):
    PROMPT_FIREWALL = "prompt_firewall"
    CONTENT_FIREWALL = "content_firewall"
    MCP_GATEWAY = "mcp_gateway"
    OUTPUT_GUARD = "output_guard"
    TOOL_FIREWALL = "tool_firewall"


_TARGET_BY_CATEGORY = {
    ProbeCategory.PROMPT_INJECTION: ProbeTarget.PROMPT_FIREWALL,
    ProbeCategory.RAG_POISON: ProbeTarget.CONTENT_FIREWALL,
    ProbeCategory.MCP_ESCALATION: ProbeTarget.MCP_GATEWAY,
    ProbeCategory.SECRET_LEAK: ProbeTarget.OUTPUT_GUARD,
    ProbeCategory.TOOL_ABUSE: ProbeTarget.TOOL_FIREWALL,
}


class ProbeTemplate(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    probe_id: str = Field(
        min_length=3,
        max_length=128,
        pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$",
    )
    category: ProbeCategory
    target: ProbeTarget
    payload: dict[str, JsonValue] = Field(min_length=1, max_length=32)
    expected_decision: DecisionAction

    @model_validator(mode="after")
    def bound_payload_size(self) -> "ProbeTemplate":
        if self.target is not _TARGET_BY_CATEGORY[self.category]:
            raise ValueError("probe target does not match its security category")
        serialized = json.dumps(
            self.payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        if len(serialized) > MAX_PROBE_PAYLOAD_BYTES:
            raise ValueError("probe payload exceeds size limit")
        return self


class ProbeSuite(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    suite_id: str = Field(
        min_length=3,
        max_length=128,
        pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$",
    )
    probes: tuple[ProbeTemplate, ...] = Field(
        min_length=1,
        max_length=MAX_PROBES_PER_SUITE,
    )

    @model_validator(mode="after")
    def require_unique_probe_ids(self) -> "ProbeSuite":
        probe_ids = [probe.probe_id for probe in self.probes]
        if len(probe_ids) != len(set(probe_ids)):
            raise ValueError("probe ids must be unique within a suite")
        return self


class ProbeResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    probe_id: str
    category: ProbeCategory
    target: ProbeTarget
    payload_fingerprint: str = Field(pattern=r"^[a-f0-9]{16}$")
    expected_decision: DecisionAction
    actual_decision: DecisionAction | None
    actual_reason_codes: tuple[ReasonCode, ...] = ()
    passed: bool
    harness_reason_code: ReasonCode


class CategoryScore(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    category: ProbeCategory
    total: int = Field(ge=1)
    passed: int = Field(ge=0)
    blocked: int = Field(ge=0)
    pass_rate_bps: int = Field(ge=0, le=10_000)
    block_rate_bps: int = Field(ge=0, le=10_000)


class RegressionReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    suite_id: str
    suite_fingerprint: str = Field(pattern=r"^[a-f0-9]{16}$")
    decision: SecurityDecision
    total: int = Field(ge=1)
    passed: int = Field(ge=0)
    regression_score_bps: int = Field(ge=0, le=10_000)
    category_scores: tuple[CategoryScore, ...]
    results: tuple[ProbeResult, ...]
