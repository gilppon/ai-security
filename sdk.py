"""In-Process Embedded SDK for the AI Security Control Plane.

Provides zero-overhead direct python integration without spinning up
Docker/FastAPI microservices.
"""

from __future__ import annotations

import asyncio
from enum import StrEnum
from functools import wraps
import inspect
from pathlib import Path
from typing import Any, Callable, TypeVar

from agent_security.tools.firewall import ToolFirewall
from agent_security.tools.schemas import ToolAuthorizationResult, ToolAuthorizeRequest
from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode
from core.events.models import SecurityEvent
from core.pipeline import SecurityPipeline
from input_security.prompt.firewall import PromptFirewall
from input_security.prompt.models import PromptScanRequest, PromptScanResult
from output_security.guard import OutputGuard
from output_security.models import OutputScanRequest, OutputScanResult
from policy.lifecycle import PolicyBundleRegistry
from policy.runtime import ActivePolicyDetector
from telemetry.audit import StructuredAuditLogger

F = TypeVar("F", bound=Callable[..., Any])


class Profile(StrEnum):
    """Execution profiles defining security depth and resource constraints."""

    LITE = "LITE"  # Stateless in-memory prompt checks & regex (Zero IO / Zero network)
    STANDARD = "STANDARD"  # Lite + Tool/MCP Firewalls + Virtual Sandboxing
    STRICT = "STRICT"  # Enterprise mode (Mandatory isolation, deep plan validation, R2 audit)


class AISecurityException(Exception):
    """Base exception for AI Security Control Plane errors."""


class SecurityViolationException(AISecurityException):
    """Raised when an operation is blocked by the security policy."""

    def __init__(self, decision: SecurityDecision, message: str | None = None) -> None:
        self.decision = decision
        self.risk_score = decision.risk_score
        self.reason_codes = [c.value if hasattr(c, "value") else str(c) for c in decision.reason_codes]
        reasons_str = ", ".join(self.reason_codes) or "SECURITY_VIOLATION"
        super().__init__(message or f"Security operation DENIED [risk={self.risk_score}, reasons={reasons_str}]")


class AISecurityClient:
    """Enterprise In-Process Security Client."""

    def __init__(
        self,
        profile: Profile | str = Profile.STANDARD,
        *,
        policy_detector: ActivePolicyDetector | None = None,
        audit_logger: StructuredAuditLogger | None = None,
    ) -> None:
        if isinstance(profile, str):
            profile = Profile(profile.upper())
        self.profile = profile

        # Initialize policy detector
        self.policy_detector = policy_detector or ActivePolicyDetector(PolicyBundleRegistry())
        self.audit_logger = audit_logger or StructuredAuditLogger()

        # Build firewalls tailored to profile
        if self.profile == Profile.LITE:
            # Lite mode: purely stateless in-memory prompt inspection
            self.prompt_firewall = PromptFirewall(
                policy_detector=self.policy_detector,
                audit_logger=self.audit_logger,
            )
            self.tool_firewall = None
            self.output_guard = None
        elif self.profile == Profile.STANDARD:
            self.prompt_firewall = PromptFirewall(
                policy_detector=self.policy_detector,
                audit_logger=self.audit_logger,
            )
            self.tool_firewall = ToolFirewall(
                policy_detector=self.policy_detector,
                audit_logger=self.audit_logger,
            )
            self.output_guard = OutputGuard(
                policy_detector=self.policy_detector,
                audit_logger=self.audit_logger,
            )
        else:  # STRICT
            self.prompt_firewall = PromptFirewall(
                policy_detector=self.policy_detector,
                audit_logger=self.audit_logger,
            )
            self.tool_firewall = ToolFirewall(
                policy_detector=self.policy_detector,
                audit_logger=self.audit_logger,
            )
            self.output_guard = OutputGuard(
                policy_detector=self.policy_detector,
                audit_logger=self.audit_logger,
            )

    def scan_prompt(
        self,
        prompt: str,
        *,
        session_id: str = "in_process_session",
        user_id: str = "default_user",
        raise_on_deny: bool = False,
    ) -> PromptScanResult:
        """Scan a user prompt for injection, jailbreaks, and sensitive leaks."""
        req = PromptScanRequest(
            prompt=prompt,
            session_id=session_id,
            user_id=user_id,
        )
        result = self.prompt_firewall.scan(req)
        if raise_on_deny and result.decision.decision == DecisionAction.DENY:
            raise SecurityViolationException(result.decision)
        return result

    def authorize_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        *,
        session_id: str = "in_process_session",
        agent_id: str = "default_agent",
        trust_level: str = "UNTRUSTED",
        raise_on_deny: bool = False,
    ) -> ToolAuthorizationResult:
        """Authorize a tool invocation against security policies and sandboxes."""
        if self.tool_firewall is None:
            raise AISecurityException(f"Tool authorization is not supported under Profile.{self.profile}")

        req = ToolAuthorizeRequest(
            session_id=session_id,
            agent_id=agent_id,
            tool_name=tool_name,
            arguments=arguments or {},
            declared_trust=trust_level,
        )
        result = self.tool_firewall.authorize(req)
        if raise_on_deny and result.decision.decision == DecisionAction.DENY:
            raise SecurityViolationException(result.decision)
        return result

    def scan_output(
        self,
        text: str,
        *,
        session_id: str = "in_process_session",
        agent_id: str = "default_agent",
        raise_on_deny: bool = False,
    ) -> OutputScanResult:
        """Scan LLM output for data leakage, unsafe instructions, or compromised content."""
        if self.output_guard is None:
            raise AISecurityException(f"Output scanning is not supported under Profile.{self.profile}")

        req = OutputScanRequest(
            session_id=session_id,
            agent_id=agent_id,
            content=text,
        )
        result = self.output_guard.scan(req)
        if raise_on_deny and result.decision.decision == DecisionAction.DENY:
            raise SecurityViolationException(result.decision)
        return result

    def evaluate(self, event: SecurityEvent) -> SecurityDecision:
        """Synchronously evaluate any raw SecurityEvent."""
        from core.normalization import DefaultEventNormalizer
        from core.context.builder import ContextBuilder
        from detection.engine import DetectionEngine
        from core.risk.engine import RiskEngine
        from policy.engine import PolicyEngine

        pipeline = SecurityPipeline(
            normalizer=DefaultEventNormalizer(),
            context_builder=ContextBuilder(),
            detector=DetectionEngine(),
            risk_engine=RiskEngine(),
            policy_engine=PolicyEngine(),
            audit_logger=self.audit_logger,
        )
        return pipeline.evaluate(event)

    async def aevaluate(self, event: SecurityEvent) -> SecurityDecision:
        """Asynchronously evaluate any raw SecurityEvent without blocking the event loop."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.evaluate, event)


# Global default client
_default_client = AISecurityClient(Profile.STANDARD)


class FirewallDecorator:
    """Decorator factory for wrapping functions with in-process security firewalls."""

    def __init__(self, client: AISecurityClient | None = None) -> None:
        self._client = client or _default_client

    def protect(
        self,
        profile: Profile | str | None = None,
        *,
        target_arg: str | None = None,
        tool_name: str | None = None,
        raise_on_deny: bool = True,
    ) -> Callable[[F], F]:
        """Decorate a function to automatically scan input or authorize tool calls."""
        client = AISecurityClient(profile) if profile else self._client

        def decorator(func: F) -> F:
            sig = inspect.signature(func)

            if inspect.iscoroutinefunction(func):
                @wraps(func)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    bound = sig.bind(*args, **kwargs)
                    bound.apply_defaults()

                    if tool_name is not None:
                        # Protect as tool call
                        client.authorize_tool(
                            tool_name=tool_name,
                            arguments=bound.arguments,
                            raise_on_deny=raise_on_deny,
                        )
                    else:
                        # Protect as prompt
                        prompt_val = _extract_prompt(bound.arguments, target_arg)
                        if prompt_val is not None:
                            client.scan_prompt(prompt_val, raise_on_deny=raise_on_deny)

                    return await func(*args, **kwargs)

                return async_wrapper  # type: ignore[return-value]
            else:
                @wraps(func)
                def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                    bound = sig.bind(*args, **kwargs)
                    bound.apply_defaults()

                    if tool_name is not None:
                        client.authorize_tool(
                            tool_name=tool_name,
                            arguments=bound.arguments,
                            raise_on_deny=raise_on_deny,
                        )
                    else:
                        prompt_val = _extract_prompt(bound.arguments, target_arg)
                        if prompt_val is not None:
                            client.scan_prompt(prompt_val, raise_on_deny=raise_on_deny)

                    return func(*args, **kwargs)

                return sync_wrapper  # type: ignore[return-value]

        return decorator


def _extract_prompt(arguments: dict[str, Any], target_arg: str | None) -> str | None:
    if target_arg and target_arg in arguments:
        val = arguments[target_arg]
        return str(val) if val is not None else None

    # Auto-detection heuristic for common prompt parameter names
    for candidate in ("prompt", "user_prompt", "query", "user_input", "text", "message"):
        if candidate in arguments and isinstance(arguments[candidate], str):
            return arguments[candidate]

    # If first positional argument is a string, use it
    for val in arguments.values():
        if isinstance(val, str):
            return val

    return None


firewall = FirewallDecorator()

__all__ = [
    "Profile",
    "AISecurityClient",
    "AISecurityException",
    "SecurityViolationException",
    "FirewallDecorator",
    "firewall",
]
