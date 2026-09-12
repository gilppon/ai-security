"""Lightweight ONNX Runtime hook for semantic prompt injection detection.

Gracefully falls back to pure regex detectors if onnxruntime is absent.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from detection.models import Severity
from input_security.prompt.contracts import PromptTextDetectorContract
from input_security.prompt.models import PromptFinding, PromptThreatCategory
from input_security.prompt.utils import fingerprint

logger = logging.getLogger(__name__)

try:
    import onnxruntime as ort
    HAS_ONNX = True
except ImportError:
    ort = None  # type: ignore[assignment]
    HAS_ONNX = False


class ONNXPromptInjectionDetector(PromptTextDetectorContract):
    """Optional semantic classifier hook using an ONNX runtime session."""

    def __init__(
        self,
        model_path: str | Path | None = None,
        *,
        threshold: float = 0.85,
        session: Any | None = None,
    ) -> None:
        self.threshold = threshold
        self.session = session
        self.is_ready = False

        if session is not None:
            self.is_ready = True
        elif HAS_ONNX and model_path is not None:
            model_file = Path(model_path)
            if model_file.exists():
                try:
                    self.session = ort.InferenceSession(str(model_file))
                    self.is_ready = True
                except Exception as exc:
                    logger.warning("Failed to initialize ONNX session: %s. Falling back to regex.", exc)
                    self.is_ready = False

    def detect(self, raw_prompt: str, normalized_text: str) -> tuple[PromptFinding, ...]:
        if not self.is_ready or self.session is None:
            return ()

        try:
            # Model-specific inference hook
            # If a custom session or mock session is provided:
            inputs = {"input_text": [normalized_text]}
            # Expected outputs or mock evaluation
            if hasattr(self.session, "predict_score"):
                score = float(self.session.predict_score(normalized_text))
            elif hasattr(self.session, "run"):
                outputs = self.session.run(None, inputs)
                score = float(outputs[0][0])
            else:
                score = 0.0

            if score >= self.threshold:
                return (
                    PromptFinding(
                        code="PROMPT_INJECTION_ONNX_SEMANTIC",
                        category=PromptThreatCategory.JAILBREAK,
                        severity=Severity.CRITICAL,
                        risk_score=int(score * 100),
                        detector="onnx_semantic_detector",
                        evidence_fingerprint=fingerprint(f"onnx_score_{score:.4f}"),
                        metadata={"semantic_score": score, "threshold": self.threshold},
                    ),
                )
        except Exception as exc:
            logger.debug("ONNX inference skipped or failed gracefully: %s", exc)

        return ()
