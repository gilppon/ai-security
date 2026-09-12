from unittest.mock import MagicMock

from core.decisions.actions import DecisionAction
from input_security.prompt.firewall import PromptFirewall
from input_security.prompt.models import PromptScanRequest
from input_security.prompt.onnx import ONNXPromptInjectionDetector


def test_onnx_detector_graceful_fallback_when_unready():
    # When no ONNX session or valid model path is provided, it falls back gracefully
    detector = ONNXPromptInjectionDetector(model_path="non_existent_model.onnx")
    assert detector.is_ready is False
    assert detector.detect("some prompt", "some prompt") == ()


def test_onnx_detector_semantic_detection_hook():
    # Mock session with a predict_score method returning high threat score
    mock_session = MagicMock()
    mock_session.predict_score.return_value = 0.95

    detector = ONNXPromptInjectionDetector(session=mock_session, threshold=0.85)
    assert detector.is_ready is True

    findings = detector.detect("adversarial prompt", "adversarial prompt")
    assert len(findings) == 1
    assert findings[0].code == "PROMPT_INJECTION_ONNX_SEMANTIC"
    assert findings[0].risk_score == 95


def test_prompt_firewall_integration_with_onnx():
    mock_session = MagicMock()
    mock_session.predict_score.return_value = 0.92

    onnx_detector = ONNXPromptInjectionDetector(session=mock_session, threshold=0.80)
    firewall = PromptFirewall(onnx_detector=onnx_detector)

    # A prompt that might pass simple regex, but triggers the ONNX detector
    req = PromptScanRequest(prompt="A subtly paraphrased adversarial jailbreak injection")
    result = firewall.scan(req)

    assert result.decision.decision == DecisionAction.DENY
    assert any(f.code == "PROMPT_INJECTION_ONNX_SEMANTIC" for f in result.findings)
