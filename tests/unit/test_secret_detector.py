import pytest

from secret_detection.detector import SecretDetector
from secret_detection.entropy import shannon_entropy
from secret_detection.models import SecretCategory, SecretLocation


@pytest.mark.parametrize(
    ("value", "category"),
    [
        ("AKIAABCDEFGHIJKLMNOP", SecretCategory.CLOUD_ACCESS_KEY),
        ("ghp_abcdefghijklmnopqrstuvwxyzABCDE", SecretCategory.GIT_TOKEN),
        ("eyJabcde.abcdefghijklmnop.abcdefgh", SecretCategory.JWT),
        ("postgresql://user:verysecret@db.example/data", SecretCategory.DATABASE_CREDENTIAL),
        ("api_key=AbCDef0123456789xyzXYZ", SecretCategory.API_KEY),
        ("password=correct-horse-battery", SecretCategory.GENERIC_CREDENTIAL),
    ],
)
def test_detects_supported_secret_categories_without_returning_values(
    value: str,
    category: SecretCategory,
) -> None:
    findings = SecretDetector().detect(value, location=SecretLocation.SOURCE_CODE)

    assert any(finding.category is category for finding in findings)
    assert value not in "".join(finding.model_dump_json() for finding in findings)


def test_private_key_and_production_output_receive_critical_risk() -> None:
    private_key = (
        "-----BEGIN PRIVATE KEY-----\n"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n"
        "-----END PRIVATE KEY-----"
    )

    finding = SecretDetector().detect(
        private_key,
        location=SecretLocation.PRODUCTION_OUTPUT,
    )[0]

    assert finding.category is SecretCategory.PRIVATE_KEY
    assert finding.risk_score == 100


def test_placeholder_credentials_are_not_reported_as_secrets() -> None:
    findings = SecretDetector().detect(
        "api_key=your_api_key_here password=changeme",
        location=SecretLocation.README,
    )

    assert findings == ()


def test_entropy_is_deterministic_and_bounded() -> None:
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaaaaaa") == 0
    assert shannon_entropy("abcdefgh") == pytest.approx(3.0)
