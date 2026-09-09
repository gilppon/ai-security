from secret_detection.models import SecretCategory, SecretLocation


_CATEGORY_RISK = {
    SecretCategory.API_KEY: 65,
    SecretCategory.GIT_TOKEN: 80,
    SecretCategory.CLOUD_ACCESS_KEY: 80,
    SecretCategory.JWT: 65,
    SecretCategory.PRIVATE_KEY: 95,
    SecretCategory.DATABASE_CREDENTIAL: 85,
    SecretCategory.GENERIC_CREDENTIAL: 55,
}

_LOCATION_FLOOR = {
    SecretLocation.README: 5,
    SecretLocation.TEST_FIXTURE: 10,
    SecretLocation.SOURCE_CODE: 50,
    SecretLocation.ENV_FILE: 80,
    SecretLocation.PRODUCTION_OUTPUT: 100,
    SecretLocation.UNKNOWN: 50,
}


def secret_risk(category: SecretCategory, entropy: float, location: SecretLocation) -> int:
    score = max(_CATEGORY_RISK[category], _LOCATION_FLOOR[location])
    if entropy >= 4.5:
        score += 10
    elif entropy >= 3.5:
        score += 5
    return min(100, score)
