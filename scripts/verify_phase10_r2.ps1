$ErrorActionPreference = "Stop"

function ConvertFrom-SecureInput([Security.SecureString]$Value) {
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

$endpoint = Read-Host "R2 S3 endpoint (https://ACCOUNT_ID.r2.cloudflarestorage.com)"
$accessKey = Read-Host "R2 Access Key ID" -AsSecureString
$secretKey = Read-Host "R2 Secret Access Key" -AsSecureString

try {
    $env:AI_SECURITY_R2_ENDPOINT = $endpoint
    $env:AI_SECURITY_R2_BUCKET = "ai-security"
    $env:AI_SECURITY_R2_ACCESS_KEY_ID = ConvertFrom-SecureInput $accessKey
    $env:AI_SECURITY_R2_SECRET_ACCESS_KEY = ConvertFrom-SecureInput $secretKey

    python -m pytest tests/integration/test_r2_audit_replica_live.py -q
    if ($LASTEXITCODE -ne 0) {
        throw "Phase 10 R2 live verification failed with exit code $LASTEXITCODE"
    }
}
finally {
    Remove-Item Env:AI_SECURITY_R2_ENDPOINT -ErrorAction SilentlyContinue
    Remove-Item Env:AI_SECURITY_R2_BUCKET -ErrorAction SilentlyContinue
    Remove-Item Env:AI_SECURITY_R2_ACCESS_KEY_ID -ErrorAction SilentlyContinue
    Remove-Item Env:AI_SECURITY_R2_SECRET_ACCESS_KEY -ErrorAction SilentlyContinue
}
