# AI Security Control Plane — Enterprise Refactoring Implementation Plan (v3.0)

## 📋 프로젝트 변경 및 결재 이력 (PMO Revision Log)

| 버전 (Ver.) | 기록 일시 (DateTime) | 작성자 (Author) | 결재 상태 (Status) | 핵심 지시 및 변경 내용 (Key Directives) |
|---|---|---|---|---|
| **v1.0** | 2026-09-09 10:00 | 코다리 부장 | 🟢 승인 완료 | Phase 0~1 Foundation & Security Core 기초 구축 (아카이브 보관) |
| **v2.0** | 2026-09-11 22:30 | 코다리 부장 | 🟢 승인 완료 | 2026 Spatial Cyber SOC 대시보드 구축 (아카이브 보관) |
| **v3.0** | 2026-09-12 19:30 | 코다리 부장 | 🟢 승인 완료 | Enterprise Refactoring (In-Process SDK, Latency/Async R2, ONNX Fallback Hook, Red-Team CI) |

---

## 1. 목표 (Goal Description)

본 리팩토링의 목표는 `ai-security` 제어 평면의 고유한 도메인 보안 엔진(MCP Gateway, Plan Validator, Confused Deputy, Resource Sandbox, Policy Signing, WORM Audit)을 **100% 온전히 보존**하면서, 실전 AI 에이전트 서빙 환경에서 발생하는 3대 운영 병목을 해소하는 것입니다:

1. **운영 오버헤드 해소**: Docker/FastAPI HTTP 왕복 오버헤드를 없애고 파이썬 에이전트 코드 내에서 직접 호출 가능한 **Embedded In-Process SDK 모드**(`sdk.py`, `Profile.LITE/STANDARD/STRICT`) 지원.
2. **지연시간 최적화 (Latency Bottleneck)**: 동기식 R2 감사를 **로컬 WAL 스풀 기반 비동기 디스패처**로 전환하여 무손실·초저지연 반환 달성, 정책 서명/매니페스트 **LRU 암호화 캐시**, **Fast-Fail 듀얼 패스** 적용.
3. **탐지 룰 고도화**: `onnxruntime` 기반의 **경량 시맨틱 인젝션 탐지 Hook**(미설치 시 무중단 Regex Fallback) 및 CI 레드팀 회귀 파이프라인 정착.

---

## 2. 사용자 검토 필요 항목 (User Review Required)

> [!IMPORTANT]
> **직언 1: Fast-Path의 원칙은 'Early Allow'가 아닌 'Fast-Fail (Early Drop)'입니다.**
> 정규식은 악성 페이로드를 즉각 거절(Deny)하는 데는 탁월하지만, 정규식을 통과했다고 해서 "100% 안전(Decisively Safe)"하다고 조기 승인(Allow)할 수는 없습니다(유니코드 호모글리프, 간접 인젝션 등 우회 위험). 따라서 Fast Path는 **"명백한 악성 패턴은 0.5ms 만에 즉시 차단(Early Reject)"**하고, 의심도가 낮은 요청은 초경량 파이프라인을 통과시키는 **"Fast-Reject, Progressive-Inspect"** 방식을 적용합니다.

> [!IMPORTANT]
> **직언 2: 비동기 R2 텔레메트리의 감사 유실 방지 (Local Spool WAL 장착)**
> 단순 인메모리 큐만 사용하면 에이전트 프로세스 비정상 종료(OOM/SIGKILL) 시 R2로 전송되지 못한 감사 로그가 증발합니다. 이에 따라 로컬 `.artifacts/audit_spool/`에 Append-only 디스크 저널(0.1ms 미만)을 1차 기록한 후 백그라운드 워커가 R2로 전송하며, `atexit` Graceful Shutdown을 통해 큐 잔류 데이터를 안전하게 Flush하도록 설계합니다.

> [!NOTE]
> **기존 REST API 호환성 보장**:
> 기존 `api/router.py` 및 엔드포인트는 단 1바이트의 하위 호환성 깨짐 없이 100% 유지되며, 내부적으로 `AISecurityClient`의 비즈니스 로직을 공유하여 코드 중복을 제거합니다.

---

## 3. 미해결 질문 (Open Questions)

없음 (코다리 부장의 아키텍처 실사 및 직언 3대 보완책 반영 완료).

---

## 4. 변경 대상 파일 및 컴포넌트 (Proposed Changes)

### [Component 1] Embedded In-Process SDK (`sdk.py`)

#### [NEW] [sdk.py](file:///e:/ai-security/sdk.py)
- `class Profile(enum.StrEnum)`:
  - `LITE`: 무상태 인메모리 프롬프트 검사 및 정규식 규칙 (Zero 외부 I/O, 초경량)
  - `STANDARD`: Lite + MCP 게이트웨이 + 파일시스템/네트워크 리소스 방화벽 (인프로세스 가상 샌드박스)
  - `STRICT`: 전체 엔터프라이즈 모드 (프로세스 격리 강제, 심층 플랜 검증, 실시간 감사 복제)
- `class AISecurityClient`:
  - `__init__(self, profile: Profile = Profile.STANDARD, policy_bundle_path: Path | None = None, ...)`
  - 동기 평가: `evaluate(self, event: SecurityEvent) -> SecurityDecision`
  - 비동기 평가: `aevaluate(self, event: SecurityEvent) -> SecurityDecision`
  - 고수준 헬퍼: `scan_prompt()`, `authorize_tool()`, `scan_output()`, `protect_resource()`
- `@firewall.protect(profile=Profile.STANDARD)` 데코레이터:
  - 함수 호출 전 인자(프롬프트, 도구 인자) 자동 가로채기 및 정책 인가
  - 위반 시 `SecurityViolationException` 발생 또는 설정된 차단 전략 수행

#### [MODIFY] [api/prompt.py](file:///e:/ai-security/api/prompt.py)
- `AISecurityClient` 코어를 재사용하여 REST 엔드포인트의 중복 로직 통합.

---

### [Component 2] 지연시간 최적화 및 비동기 감사 디스패처

#### [MODIFY] [telemetry/r2.py](file:///e:/ai-security/telemetry/r2.py)
- `AsyncR2AuditDispatcher` 추가:
  - `asyncio.Queue` 및 백그라운드 스레드 워커 지원.
  - 비동기 작업 처리 중 프로세스 다운 시 유실 방지를 위한 로컬 Spool Journaling (`.artifacts/audit_spool/` 디스크 버퍼).
  - Graceful Shutdown Hook (`atexit.register`, 비동기 루프 종료 리스너) 장착.
  - `record_async(record)` 호출 시 즉시 리턴(<0.2ms).

#### [MODIFY] [policy/signing.py](file:///e:/ai-security/policy/signing.py)
- `PolicySignatureVerifier.verify()`에 LRU 캐시(`functools.lru_cache` 또는 bounded dict) 적용:
  - 캐시 키: `(signer_id, bundle.metadata.content_fingerprint, signature)`
  - 번들 내용과 서명이 동일할 경우 반복적인 바이트 직렬화 및 HMAC-SHA256 연산 100% 스킵.

#### [MODIFY] [agent_security/mcp/manifest.py](file:///e:/ai-security/agent_security/mcp/manifest.py)
- `MCPManifestRegistry`:
  - 매니페스트 해시 기반 스코프 및 툴 목록 파싱 결과 인메모리 캐싱.

#### [MODIFY] [core/pipeline.py](file:///e:/ai-security/core/pipeline.py)
- Dual-Path (Fast/Slow) 파이프라인 도입:
  - **Fast-Fail Path**: Pre-compiled regex 및 명백한 서명 위조/블랙리스트 매칭 시 즉시 `DENY` 결정 반환(<0.5ms).
  - **Normal / Slow Path**: 위험도가 임계값 미만인 경우 심층 플랜 분석(`plan_validator`)을 건너뛰고 정상 통과, 위험 징후 포착 시에만 심층 상관분석 트리거.
  - 비동기 감사 로거(`AsyncAuditLoggerContract`) 지원 연동.

---

### [Component 3] 하이브리드 탐지 (ONNX Hook) 및 CI 레드팀 회귀

#### [MODIFY] [input_security/prompt/firewall.py](file:///e:/ai-security/input_security/prompt/firewall.py)
- ONNX Runtime 선택적 바인딩(Optional Dependency):
  - `try: import onnxruntime as ort ... except ImportError:` 구조로 런타임 하드 디펜던시 배제.
  - 모델 파일 경로(`model_path`)가 지정되고 런타임이 존재할 경우 ONNX 기반 임베딩/시맨틱 분류 훅 실행.
  - 모델이 없거나 예외 발생 시 기존 정규식 및 휴리스틱 룰(`rules.py`)로 100% 무중단 Graceful Fallback.

#### [NEW] [detection/redteam/regression.py](file:///e:/ai-security/detection/redteam/regression.py)
- 자동화된 적대적 공격 회귀 테스트 러너:
  - `evaluation/scenarios.py` 공격 데이터셋을 순회하며 Zero-day 및 Jailbreak 탐지율 Pass/Fail 매트릭스 리포트 생성.

#### [NEW] [scripts/benchmark_sdk_vs_rest.py](file:///e:/ai-security/scripts/benchmark_sdk_vs_rest.py)
- REST API (FastAPI TestClient/HTTP) vs In-Process SDK 레이턴시 P50/P95/P99 비교 벤치마크 스크립트.

---

### [Component 4] 단위 및 통합 테스트 슈트

#### [NEW] [tests/unit/test_sdk.py](file:///e:/ai-security/tests/unit/test_sdk.py)
- `Profile.LITE`, `Profile.STANDARD`, `Profile.STRICT` 초기화 및 격리 검증.
- `AISecurityClient` 동기/비동기 API 및 `@firewall.protect` 데코레이터 테스트.

#### [NEW] [tests/unit/test_async_telemetry.py](file:///e:/ai-security/tests/unit/test_async_telemetry.py)
- 비동기 R2 디스패처 큐 동작 및 로컬 스풀 저널링, 플러시 동작 검증.

#### [NEW] [tests/unit/test_policy_and_manifest_cache.py](file:///e:/ai-security/tests/unit/test_policy_and_manifest_cache.py)
- `PolicySignatureVerifier` 캐시 히트/미스 및 서명 불일치 시 무효화 검증.

#### [NEW] [tests/unit/test_onnx_hook.py](file:///e:/ai-security/tests/unit/test_onnx_hook.py)
- ONNX 런타임 미설치 시 Fallback 동작 및 모델 감지 시 추론 후킹 검증.

---

## 5. 검증 계획 (Verification Plan)

### Automated Tests (자동화 테스트)
- **신규 기능 단위 테스트**:
  ```powershell
  python -m pytest tests/unit/test_sdk.py tests/unit/test_async_telemetry.py tests/unit/test_policy_and_manifest_cache.py tests/unit/test_onnx_hook.py -v
  ```
- **기존 보안 회귀 스위트 전체 실행 (0 Regression 보증)**:
  ```powershell
  python -m pytest -m "not native_isolation" -q
  ```
- **적대적 공격 회귀 스위트**:
  ```powershell
  python -m pytest detection/redteam/ -q
  ```

### Manual & Performance Verification (성능 실사 검증)
- **In-Process SDK vs REST 지연시간 벤치마크**:
  ```powershell
  python scripts/benchmark_sdk_vs_rest.py
  ```
  - 기대치: REST API 대비 In-Process SDK 지연시간 80% 이상 단축 (HTTP 직렬화/역직렬화 및 소켓 I/O 오버헤드 제거).
