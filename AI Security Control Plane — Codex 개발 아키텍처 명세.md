# AI Security Control Plane

## 0. 프로젝트 목표

이 프로젝트는 단순한 Prompt Injection 차단기가 아니다.

목표는 AI 시스템의 전체 행동 흐름을 통제하는 **AI Security Control Plane**을 만드는 것이다.

보호 대상:

- 사용자 Prompt
- System Prompt
- RAG
- 외부 문서
- 웹 콘텐츠
- AI Agent
- MCP Server
- Tool Call
- Filesystem
- Network
- Process
- API
- Database
- Credentials
- AI Output

핵심 원칙:

```text
AI의 판단은 보안 결정이 아니다.

LLM은 보안 경계가 아니다.

모든 중요한 보안 결정은
Deterministic Security Engine이 수행한다.
```

---

# 1. 핵심 설계 원칙

## 1.1 Default Deny

허용 여부가 불명확한 행동은 기본적으로 차단한다.

```text
UNKNOWN → DENY
```

---

## 1.2 Least Privilege

Agent, Tool, MCP Server는 필요한 최소 권한만 가진다.

예:

```text
read_file
→ /workspace/** 만 허용

network
→ public HTTPS만 허용

shell
→ 승인된 명령만 허용
```

---

## 1.3 LLM Output Is Untrusted

AI가 만든 다음 데이터는 절대 바로 실행하지 않는다.

```text
Tool name
Tool arguments
File path
URL
SQL
Shell command
API parameters
MCP call
```

반드시 Security Layer를 통과한다.

---

## 1.4 External Content Is Data

외부에서 들어온:

```text
PDF
DOCX
Web
Email
Slack
Notion
GitHub
RAG document
Tool result
```

는 모두 신뢰하지 않는다.

---

## 1.5 Event Driven Architecture

AI와 시스템의 모든 중요한 행동을 Security Event로 변환한다.

```text
Prompt
RAG
Tool
MCP
File
Network
Process
Output
```

전부 동일한 Security Event Pipeline으로 처리한다.

---

# 2. 전체 시스템 아키텍처

```text
USER / APP / IDE / API
          │
          ▼
┌─────────────────────────────┐
│ INPUT SECURITY              │
│                             │
│ Prompt Injection            │
│ Jailbreak                   │
│ Encoding Abuse              │
│ Obfuscation                 │
│ Intent Risk                 │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ CONTENT SECURITY            │
│                             │
│ RAG Poison                  │
│ Hidden Instruction          │
│ External Content Injection  │
│ Unicode / HTML Tricks       │
│ Source Trust                │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ SECURITY CONTEXT ENGINE     │
│                             │
│ User Trust                  │
│ Agent Trust                 │
│ Session Risk                │
│ Resource Sensitivity        │
│ Previous Events             │
└──────────────┬──────────────┘
               │
               ▼
           Planner LLM
               │
               ▼
          Proposed Action
               │
               ▼
┌─────────────────────────────┐
│ POLICY ENGINE               │
│                             │
│ Rule Evaluation             │
│ Permission                  │
│ Risk Policy                 │
│ Approval Policy             │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ AGENT / MCP FIREWALL        │
│                             │
│ Tool Validation             │
│ Argument Validation         │
│ MCP Validation              │
│ Tool Chaining               │
│ Capability Escalation       │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ RESOURCE FIREWALL           │
│                             │
│ Filesystem                  │
│ Network                     │
│ Process                     │
│ Database                    │
│ API                         │
│ Credentials                 │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ SAFE EXECUTOR               │
│                             │
│ Process Isolation           │
│ Timeout                     │
│ CPU / Memory Limits         │
│ Workspace Restriction       │
│ Network Restriction         │
└──────────────┬──────────────┘
               │
               ▼
          Actual System
               │
               ▼
┌─────────────────────────────┐
│ RUNTIME SENSOR              │
│                             │
│ Tool Event                  │
│ Process Event               │
│ File Event                  │
│ Network Event               │
│ Resource Event              │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ DETECTION ENGINE            │
│                             │
│ AISec Rules                 │
│ Risk Engine                 │
│ Correlation                 │
│ Anomaly Detection           │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ OUTPUT SECURITY             │
│                             │
│ Secret                      │
│ Credential                  │
│ PII                         │
│ Internal Data               │
│ Dangerous URL               │
└──────────────┬──────────────┘
               │
               ▼
              USER
```

---

# 3. 프로젝트 디렉터리

```text
ai-security/
│
├── AGENTS.md
├── README.md
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml
├── .env.example
│
├── app/
│   ├── main.py
│   ├── bootstrap.py
│   ├── config.py
│   └── dependencies.py
│
├── core/
│   ├── events/
│   │   ├── models.py
│   │   ├── types.py
│   │   ├── factory.py
│   │   └── bus.py
│   │
│   ├── decisions/
│   │   ├── models.py
│   │   ├── reasons.py
│   │   └── actions.py
│   │
│   ├── context/
│   │   ├── models.py
│   │   ├── builder.py
│   │   └── trust.py
│   │
│   └── risk/
│       ├── engine.py
│       ├── scoring.py
│       ├── weights.py
│       └── models.py
│
├── input_security/
│   ├── prompt/
│   │   ├── firewall.py
│   │   ├── rules.py
│   │   ├── normalizer.py
│   │   ├── encoding.py
│   │   ├── obfuscation.py
│   │   └── classifier.py
│   │
│   └── jailbreak/
│       ├── detector.py
│       └── patterns.py
│
├── content_security/
│   ├── rag/
│   │   ├── firewall.py
│   │   ├── poison_detector.py
│   │   └── context_isolation.py
│   │
│   ├── document/
│   │   ├── scanner.py
│   │   ├── html.py
│   │   ├── unicode.py
│   │   ├── hidden_text.py
│   │   └── sanitizer.py
│   │
│   └── source_trust/
│       ├── engine.py
│       └── models.py
│
├── policy/
│   ├── engine.py
│   ├── evaluator.py
│   ├── parser.py
│   ├── models.py
│   ├── permissions.py
│   ├── approval.py
│   │
│   └── policies/
│       ├── default.yaml
│       ├── filesystem.yaml
│       ├── network.yaml
│       ├── tools.yaml
│       └── mcp.yaml
│
├── agent_security/
│   ├── tools/
│   │   ├── firewall.py
│   │   ├── registry.py
│   │   ├── validator.py
│   │   └── schemas.py
│   │
│   ├── mcp/
│   │   ├── gateway.py
│   │   ├── manifest.py
│   │   ├── permissions.py
│   │   ├── description_scanner.py
│   │   └── trust.py
│   │
│   ├── planner/
│   │   ├── guard.py
│   │   └── plan_validator.py
│   │
│   └── chaining/
│       ├── tracker.py
│       └── confused_deputy.py
│
├── resource_security/
│   ├── filesystem/
│   │   ├── firewall.py
│   │   ├── paths.py
│   │   ├── sensitive.py
│   │   └── policy.py
│   │
│   ├── network/
│   │   ├── firewall.py
│   │   ├── dns.py
│   │   ├── ip_policy.py
│   │   └── redirects.py
│   │
│   ├── process/
│   │   ├── firewall.py
│   │   ├── commands.py
│   │   └── allowlist.py
│   │
│   ├── database/
│   │   ├── firewall.py
│   │   └── query_policy.py
│   │
│   └── api/
│       ├── firewall.py
│       └── endpoint_policy.py
│
├── execution/
│   ├── sandbox/
│   │   ├── executor.py
│   │   ├── limits.py
│   │   └── workspace.py
│   │
│   ├── approval/
│   │   ├── service.py
│   │   └── models.py
│   │
│   └── result/
│       ├── sanitizer.py
│       └── normalizer.py
│
├── secrets/
│   ├── detector.py
│   ├── classifier.py
│   ├── entropy.py
│   ├── context.py
│   ├── risk.py
│   │
│   └── patterns/
│       ├── cloud.yaml
│       ├── git.yaml
│       ├── private_keys.yaml
│       └── generic.yaml
│
├── artifact_security/
│   ├── scanner.py
│   ├── classifier.py
│   ├── engine.py
│   │
│   └── rules/
│       ├── scripts.yaml
│       ├── binaries.yaml
│       ├── documents.yaml
│       └── ai_generated.yaml
│
├── detection/
│   ├── engine.py
│   ├── matcher.py
│   ├── correlation.py
│   ├── loader.py
│   │
│   └── rules/
│       ├── prompt/
│       ├── agent/
│       ├── mcp/
│       ├── filesystem/
│       ├── network/
│       ├── credential/
│       └── runtime/
│
├── runtime/
│   ├── collector/
│   │   ├── agent.py
│   │   ├── process.py
│   │   ├── file.py
│   │   └── network.py
│   │
│   ├── behavior/
│   │   ├── baseline.py
│   │   ├── anomaly.py
│   │   └── profiles.py
│   │
│   └── sessions/
│       ├── manager.py
│       └── models.py
│
├── output_security/
│   ├── guard.py
│   ├── secrets.py
│   ├── pii.py
│   ├── urls.py
│   ├── internal_data.py
│   └── redactor.py
│
├── telemetry/
│   ├── logger.py
│   ├── audit.py
│   ├── metrics.py
│   └── storage.py
│
├── intelligence/
│   ├── models.py
│   ├── graph.py
│   ├── techniques.py
│   └── mappings.py
│
├── redteam/
│   ├── corpus/
│   │   ├── prompt_injection/
│   │   ├── jailbreak/
│   │   ├── rag/
│   │   ├── mcp/
│   │   ├── tool_abuse/
│   │   └── secrets/
│   │
│   ├── probes/
│   │   ├── models.py
│   │   ├── runner.py
│   │   └── evaluator.py
│   │
│   └── scenarios/
│       └── built_in/
│
├── api/
│   ├── router.py
│   ├── prompt.py
│   ├── content.py
│   ├── tool.py
│   ├── mcp.py
│   ├── output.py
│   ├── runtime.py
│   ├── events.py
│   └── health.py
│
├── cli/
│   ├── main.py
│   └── commands/
│
├── dashboard/
│   └── README.md
│
├── configs/
│   ├── security.yaml
│   ├── risk.yaml
│   └── logging.yaml
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── security/
│   └── regression/
│
└── docs/
    ├── architecture.md
    ├── threat-model.md
    ├── security-model.md
    ├── rule-language.md
    └── roadmap.md
```

---

# 4. 가장 중요한 공통 데이터 구조

## SecurityEvent

모든 보안 모듈은 직접 서로 강하게 연결하지 말고 Event 중심으로 통신한다.

```python
class SecurityEvent(BaseModel):
    event_id: str
    timestamp: datetime

    event_type: str

    session_id: str | None
    user_id: str | None
    agent_id: str | None

    source: str
    target: str | None

    action: str | None

    resource_type: str | None
    resource: str | None

    data: dict

    trust_level: str

    risk_score: int = 0
```

예:

```json
{
  "event_id": "evt_001",

  "event_type": "agent.tool.call",

  "session_id": "session_abc",

  "user_id": "user_1",

  "agent_id": "coding_agent",

  "source": "agent",

  "target": "filesystem",

  "action": "read",

  "resource_type": "file",

  "resource": "/home/user/.ssh/id_rsa",

  "trust_level": "untrusted",

  "risk_score": 0
}
```

---

# 5. SecurityDecision

모든 Security Engine은 같은 Decision 형식을 반환한다.

```python
class SecurityDecision(BaseModel):

    decision: Literal[
        "ALLOW",
        "LOG",
        "SANITIZE",
        "APPROVAL_REQUIRED",
        "DENY",
        "QUARANTINE",
        "TERMINATE"
    ]

    risk_score: int

    reason_codes: list[str]

    matched_rules: list[str]

    metadata: dict = {}
```

예:

```json
{
  "decision": "DENY",

  "risk_score": 100,

  "reason_codes": [
    "PATH_OUTSIDE_WORKSPACE",
    "CREDENTIAL_ACCESS"
  ],

  "matched_rules": [
    "ASEC-FS-001"
  ]
}
```

---

# 6. Risk Engine

Risk Score 범위:

```text
0 ~ 100
```

기본 정책:

```text
0–20
ALLOW

21–40
ALLOW + LOG

41–60
SANITIZE / MONITOR

61–79
APPROVAL_REQUIRED

80–100
DENY / QUARANTINE
```

Risk는 단일 패턴으로 계산하지 않는다.

```text
Prompt Risk
+
User Trust
+
Agent Trust
+
Resource Sensitivity
+
Tool Capability
+
Historical Behavior
+
Session Behavior
+
Policy Violation
```

예:

```text
Prompt Risk             20
Sensitive File          35
Untrusted Agent         15
Previous Violations     20
Tool Risk               10
---------------------------
Total                   100
```

---

# 7. AISec Rule Language

우리 프로젝트의 핵심 IP 중 하나다.

예:

```yaml
id: ASEC-FS-001

title: Agent Credential File Access

category: filesystem

severity: critical

when:
  event_type: agent.file.read

match:
  resource:
    - "**/.ssh/**"
    - "**/.aws/**"
    - "**/.env"
    - "**/*.pem"
    - "**/*.key"

unless:
  approved: true

risk:
  score: 100

actions:
  - deny
  - alert
  - audit
```

MCP:

```yaml
id: ASEC-MCP-001

title: MCP Capability Escalation

category: mcp

severity: critical

when:
  event_type: mcp.tool.call

condition:
  requested_scope > declared_scope

risk:
  score: 95

actions:
  - deny
  - quarantine
  - audit
```

Agent loop:

```yaml
id: ASEC-AGENT-LOOP-001

title: Excessive Agent Loop

category: agent_behavior

severity: high

condition:
  session.tool_calls > 50

risk:
  score: 80

actions:
  - pause
  - approval_required
```

---

# 8. Prompt Firewall

처리 순서:

```text
Raw Prompt
    ↓
Normalization
    ↓
Unicode Analysis
    ↓
Encoding Detection
    ↓
Rule Detection
    ↓
Semantic Risk
    ↓
Risk Engine
```

초기 탐지 범주:

```text
SYSTEM_OVERRIDE
SYSTEM_PROMPT_EXTRACTION
ROLE_OVERRIDE
JAILBREAK
ENCODED_INSTRUCTION
OBFUSCATED_INSTRUCTION
TOOL_MANIPULATION
DATA_EXFILTRATION
```

---

# 9. RAG / Content Firewall

처리:

```text
Document
 ↓
Normalize
 ↓
Hidden Content Scan
 ↓
Unicode Scan
 ↓
Instruction Scan
 ↓
Source Trust
 ↓
Risk
 ↓
Clean / Isolate / Reject
```

검사:

```text
HTML comment
hidden CSS text
zero-width characters
system tags
instruction tags
prompt-like imperative language
encoded content
oversized content
suspicious links
```

외부 문서는 절대로 바로 LLM Context에 넣지 않는다.

---

# 10. Agent Tool Firewall

요청 예:

```json
{
  "tool": "read_file",

  "arguments": {
    "path": "/workspace/app.py"
  }
}
```

흐름:

```text
Tool Exists?
    ↓
Agent Allowed?
    ↓
Argument Schema Valid?
    ↓
Policy Allowed?
    ↓
Resource Allowed?
    ↓
Risk Acceptable?
    ↓
Approval Required?
    ↓
Execute
```

---

# 11. MCP Security Gateway

MCP Server는 기본적으로 신뢰하지 않는다.

검사:

```text
Server identity
Version
Declared tools
Declared scope
Tool descriptions
Tool arguments
Requested capability
Execution result
Tool chaining
```

관리해야 하는 위협:

```text
Tool Shadowing
Description Injection
Scope Mismatch
Capability Escalation
Unexpected Tool
Confused Deputy
Credential Access
Filesystem Escape
Network Escape
```

---

# 12. Filesystem Firewall

기본 허용:

```text
/workspace/**
/tmp/ai-security/**
```

기본 민감 영역:

```text
~/.ssh/**
~/.aws/**
~/.gnupg/**
~/.config/**
.env
.env.*
*.pem
*.key
credentials.*
```

항상:

```python
Path(...).resolve()
```

후 검사한다.

Path traversal:

```text
../../.ssh/id_rsa
```

도 최종 경로 기준으로 판정한다.

---

# 13. Network Firewall

기본 차단:

```text
127.0.0.0/8
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
169.254.0.0/16

::1
fc00::/7
fe80::/10
```

흐름:

```text
URL
 ↓
Scheme
 ↓
Hostname
 ↓
DNS Resolution
 ↓
Resolved IP
 ↓
Policy
 ↓
Redirect Target
 ↓
Request
```

특히:

```text
169.254.169.254
```

같은 metadata endpoint는 기본 DENY.

---

# 14. Process / Command Firewall

절대 기본 사용 금지:

```python
shell=True
```

실행:

```python
subprocess.run(
    ["git", "status"],
    shell=False
)
```

Command classification:

```text
SAFE
RESTRICTED
DANGEROUS
```

예:

```text
git status
pytest
python script.py

→ SAFE
```

```text
rm
powershell
cmd
bash
sh
curl
wget
ssh
scp
nc

→ RESTRICTED / DENY
```

---

# 15. Secret Detection Engine

구성:

```text
Pattern
+
Entropy
+
Context
+
File Sensitivity
+
Location
+
Exposure
```

지원 범주:

```text
API Keys
Git tokens
Cloud credentials
JWT
Private keys
Database passwords
Generic credentials
```

단순 발견만 하지 말고 Risk를 계산한다.

```text
README sample
risk 5

test fixture
risk 10

source code
risk 50

.env
risk 80

production credential
risk 100
```

---

# 16. Runtime Behavior Engine

모든 Agent 행동을 기록한다.

```text
Prompt
Tool Selection
Tool Call
File Access
Network Request
Process Start
MCP Call
Output
```

세션 단위로:

```text
Normal Behavior
vs
Current Behavior
```

비교.

초기 Rule 기반.

추후:

```text
Statistical Anomaly
Behavioral Baseline
Sequence Detection
```

추가.

---

# 17. API 설계

## Prompt

```text
POST /v1/security/prompt/scan
```

## Document

```text
POST /v1/security/content/scan
```

## Tool

```text
POST /v1/security/tool/authorize
```

## MCP

```text
POST /v1/security/mcp/authorize
```

## Output

```text
POST /v1/security/output/scan
```

## Runtime Event

```text
POST /v1/security/events
```

## Session

```text
GET /v1/security/sessions/{session_id}
```

## Health

```text
GET /v1/health
```

---

# 18. 테스트 시나리오

최소 다음 테스트를 만든다.

```text
Prompt Injection
System Prompt Extraction
Role Override
Unicode Injection
Base64 Injection
Indirect Prompt Injection
RAG Poison
Hidden HTML Instruction

Path Traversal
SSH Key Access
AWS Credential Access
.env Access

localhost SSRF
Private IP SSRF
Metadata Endpoint
DNS Rebinding Pattern

Unsafe Shell Command
Command Injection

Unauthorized MCP Tool
MCP Scope Escalation
Tool Description Injection

Secret Leakage
Private Key Leakage
JWT Leakage

Agent Infinite Loop
Tool Call Flood
Repeated Denied Access
```

---

# 19. 개발 단계

## PHASE 0 — Foundation

먼저:

```text
Project skeleton
Config
Logging
Event model
Decision model
Risk model
Tests
```

완성.

---

## PHASE 1 — Security Core

구현:

```text
SecurityEvent
SecurityDecision
RiskEngine
AISec Rule Engine
Audit Logger
```

이 단계가 가장 중요하다.

---

## PHASE 2 — Input Protection

```text
Prompt Firewall
Jailbreak Detector
Encoding Detector
Normalization
```

---

## PHASE 3 — Content Protection

```text
RAG Firewall
Document Scanner
Hidden Content Scanner
Source Trust
```

---

## PHASE 4 — Agent Protection

```text
Tool Registry
Tool Firewall
Argument Validator
MCP Gateway
Plan Validator
```

---

## PHASE 5 — Resource Protection

```text
Filesystem Firewall
Network Firewall
Process Firewall
API Firewall
```

---

## PHASE 6 — Secret / Output Security

```text
Secret Engine
PII
Output Guard
Redaction
```

---

## PHASE 7 — Runtime Protection

```text
Session Monitoring
Behavior Engine
Correlation
Anomaly Detection
```

---

## PHASE 8 — Red Team Regression

우리 테스트 시스템:

```text
Probe Template
Scenario Runner
Expected Decision
Regression Score
```

예:

```text
Prompt Injection Block Rate
RAG Poison Block Rate
MCP Escalation Block Rate
Secret Leak Rate
Tool Abuse Block Rate
```

---

# 20. MVP 완료 기준

V1 완료 조건:

```text
✓ Prompt Firewall
✓ RAG Firewall
✓ Risk Engine
✓ AISec Rule Engine
✓ Policy Engine
✓ Tool Firewall
✓ MCP Gateway
✓ Filesystem Firewall
✓ Network Firewall
✓ Secret Detector
✓ Output Guard
✓ Audit Event
✓ FastAPI
✓ CLI
✓ Tests
```

그리고:

```text
pytest
```

전체 PASS.

---

# 21. Codex가 절대로 하면 안 되는 것

```text
외부 보안 오픈소스 코드 복사 금지

Falco 코드 복사 금지
Sigma Rule Corpus 복사 금지
Gitleaks 코드 복사 금지
TruffleHog 코드 복사 금지
Checkov 코드 복사 금지
YARA-X 코드 복사 금지
Nuclei 코드 복사 금지
VibeHacking 코드 복사 금지
```

이들은 아이디어 참고만 한다.

우리 코어는 독립 구현한다.

---

# 22. AGENTS.md — Codex용 최상위 지침

프로젝트 루트에 다음 내용을 넣는다.

```text
# AI Security Project Instructions

You are building a proprietary AI Security Control Plane.

This is a defensive security product.

Do not copy source code from third-party security projects.

External projects such as Falco, Sigma, osquery, Gitleaks,
TruffleHog, Checkov, YARA-X, Nuclei and VibeHacking may only
be used as architectural inspiration.

The proprietary architecture must center around:

SecurityEvent
→ Normalize
→ Context
→ Detect
→ Risk
→ Policy
→ Decision
→ Audit

Core requirements:

1. Default deny.
2. Least privilege.
3. LLM output is untrusted.
4. External content is untrusted.
5. LLM must never make final security decisions.
6. Critical security decisions must be deterministic.
7. Every decision requires structured reason codes.
8. Every important action generates a SecurityEvent.
9. Every blocked or approved action must be auditable.
10. Modules must remain independently replaceable.

Primary proprietary components:

- Unified AI Security Event Model
- AI Risk Engine
- AISec Rule Engine
- Prompt Firewall
- RAG / Content Firewall
- Policy Engine
- Agent Tool Firewall
- MCP Security Gateway
- Filesystem Firewall
- Network Firewall
- Process Firewall
- Secret Detection Engine
- Runtime Behavior Engine
- Output Guard

Technology:

Python 3.12+
FastAPI
Pydantic v2
pytest
PyYAML
structured JSON logging

Do not add major dependencies without a clear architectural reason.

Security-sensitive functions must have unit tests.

Any new tool capability must pass through the Tool Firewall.

Any new external network capability must pass through the Network Firewall.

Any filesystem capability must pass through the Filesystem Firewall.

Never directly execute LLM-generated shell strings.

Use shell=False.

Resolve filesystem paths before authorization.

Resolve network destinations before authorization.

Do not log raw credentials or secrets.

Prefer hashes, fingerprints, redacted values and metadata.

Implement incrementally.

Do not skip tests to make builds pass.
```

---

# 23. Codex 첫 번째 작업 프롬프트

AGENTS.md를 만든 다음 코덱스에 아래를 입력한다.

```text
Read AGENTS.md completely before modifying anything.

Implement Phase 0 and Phase 1 only.

Create the project skeleton exactly according to the architecture.

Implement:

1. SecurityEvent
2. SecurityDecision
3. SecurityContext
4. RiskScore
5. RiskEngine
6. AISec Rule parser
7. AISec Rule evaluator
8. structured reason codes
9. audit logger
10. FastAPI health endpoint

Create comprehensive pytest coverage.

Do not implement PromptFirewall yet.

Do not add external security frameworks.

At the end:

- run all tests
- run type checks if configured
- report created files
- report architectural decisions
- report remaining Phase 2 work
```

---

# 24. 두 번째 Codex 작업

Phase 1이 통과하면:

```text
Implement Phase 2.

Add:

PromptFirewall
PromptNormalizer
PromptRuleDetector
EncodingDetector
ObfuscationDetector
JailbreakDetector

Integrate all detections through SecurityEvent,
RiskEngine and SecurityDecision.

Do not let detectors directly decide BLOCK.

Detectors produce findings.
RiskEngine produces risk.
PolicyEngine will later produce final decisions.

Add:

POST /v1/security/prompt/scan

Tests must cover:

normal prompts
system instruction override
system prompt extraction
role override
base64-like encoded attacks
unicode zero width content
obfuscated instructions
false positive examples

Run all tests before completion.
```

---

# 25. 세 번째 Codex 작업

```text
Implement Phase 3.

Create:

RAGFirewall
DocumentScanner
HiddenContentDetector
UnicodeContentDetector
InstructionDetector
SourceTrustEngine
ContentSanitizer

External content must always carry a trust level.

No document may enter an LLM context without passing
through the Content Security layer.

Add:

POST /v1/security/content/scan

Write security tests for indirect prompt injection
and poisoned RAG documents.
```

---

# 26. 네 번째 Codex 작업

```text
Implement Phase 4 and the first part of Phase 5.

Create:

ToolRegistry
ToolFirewall
ToolArgumentValidator
MCPGateway
MCPManifest
MCPPermissionModel
FilesystemFirewall
NetworkFirewall

Tool execution must not be implemented yet.

Authorization only.

Add endpoints:

POST /v1/security/tool/authorize
POST /v1/security/mcp/authorize

Filesystem tests:

workspace read
workspace write
path traversal
SSH keys
AWS credentials
.env
private keys

Network tests:

public HTTPS
localhost
127.0.0.1
private IPv4
link-local
169.254.169.254
IPv6 loopback
IPv6 private network
```

---

# 27. 최종 제품의 핵심 경쟁력

이 프로젝트에서 가장 중요한 독자 기술은 다음 네 가지다.

```text
1. Unified AI Security Event Model

2. AISec Rule Engine

3. Context-aware AI Risk Engine

4. Agent Security Control Plane
```

Prompt Injection Detector 자체가 핵심 제품이 아니다.

궁극적인 차별화는:

```text
AI가 공격을 받아도
실제 시스템 행동으로 이어지기 직전에
Security Control Plane이 판단하고 차단하는 것
```

이다.

---

# 28. 최종 제품 흐름

```text
               AI SECURITY CONTROL PLANE

                     Prompt
                       ↓
               Prompt Firewall
                       ↓
                Security Event
                       ↓
                  Risk Engine
                       ↓
                      LLM
                       ↓
                 Proposed Tool
                       ↓
                 Tool Firewall
                       ↓
                   MCP Guard
                       ↓
                 Policy Engine
                       ↓
              Resource Firewalls
              ┌─────┼──────┐
              ↓     ↓      ↓
            File Network Process
              └─────┼──────┘
                    ↓
              Safe Executor
                    ↓
             Runtime Events
                    ↓
              Detection Engine
                    ↓
                Output Guard
                    ↓
                   User
```

이 구조를 프로젝트의 기준 아키텍처로 유지한다.

---

# 29. Architecture Completion Roadmap

공식 개발 Phase 0–8은 변경하지 않는다. 아키텍처의 배포·운영 경계를 100% 완료하기 위한 Phase 9–12 계획, 완료 정의, 검증 증거는 `docs/architecture_completion_plan.md`에서 관리한다.

| 후속 Phase | 목적 | 현재 상태 |
|---|---|---|
| Phase 9 | Hardened Execution Isolation | OS/network isolation 및 restricted token 잔여 |
| Phase 10 | Durable Audit Deployment Hardening | multi-process, ACL, remote WORM 잔여 |
| Phase 11 | CI Resilience and Evidence | fault matrix CI·benchmark history 잔여 |
| Phase 12 | Production Policy Lifecycle | production 운영 연동·rotation 검증 잔여 |

따라서 Phase 0–8 구현 완료와 아키텍처 전체 100% 완료를 구분한다. Phase 9–12의 실제 환경 검증 증거가 모두 확보되기 전에는 전체 완료로 표시하지 않는다.
