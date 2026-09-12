# AI Security Control Plane — 2026 Spatial Cyber SOC 대시보드 구축 계획서 (v2.0)

## 📋 프로젝트 변경 및 결재 이력 (PMO Revision Log)

| 버전 (Ver.) | 기록 일시 (DateTime) | 작성자 (Author) | 결재 상태 (Status) | 핵심 지시 및 변경 내용 (Key Directives) |
|---|---|---|---|---|
| **v1.0** | 2026-09-09 10:00 | 코다리 부장 | 🟢 승인 완료 | Phase 0~1 Foundation & Security Core 기초 구축 (아카이브 보관) |
| **v2.0** | 2026-09-11 22:30 | 코다리 부장 | 🟡 검토 대기 | 2026 Spatial Cyber SOC 대시보드 구축 (`/grill-me` 5대 요건 합의 반영) |

---

## 1. 목표 (Goal Description)

본 작업의 목표는 무결점 방어벽(Phase 0~12)이 구축된 **AI Security Control Plane**의 상태를 직관적이고 강력하게 통제·시연할 수 있는 **2026년형 Spatial Cyber-Defense 관제탑(AI SOC 대시보드)**을 구축하는 것입니다.

대표님과의 `/grill-me` 5단계 인터뷰 합의에 따라:
1. `slm-agent`의 검증된 프론트엔드 기반(Next.js 16, React 19, TailwindCSS v4)을 전리품으로 흡수하여 하이브리드(독립 개발 + 정적 서빙 마운트)로 구축합니다.
2. 2026 프론트엔드 디자인 규격(`frontend-design` 스킬)에 따라 흑요석 다크(`Obsidian Dark #04080E`)와 Glassmorphism v2, 네온 방화벽 경계선을 적용하여 AI Slop 0%의 압도적 비주얼을 제공합니다.
3. 5대 올인원 뷰(위협 레이더, 8단계 파이프라인 인스펙터, 인터랙티브 위협 시뮬레이터, WORM 해시체인 탐색기, 정책 콘솔)를 완결형으로 시공합니다.
4. FastAPI 백엔드에 SSE(`GET /v1/security/events/stream`) 및 CORS를 지원하여 실시간 라이브 스트림과 시연용 데모 피드를 동시 지원합니다.

---

## 2. 사용자 검토 필요 항목 (User Review Required)

> [!IMPORTANT]
> **패키지 설치 및 빌드 의존성**:
> `dashboard/` 디렉토리에 `npm install`을 실행하여 Next.js 16, TailwindCSS v4, Lucide, Recharts를 설치합니다. 시스템에 설치된 Node.js v24.11.1 및 npm 11.6.2 환경에서 표준 설치를 수행합니다.

> [!NOTE]
> **단일 포트 서빙(FastAPI) vs 개발 서버(Next.js)**:
> 개발 시에는 `cd dashboard && npm run dev` (포트 3000)로 핫리로딩 개발이 가능하며, 빌드 시(`npm run build`) `dashboard/out`에 생성되는 정적 파일을 FastAPI가 `/dashboard` 경로로 직접 서빙할 수 있도록 하이브리드 지원합니다.

---

## 3. 미해결 질문 (Open Questions)

없음 (`/grill-me` 5단계 심층 인터뷰를 통해 100% 합의 및 의사결정 완료).

---

## 4. 변경 대상 파일 및 컴포넌트 (Proposed Changes)

### [Component 1] FastAPI 백엔드 실시간 통신 및 CORS 확장

#### [NEW] [api/events.py](file:///e:/ai-security/api/events.py)
- `GET /v1/security/events/stream`: Server-Sent Events (SSE) 엔드포인트 구현.
- 인메모리 감사 이벤트 큐 및 신규 보안 판정 이벤트를 연결된 클라이언트에 JSON 스트림 형태로 실시간 푸시 (`event: security_event`).

#### [MODIFY] [api/router.py](file:///e:/ai-security/api/router.py)
- `events_router` 등록 (`/v1/security/events/stream`).

#### [MODIFY] [app/bootstrap.py](file:///e:/ai-security/app/bootstrap.py)
- `CORSMiddleware` 추가: `http://localhost:3000`, `http://127.0.0.1:3000`의 대시보드 오리진 허용.
- `dashboard/out` 디렉토리가 존재할 경우 `app.mount("/dashboard", StaticFiles(directory="dashboard/out", html=True))` 자동 마운트 지원.

---

### [Component 2] 대시보드 프로젝트 구조 및 디자인 시스템 (`dashboard/`)

#### [NEW] [dashboard/package.json](file:///e:/ai-security/dashboard/package.json)
- `next`: `16.2.6` (or `15.x`), `react`: `19.2.4`, `react-dom`: `19.2.4`
- `tailwindcss`: `^4`, `@tailwindcss/postcss`: `^4`
- `lucide-react`: `^1.16.0`, `framer-motion`: `^12.38.0`, `recharts`: `^3.8.1`, `clsx`, `tailwind-merge`

#### [NEW] [dashboard/tsconfig.json](file:///e:/ai-security/dashboard/tsconfig.json) & [dashboard/next.config.ts](file:///e:/ai-security/dashboard/next.config.ts)
- TypeScript 경로 매핑 (`@/* -> ./src/*`)
- Next.js 정적 내보내기(`output: 'export'`) 및 프록시 리라이트 설정.

#### [NEW] [dashboard/src/app/globals.css](file:///e:/ai-security/dashboard/src/app/globals.css)
- 2026 Tactical Cyber Obsidian 테마 토큰:
  - `--color-background: #04080E;`
  - `--color-surface: #0B131E;`
  - `--color-surface-glass: rgba(11, 19, 30, 0.75);`
  - `--color-emerald-neon: #00FF9D;` (ALLOW)
  - `--color-amber-neon: #FFB800;` (LOG/SANITIZE)
  - `--color-crimson-neon: #FF0055;` (DENY/TERMINATE)
  - `--color-cyan-radar: #00F0FF;`
- Glassmorphism v2 효과, 미세 스캔라인 오버레이, 네온 펄스 애니메이션, 커스텀 스크롤바.

#### [NEW] [dashboard/src/app/layout.tsx](file:///e:/ai-security/dashboard/src/app/layout.tsx)
- Google Fonts (Inter, Space Grotesk, JetBrains Mono) 장착.
- 메타데이터 및 반응형 뷰포트 설정.

---

### [Component 3] 대시보드 코어 로직 & UI 컴포넌트

#### [NEW] [dashboard/src/lib/types.ts](file:///e:/ai-security/dashboard/src/lib/types.ts)
- `SecurityEvent`, `SecurityDecision`, `ReasonCode`, `RiskScore`, `PipelineNode` TypeScript 인터페이스 정의.

#### [NEW] [dashboard/src/lib/api.ts](file:///e:/ai-security/dashboard/src/lib/api.ts)
- REST 클라이언트: `/v1/health`, `/v1/security/prompt/scan`, `/v1/security/content/scan`, `/v1/security/tool/authorize`, `/v1/security/output/scan`.
- SSE 리스너: `/v1/security/events/stream` 자동 재연결.
- 모의 공격 트래픽 제너레이터 (Demo Feed): 실제 트래픽 부재 시 8대 방화벽 시연 이벤트 자동 생성기.

#### [NEW] [dashboard/src/components/ui/TopNav.tsx](file:///e:/ai-security/dashboard/src/components/ui/TopNav.tsx)
- 시스템 헬스 인디케이터 (GREEN / 1ms Latency Gate), Cloudflare R2 Sync 상태, 총 차단율 카운터, 데모 트래픽 토글 버튼.

#### [NEW] [dashboard/src/components/ui/SubNav.tsx](file:///e:/ai-security/dashboard/src/components/ui/SubNav.tsx)
- 5대 뷰 전환 탭:
  1. 🛰️ **위협 레이더 (Threat Radar)**
  2. ⚡ **파이프라인 추적기 (Pipeline Inspector)**
  3. 🎯 **공격 시뮬레이터 (Threat Simulator)**
  4. ⛓️ **WORM 감사 체인 (WORM Chain Vault)**
  5. 📜 **정책 콘솔 (Policy Console)**

#### [NEW] [dashboard/src/components/views/ThreatRadarView.tsx](file:///e:/ai-security/dashboard/src/components/views/ThreatRadarView.tsx)
- 8대 방어선(Prompt, Content, Tool, MCP, Resource, Output, Runtime, Red-Team) 실시간 방어 게이지.
- 실시간 이벤트 스트림 피드 (최근 이벤트 20건 롤링).
- 리스크 스코어 분포 및 초저지연 게이트 통계.

#### [NEW] [dashboard/src/components/views/PipelineInspectorView.tsx](file:///e:/ai-security/dashboard/src/components/views/PipelineInspectorView.tsx)
- 8단계 `SecurityEvent -> Normalize -> Context -> Detect -> Risk -> Policy -> Decision -> Audit` 노드 다이어그램.
- 이벤트 선택 시 각 단계별 입력값, 적용된 룰, 가산된 리스크 스코어, 산출된 ReasonCode 정밀 분석.

#### [NEW] [dashboard/src/components/views/ThreatSimulatorView.tsx](file:///e:/ai-security/dashboard/src/components/views/ThreatSimulatorView.tsx)
- 실시간 인터랙티브 공격 주입기:
  - 공격 프리셋: "DAN 탈옥 공격", "시스템 프롬프트 유출 시도", "RAG 간접 인젝션", "비인가 Shell 실행 공격", "API Secret 유출 시도".
  - 커스텀 텍스트 입력 후 즉각 백엔드 API 호출 ➡️ 실시간 방어 결과 및 소독된 봉투(Envelope) 확인.

#### [NEW] [dashboard/src/components/views/WormVaultView.tsx](file:///e:/ai-security/dashboard/src/components/views/WormVaultView.tsx)
- Phase 10 SHA-256 감사 체인 시각화:
  - Genesis 블록부터 최근 블록까지의 해시 연결 상태.
  - Cloudflare R2 원격 WORM 복제 상태 및 무결성 검증 뱃지.

#### [NEW] [dashboard/src/components/views/PolicyConsoleView.tsx](file:///e:/ai-security/dashboard/src/components/views/PolicyConsoleView.tsx)
- 활성화된 Ed25519 서명 정책 번들 뷰어.
- 허용된 도구 목록, 파일시스템 허용 루트, 네트워크 화이트리스트 실시간 열람.

#### [NEW] [dashboard/src/app/page.tsx](file:///e:/ai-security/dashboard/src/app/page.tsx)
- 위 모든 컴포넌트를 조립한 메인 오케스트레이션 페이지.

---

## 5. 검증 계획 (Verification Plan)

### Automated Tests (자동화 테스트)
- **FastAPI SSE & CORS 검증**:
  - `tests/integration/test_dashboard_api.py` 신규 작성 및 `python -m pytest tests/integration/test_dashboard_api.py -v` 통과.
- **기존 보안 회귀 스위트 보호**:
  - `python -m pytest -m "not native_isolation"` 전체 통과 (326+ 테스트 ALL GREEN 보존).
  - `python -m evaluation` 레이턴시 게이트 1ms 통과 보존.
- **대시보드 빌드 검증**:
  - `cd dashboard && npm run build` 정상 완료 및 린트 통과.

### Manual Verification (수동 실사 검증)
1. `uvicorn app.main:app --reload`로 백엔드 기동.
2. `cd dashboard && npm run dev`로 프론트엔드 기동 (포트 3000 접속).
3. **5대 뷰 동작 점검**:
   - 위협 레이더에서 데모 트래픽 토글 시 실시간 패킷 흐름 확인.
   - 공격 시뮬레이터에서 "DAN 탈옥 공격" 주입 후 0.001초 만에 `PROMPT_INJECTION_DETECTED` 차단 확인.
   - 파이프라인 인스펙터에서 8단계 노드 스트림이 정상 분기되는지 확인.
   - WORM 체인 볼트에서 해시체인 무결성 확인.
