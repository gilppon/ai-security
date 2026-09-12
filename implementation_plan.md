# AI Security Control Plane — 2026 Spatial Cyber War-Room 하이테크 랜딩페이지 & SOC 투 트랙 구축 기획서 (v4.0)

## 📋 프로젝트 변경 및 결재 이력 (PMO Revision Log)

| 버전 (Ver.) | 기록 일시 (DateTime) | 작성자 (Author) | 결재 상태 (Status) | 핵심 지시 및 변경 내용 (Key Directives) |
|---|---|---|---|---|
| **v1.0** | 2026-09-09 10:00 | 코다리 부장 | 🟢 승인 완료 | Phase 0~1 Foundation & Security Core 기초 구축 (아카이브 보관) |
| **v2.0** | 2026-09-11 22:30 | 코다리 부장 | 🟢 승인 완료 | 2026 Spatial Cyber SOC 대시보드 구축 (아카이브 보관) |
| **v3.0** | 2026-09-12 19:30 | 코다리 부장 | 🟢 승인 완료 | Enterprise Refactoring (In-Process SDK, 0.145ms 지연시간 최적화, ONNX Hook, CI 회귀) (아카이브 보관) |
| **v4.0** | 2026-09-12 20:40 | 코다리 부장 | 🟡 검토 대기 | 코다리군단 합작: 2026 Spatial Cyber War-Room 하이테크 랜딩페이지 & SOC 투 트랙 기획 |

---

## 1. 목표 및 배경 (Goal Description)

본 기획은 우리 `ai-security` 제어 평면의 압도적인 기술 성과(**0.145ms 인프로세스 SDK**, **MCP 도구 격리 방화벽**, **WORM 해시체인 무결성 감사**)를 글로벌 B2B 고객사(CISO, AI 엔지니어, 보안 리드)와 투자자들에게 단 3초 만에 각인시키기 위한 **"2026 Spatial Cyber War-Room 하이테크 랜딩페이지"**를 구축하고, 이미 완공된 **"SOC 관제탑(`/dashboard`)"**과 유기적으로 결합하는 **투 트랙(Two-Track) 웹 아키텍처**를 완성하는 것입니다.

코다리 부장 직속 5대 전문 분과(`cto-architect`, `design-team`, `seo-expert`, `security-auditor`, `performance-analyst`)가 총출동하여, 흔한 AI Slop 템플릿을 철저히 배제하고 **독점적 기술력과 압도적 비주얼이 살아 숨 쉬는 명품 쇼룸**으로 시공합니다.

---

## 2. 코다리 정예군단 5대 분과 협업 설계 (Legion Directives)

### 🏛️ 1. CTO 아키텍트 분과 (`cto-architect`)
* **투 트랙 라우팅 분리**:
  * 메인 도메인 루트 (`/`): **초경량 하이테크 랜딩페이지 (Showroom)**
  * 관제탑 경로 (`/dashboard`): **실제 5대 뷰 실시간 사이버 SOC 대시보드 (War-Room)**
* **상호 연결 동선 (CTA Flow)**:
  * 랜딩페이지 헤더 및 히어로 섹션의 **[Launch Live SOC Console]** 원클릭 전환 버튼.
  * 대시보드 상단 내비게이션에 [Back to Showcase] 홈 복귀 링크 배치.
* **증적 기반 데이터 연동**: 500회 정밀 실사로 입증된 **"0.145ms (28.2x Speedup)"** 벤치마크 및 **"338/338 Security Tests 100% Pass"** 데이터를 전면에 배치.

### 🎨 2. UI/UX 디자인 분과 (`frontend-design`, `design-team`)
* **2026 Spatial UI 흑요석 다크 (`Obsidian Dark`) 시스템**:
  * Base Background: `#04080E` (심해의 흑요석 블랙)
  * Surface Glass: `rgba(11, 19, 30, 0.75)` + Backdrop Blur 16px
  * Tactical Neon: 에메랄드 `#00FF9D` (Safe), 앰버 `#FFB800` (Audit), 크림슨 `#FF0055` (Blocked), 시안 `#00F0FF` (Radar)
* **Hero 미니 인터랙티브 위협 방어 쇼룸 (Interactive Threat Simulator)**:
  * 첫 화면에서 방문자가 직접 버튼 클릭 ("DAN 탈옥 공격", "시스템 프롬프트 유출 시도", "비인가 쉘 주입").
  * 클릭 즉시 0.001초 만에 화면 중앙 네온 펄스 레이더가 반응하며 `[DENIED: PROMPT_INJECTION_DETECTED]` 보안 봉투와 ReasonCode를 실시간 렌더링.

### 🔍 3. 글로벌 SEO & AI 검색(GEO) 분과 (`seo-expert`)
* **2026 차세대 GEO(Generative Engine Optimization) 전략**:
  * ChatGPT, Perplexity, Claude가 "AI 에이전트 보안", "MCP 게이트웨이 방화벽" 질의 시 우리 제어 평면을 1순위로 인용하도록 시맨틱 마크업 설계.
* **Schema.org 구조화 데이터 (`SoftwareApplication`, `CybersecurityControlPlane`)**:
  * JSON-LD 메타데이터 장착 (오픈소스 라이선스, 버전, 주요 기능, 벤치마크 지표).
* **오픈그래프(OpenGraph) & 트위터 카드**: 다크 사이버네틱 무드의 프리뷰 썸네일 및 메타 태그 완비.

### 🛡️ 4. 보안 감사 분과 (`security-auditor`)
* **철저한 정보 격리**: 실제 내부 서명 키, 환경변수, R2 크리덴셜 노출 0% 보장.
* **쇼룸 샌드박스 안전성**: 랜딩페이지 내 미니 시뮬레이터는 클라이언트 단의 정규식 에뮬레이터 또는 속도 제한(Rate Limiting)이 걸린 안전한 공개 스캔 API만 타격.

### ⚡ 5. 성능 분석 분과 (`performance-analyst`)
* **LCP < 0.8초, CLS 0 달성**:
  * Next.js 정적 내보내기(`output: 'export'`)를 활용하여 전 세계 CDN 엣지에서 즉각 로딩.
  * 무거운 3D 라이브러리 대신 순수 CSS3 하드웨어 가속 트랜스폼 및 SVG 경량 벡터 렌더링.

---

## 3. 랜딩페이지 섹션 구성도 (Landing Page Wireframe)

```
[ TopNav ]  AI SECURITY CONTROL PLANE 로고  |  특징  |  아키텍처  |  벤치마크  |  [ Launch SOC Console -> ]
------------------------------------------------------------------------------------------------------
[ Hero Section ]
  - 뱃지: "⚡ 0.145ms In-Process SDK & Enterprise Control Plane"
  - 메인 헤드라인: "AI 에이전트의 모든 실행 사이클을 통제하는 무결점 방어 평면"
  - 서브 카피: "LLM의 출력을 신뢰하지 마십시오. Default Deny 원칙 기반의 8단계 보안 제어와 WORM 불변 감사."
  - 인터랙티브 쇼룸: [공격 페이로드 주입 프리셋 버튼] -> 0.001초 만에 차단 배지 & 리스크 스코어 시각화
  - 듀얼 CTA: [Live SOC Console 입장] | [GitHub Repository]

[ Live Benchmark Section ]
  - 28.2x 속도 혁신 비교 인터랙티브 차트 (REST API 4.089ms vs In-Process SDK 0.145ms)
  - P50 (0.110ms), P95 (0.352ms), P99 (0.546ms) 레이턴시 게이트 수치 증적

[ 8-Stage Security Pipeline Section ]
  - SecurityEvent -> Normalize -> Context -> Detect -> Risk -> Policy -> Decision -> Audit
  - 각 단계별 인터랙티브 카드 (호버 시 네온 발광 및 핵심 방어 룰 표시)

[ Proprietary Control Layers Section ]
  - 1. MCP Gateway & Scopes (도구 권한 통제)
  - 2. Plan Validator & Confused Deputy 방어
  - 3. Resource Security (프로세스, 파일시스템, 네트워크 SSRF 필터)
  - 4. WORM Immutable Audit & Cryptographic Policy Signing

[ Enterprise Trust & Code Snippet Section ]
  - In-Process SDK 단 3줄 임베딩 예시 코드:
    ```python
    from sdk import AISecurityClient, Profile, firewall
    @firewall.protect(profile=Profile.STANDARD)
    def my_agent(prompt: str): ...
    ```

[ Footer Section ]
  - MIT License | Security Docs | GitHub Repo | Status: ALL SYSTEMS DEFENDED (338/338 Green)
```

---

## 4. 변경 대상 파일 및 컴포넌트 (Proposed Changes)

### [Component 1] 랜딩페이지 뷰 컴포넌트 및 인터랙티브 위젯

#### [NEW] [dashboard/src/components/views/LandingPageView.tsx](file:///e:/ai-security/dashboard/src/components/views/LandingPageView.tsx)
- 상단 히어로, 인터랙티브 미니 시뮬레이터, 벤치마크 비교 섹션, 8단계 파이프라인 쇼케이스, 코드 스니펫 복사기, 푸터 완비.

#### [NEW] [dashboard/src/components/ui/HeroSimulator.tsx](file:///e:/ai-security/dashboard/src/components/ui/HeroSimulator.tsx)
- 원클릭으로 "DAN 공격", "시스템 유출", "Shell 주입"을 테스트하고 0.001초 차단 효과를 보여주는 하이테크 미니 쇼룸 위젯.

#### [NEW] [dashboard/src/components/ui/BenchmarkChart.tsx](file:///e:/ai-security/dashboard/src/components/ui/BenchmarkChart.tsx)
- In-Process SDK (0.145ms) vs REST API (4.089ms) 실사 벤치마크 시각화 네온 바 차트.

---

### [Component 2] 대시보드 라우팅 및 투 트랙 네비게이션 연동

#### [MODIFY] [dashboard/src/app/page.tsx](file:///e:/ai-security/dashboard/src/app/page.tsx)
- 뷰 모드 상태에 `'landing'` 모드 추가:
  - 기본 접속 시 하이테크 랜딩페이지(`LandingPageView`) 렌더링.
  - 상단 헤더의 [Launch SOC Console] 클릭 시 즉시 실시간 SOC 관제탑(`radar`, `inspector`, `simulator`, `worm`, `policy`)으로 0초 전환.
  - 대시보드 내 서브 네비게이션에 [Landing Showcase] 탭을 추가하여 상호 자유로운 이동 지원.

#### [MODIFY] [dashboard/src/components/ui/TopNav.tsx](file:///e:/ai-security/dashboard/src/components/ui/TopNav.tsx)
- 랜딩페이지 모드와 SOC 관제탑 모드를 토글할 수 있는 하이테크 네온 버튼 장착.

#### [MODIFY] [dashboard/src/app/layout.tsx](file:///e:/ai-security/dashboard/src/app/layout.tsx)
- 글로벌 SEO 메타 태그, OpenGraph, Twitter Cards, Schema.org JSON-LD 구조화 데이터 삽입.

---

## 5. 검증 계획 (Verification Plan)

### Automated Tests (자동화 테스트)
- **Next.js 빌드 및 린트 검증**:
  ```powershell
  cd dashboard
  npm run build
  ```
  - 정적 내보내기(`dashboard/out`)가 100% 오류 없이 완료되는지 확인.
- **백엔드 보안 스위트 0 회귀 확인**:
  ```powershell
  python -m pytest -m "not native_isolation" -q
  ```
  - 338개 보안 테스트 전원 ALL GREEN 유지 확인.

### Manual Verification (수동 실사 검증)
1. `cd dashboard && npm run dev` (포트 3000) 기동.
2. **랜딩페이지 접속 확인**:
   - 흑요석 다크 테마 및 타이포그래피(Inter, Space Grotesk) 렌더링 확인.
   - Hero 미니 시뮬레이터에서 공격 버튼 클릭 시 즉각적인 차단 네온 이펙트 점검.
   - 28.2x 벤치마크 그래프의 시각적 명료성 확인.
3. **투 트랙 전환 동선 점검**:
   - [Launch SOC Console] 버튼 클릭 시 기존 5대 뷰 관제탑으로 부드럽게 전환되는지 확인.
   - 관제탑에서 [Showcase Home] 버튼 클릭 시 랜딩페이지로 원복되는지 확인.
