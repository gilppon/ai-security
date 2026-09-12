"use client";

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';

export type Language = 'ko' | 'en' | 'ja';

interface LanguageContextProps {
  language: Language;
  setLanguage: (lang: Language) => void;
  t: (key: string) => string;
}

const LanguageContext = createContext<LanguageContextProps | undefined>(undefined);

const translations: Record<Language, Record<string, string>> = {
  ko: {
    // TopNav
    app_title: "AI SECURITY",
    app_subtitle: "CONTROL PLANE",
    gate_status: "결정론적 게이트: Phase 0–12 완결 (통과: 21/21)",
    core: "코어 상태",
    online: "정상 가동 (ONLINE)",
    offline: "오프라인 (OFFLINE)",
    latency: "레이턴시",
    latency_val: "1ms (초저지연)",
    r2_worm: "R2 감사 체인",
    synced: "동기화 완료 (SYNCED)",
    total: "총 처리",
    block_rate: "차단율",
    demo_traffic: "데이터 소스 모드",
    live: "데모 가동 중",
    off: "순수 실시간",
    badge_live: "LIVE 실제",
    badge_mock: "MOCK 목업",
    demo_mode_active: "⚠️ 시뮬레이션 목업 가동 중",
    demo_mode_desc: "현재 외부 실시간 트래픽 유휴 상태로 발생 가능한 위협 시나리오(목업)가 재생되고 있습니다. 백엔드 공격 시뮬레이터를 실행하거나 API를 호출하면 [LIVE 실제] 이벤트로 즉시 기록됩니다.",
    live_mode_active: "🟢 100% 백엔드 실시간 대기",
    live_mode_desc: "목업 재생이 중단되었습니다. 외부 AI 에이전트 및 모의 침투 시뮬레이터의 검증된 실제 백엔드 이벤트만 수신합니다.",
    switch_to_live_btn: "순수 실시간 모드로 전환",
    switch_to_demo_btn: "데모 목업 켜기",
    data_source_title: "데이터 소스 관제 상태",
    refresh: "상태 새로고침",

    // SubNav
    tab_radar: "1. 위협 레이더",
    tab_pipeline: "2. 파이프라인 인스펙터",
    tab_simulator: "3. 공격 시뮬레이터",
    tab_worm: "4. WORM 체인 볼트",
    tab_policy: "5. 정책 & 가드레일",
    badge_8steps: "8단계",

    // Threat Radar
    perimeter_title: "8대 능동 방어선 실시간 관제",
    perimeter_sub: "기본 차단(Default Deny) • 비협상 보안 통제",
    tier_prompt: "프롬프트 방화벽",
    tier_prompt_desc: "탈옥 및 시스템 프롬프트 유출 원천 차단",
    tier_content: "콘텐츠 방화벽",
    tier_content_desc: "RAG 데이터 오염 및 악성 마크다운 봉투 소독",
    tier_tool: "도구 방화벽",
    tier_tool_desc: "PlanValidator 및 대리인 공격/루프 방어",
    tier_mcp: "MCP 게이트웨이",
    tier_mcp_desc: "1회용 결과 티켓 및 출력 봉투 검증",
    tier_output: "출력 가드",
    tier_output_desc: "비밀키 노출 차단 및 결정론적 PII 비가역 마스킹",
    tier_resource: "자원 방화벽",
    tier_resource_desc: "파일시스템 / 네트워크 / 프로세스 SafeExecutor 격리",
    tier_runtime: "런타임 모니터",
    tier_runtime_desc: "세션 이상 행동 및 폭주 호출 탐지",
    tier_redteam: "레드팀 하네스",
    tier_redteam_desc: "오프라인 공격 시나리오 회귀 리그",
    shielded: "방어 가동",

    metric_latency: "파이프라인 레이턴시",
    metric_latency_desc: "p95 / 최대 지연시간 (1ms 검증 통과)",
    metric_total: "총 감사 처리량",
    metric_total_desc: "유계 링 버퍼 슬라이딩 윈도우",
    metric_blocked: "차단된 위협",
    metric_blocked_desc: "프롬프트/RAG/도구/시크릿 공격 차단",
    metric_sanitized: "소독 및 마스킹",
    metric_sanitized_desc: "결정론적 PII 및 개인정보 보호",

    stream_title: "실시간 감사 이벤트 스트림 (SecurityEvent Pipeline)",
    col_decision: "판정",
    col_type: "이벤트 유형",
    col_id: "이벤트 ID",
    col_reason: "사유 코드 (Reason Codes)",
    col_risk: "위험도",
    col_action: "동작",
    trace_btn: "추적",
    no_events: "해당 필터에 기록된 이벤트가 없습니다. 시뮬레이터에서 공격을 날리거나 데모 피드를 켜십시오.",

    // Pipeline Inspector
    inspector_title: "8단계 결정론적 의사결정 추적기",
    inspector_sub: "SecurityEvent ➔ Normalize ➔ Context ➔ Detect ➔ Risk ➔ Policy ➔ Decision ➔ Audit",
    inspecting_event: "선택된 이벤트:",
    exec_latency: "결정론적 처리 속도: < 0.2ms",
    stage_eval_detail: "단계별 상세 판정 결과",
    stage_artifacts: "구조화된 증적 데이터 (JSON)",

    // Threat Simulator
    sim_title: "인터랙티브 모의 침투 공격 시뮬레이터",
    sim_sub: "실제 FastAPI Control Plane으로 적대적 공격 페이로드를 주입하고 0.001초 만의 결정론적 차단을 검증하십시오.",
    presets_label: "공격 시나리오 프리셋:",
    target_layer: "공격 대상 방어선:",
    fire_btn: "적대적 공격 프로브 발사",
    firing_btn: "방어벽 가동 중...",
    telemetry_title: "실시간 차단 텔레메트리",
    standby_sim: "공격 대기 중. 상단 프리셋을 선택하거나 텍스트를 입력하고 발사 버튼을 누르십시오.",
    det_action: "결정론적 판정",
    comp_risk: "계산된 위험도",
    reasons_label: "구조화된 사유 코드 (Reason Codes):",
    payload_label: "판정 응답 페이로드 (Artifact):",
    llm_rule_notice: "🛡️ LLM은 최종 결정을 내리지 않습니다. 모든 판정은 100% 결정론적 엔진이 수행합니다.",

    // Worm Vault
    worm_title: "PHASE 10 WORM 감사 체인 & CLOUDFLARE R2 무결성 금고",
    worm_sub: "Cloudflare R2 audit/ 잠금 접두사 아래 삭제 거부가 강제되는 SHA-256 추가 전용(Append-Only) 암호화 해시체인.",
    verify_chain_btn: "전체 체인 무결성 정밀 검증",
    verifying_chain: "해시 체인 무결성 검증 중...",
    hash_chain_label: "위변조 불가 해시 체인",
    r2_worm_label: "CLOUDFLARE R2 WORM",
    redacted_secrets_label: "원천 차단된 시크릿",
    block_seq_title: "순차적 암호화 블록 시퀀스 (WORM Blocks)",

    // Policy Console
    policy_title: "PHASE 12 정책 라이프사이클 & 비협상 보안 통제",
    policy_sub: "엄격한 읽기 전용 모드에서 로드되는 Ed25519 전자서명 정책 번들 및 결정론적 룰 평가.",
    signature_ok: "🔒 전자서명 유효 (Ed25519 VERIFIED)",
    tab_controls: "비협상 보안 통제 6대 원칙",
    tab_grants: "승인된 도구 권한 화이트리스트",
    tab_yaml: "활성 AISEC YAML 정책 번들",

    // Footer
    footer_text: "🛡️ AI SECURITY CONTROL PLANE • 게이트: 100% 완결 • PYTHON 3.12+ / FASTAPI / PYDANTIC v2",
    footer_right: "독자적 방어 플랫폼 • ANTI-SLOP 규격 완벽 준수",
  },
  en: {
    // TopNav
    app_title: "AI SECURITY",
    app_subtitle: "CONTROL PLANE",
    gate_status: "Deterministic Gate: Phase 0–12 Closed (Pass: 21/21)",
    core: "CORE STATUS",
    online: "ONLINE",
    offline: "OFFLINE",
    latency: "LATENCY",
    latency_val: "1ms (p95)",
    r2_worm: "R2 WORM",
    synced: "SYNCED",
    total: "TOTAL",
    demo_traffic: "DATA SOURCE",
    live: "DEMO ACTIVE",
    off: "PURE LIVE",
    badge_live: "LIVE REAL",
    badge_mock: "MOCK DEMO",
    demo_mode_active: "⚠️ SIMULATION MOCK ACTIVE",
    demo_mode_desc: "Simulated threat scenarios are running while awaiting external live traffic. API calls and simulator executions will be logged as [LIVE REAL] events.",
    live_mode_active: "🟢 100% PURE LIVE BACKEND STREAM",
    live_mode_desc: "Mock generation is off. Listening strictly for verified live security events from external AI agents and the simulator.",
    switch_to_live_btn: "Switch to Pure Live",
    switch_to_demo_btn: "Turn On Demo Feed",
    data_source_title: "Data Source Status",
    refresh: "Refresh Core State",

    // SubNav
    tab_radar: "1. THREAT RADAR",
    tab_pipeline: "2. PIPELINE INSPECTOR",
    tab_simulator: "3. ATTACK SIMULATOR",
    tab_worm: "4. WORM CHAIN VAULT",
    tab_policy: "5. POLICY & GRANTS",
    badge_8steps: "8 STEPS",

    // Threat Radar
    perimeter_title: "8-Tier Active Defense Perimeter",
    perimeter_sub: "Default Deny • Non-Negotiable Controls",
    tier_prompt: "Prompt Firewall",
    tier_prompt_desc: "Jailbreak & System Override Defense",
    tier_content: "Content Firewall",
    tier_content_desc: "RAG Poisoning & Markdown Envelope",
    tier_tool: "Tool Firewall",
    tier_tool_desc: "PlanValidator & Confused Deputy Loop",
    tier_mcp: "MCP Gateway",
    tier_mcp_desc: "1-Time Capability & Result Sanitizer",
    tier_output: "Output Guard",
    tier_output_desc: "Secret Detection & Deterministic PII",
    tier_resource: "Resource Firewall",
    tier_resource_desc: "FS / Network / Process SafeExecutor",
    tier_runtime: "Runtime Monitor",
    tier_runtime_desc: "Session Anomaly & Burst Fan-out",
    tier_redteam: "Red-Team Engine",
    tier_redteam_desc: "Deterministic Probe Regression League",
    shielded: "SHIELDED",

    metric_latency: "PIPELINE LATENCY",
    metric_latency_desc: "p95 / Max Durations (Evaluated)",
    metric_total: "TOTAL PROCESSED",
    metric_total_desc: "Bounded sliding ring window",
    metric_blocked: "ATTACKS INTERCEPTED",
    metric_blocked_desc: "Prompt, RAG, Tool, Secret attacks",
    metric_sanitized: "SANITIZED / MASKED",
    metric_sanitized_desc: "Deterministic PII & redactions",

    stream_title: "REAL-TIME AUDIT STREAM (SecurityEvent Pipeline)",
    col_decision: "DECISION",
    col_type: "EVENT TYPE",
    col_id: "EVENT ID",
    col_reason: "REASON CODES",
    col_risk: "RISK SCORE",
    col_action: "ACTION",
    trace_btn: "TRACE",
    no_events: "NO EVENTS DETECTED IN THIS FILTER. INJECT AN ATTACK IN THE SIMULATOR OR TOGGLE DEMO FEED.",

    // Pipeline Inspector
    inspector_title: "DETERMINISTIC PIPELINE TRACER",
    inspector_sub: "SecurityEvent ➔ Normalize ➔ Context ➔ Detect ➔ Risk ➔ Policy ➔ Decision ➔ Audit",
    inspecting_event: "INSPECTING EVENT:",
    exec_latency: "Deterministic Execution: < 0.2ms",
    stage_eval_detail: "Operational Evaluation Detail",
    stage_artifacts: "Structured Telemetry Artifacts",

    // Threat Simulator
    sim_title: "INTERACTIVE ATTACK SIMULATOR & ZERO-TRUST SANDBOX",
    sim_sub: "Inject real-time adversarial payloads into the FastAPI Control Plane and observe millisecond deterministic interception.",
    presets_label: "ATTACK SCENARIO PRESETS:",
    target_layer: "TARGET DEFENSE LAYER:",
    fire_btn: "FIRE ADVERSARIAL PROBE",
    firing_btn: "INTERCEPTING...",
    telemetry_title: "Interception Telemetry",
    standby_sim: "STANDBY FOR PROBE EXECUTION. CHOOSE A PRESET AND CLICK FIRE.",
    det_action: "Deterministic Action",
    comp_risk: "Computed Risk Score",
    reasons_label: "Structured Reason Codes:",
    payload_label: "Decision Response Payload:",
    llm_rule_notice: "🛡️ LLMs never make final security decisions. All outcomes are deterministic.",

    // Worm Vault
    worm_title: "PHASE 10 WORM AUDIT CHAIN & CLOUDFLARE R2 VAULT",
    worm_sub: "Append-only SHA-256 cryptographic hash chain with enforced deletion denial under Cloudflare R2 audit/ prefix.",
    verify_chain_btn: "VERIFY FULL CHAIN INTEGRITY",
    verifying_chain: "VERIFYING HASHES...",
    hash_chain_label: "IMMUTABLE HASH CHAIN",
    r2_worm_label: "CLOUDFLARE R2 WORM",
    redacted_secrets_label: "REDACTED SECRETS",
    block_seq_title: "Sequential Cryptographic Block Sequence",

    // Policy Console
    policy_title: "PHASE 12 POLICY LIFECYCLE & MANDATORY CONSTRAINTS",
    policy_sub: "Ed25519-signed policy bundles loaded in strict read-only mode with deterministic rule evaluation.",
    signature_ok: "🔒 SIGNATURE VALIDATED (Ed25519)",
    tab_controls: "NON-NEGOTIABLE CONTROLS",
    tab_grants: "APPROVED TOOL GRANTS",
    tab_yaml: "ACTIVE AISEC YAML BUNDLE",

    // Footer
    footer_text: "🛡️ AI SECURITY CONTROL PLANE • GATE: CLOSED 100% • PYTHON 3.12+ / FASTAPI / PYDANTIC v2",
    footer_right: "PROPRIETARY DEFENSIVE PLATFORM • ANTI-SLOP COMPLIANT",
  },
  ja: {
    // TopNav
    app_title: "AI SECURITY",
    app_subtitle: "CONTROL PLANE",
    gate_status: "確定論的ゲート: Phase 0–12 完了 (全21ジョブ合格)",
    core: "コア状態",
    online: "稼働中 (ONLINE)",
    offline: "停止中 (OFFLINE)",
    latency: "レイテンシ",
    latency_val: "1ms (超低遅延)",
    r2_worm: "R2監査チェーン",
    synced: "同期完了 (SYNCED)",
    total: "処理総数",
    block_rate: "阻止率",
    demo_traffic: "データソース",
    live: "デモ稼働中",
    off: "純粋実機",
    badge_live: "LIVE 実機",
    badge_mock: "MOCK 模擬",
    demo_mode_active: "⚠️ 模擬モック稼働中",
    demo_mode_desc: "現在外部トラフィック待機中のため模擬シナリオを再生しています。攻撃シミュレータ実行やAPI呼出時は即座に[LIVE 実機]イベントとして記録されます。",
    live_mode_active: "🟢 100% 実機リアルタイム待機",
    live_mode_desc: "モック生成を停止しました。外部AIエージェントおよびシミュレータからの検証済み実機イベントのみ受信します。",
    switch_to_live_btn: "純粋実機モードへ切替",
    switch_to_demo_btn: "デモモックを有効化",
    data_source_title: "データソース監視状態",
    refresh: "状態更新",

    // SubNav
    tab_radar: "1. 脅威レーダー",
    tab_pipeline: "2. パイプライン追跡",
    tab_simulator: "3. 攻撃シミュレーター",
    tab_worm: "4. WORMチェーン保管庫",
    tab_policy: "5. ポリシー・権限",
    badge_8steps: "8段階",

    // Threat Radar
    perimeter_title: "8層能動的防衛境界 リアルタイム監視",
    perimeter_sub: "デフォルト拒否(Default Deny) • 厳格なセキュリティ制御",
    tier_prompt: "プロンプト防壁",
    tier_prompt_desc: "脱獄(Jailbreak)およびシステム命令漏洩を完全遮断",
    tier_content: "コンテンツ防壁",
    tier_content_desc: "RAGデータ汚染および悪性Markdownの無害化封筒処理",
    tier_tool: "ツール防壁",
    tier_tool_desc: "PlanValidatorによる代理人攻撃および無限ループ防止",
    tier_mcp: "MCPゲートウェイ",
    tier_mcp_desc: "単一用途チケット発行と出力検証",
    tier_output: "出力ガード",
    tier_output_desc: "認証情報漏洩阻止および確定論的PII不可逆マスキング",
    tier_resource: "リソース防壁",
    tier_resource_desc: "ファイル/ネットワーク/プロセスのSafeExecutor隔離",
    tier_runtime: "ランタイム監視",
    tier_runtime_desc: "セッション異常行動およびバースト呼び出し検知",
    tier_redteam: "レッドチーム検証",
    tier_redteam_desc: "確定論的プローブ回帰リーグ",
    shielded: "防衛中",

    metric_latency: "パイプライン遅延",
    metric_latency_desc: "p95 / 最大遅延 (1ms合格検証済み)",
    metric_total: "監査処理総数",
    metric_total_desc: "有界リングバッファ監視",
    metric_blocked: "阻止された攻撃",
    metric_blocked_desc: "プロンプト/RAG/ツール/秘密情報の遮断",
    metric_sanitized: "無害化・マスキング",
    metric_sanitized_desc: "確定論的個人情報(PII)保護",

    stream_title: "リアルタイム監査イベントストリーム (SecurityEvent)",
    col_decision: "判定",
    col_type: "イベント種別",
    col_id: "イベントID",
    col_reason: "理由コード (Reason Codes)",
    col_risk: "危険度",
    col_action: "操作",
    trace_btn: "追跡",
    no_events: "現在フィルターに該当するイベントはありません。シミュレーターでテストするかデモを有効化してください。",

    // Pipeline Inspector
    inspector_title: "8段階 確定論的パイプライン追跡機",
    inspector_sub: "SecurityEvent ➔ Normalize ➔ Context ➔ Detect ➔ Risk ➔ Policy ➔ Decision ➔ Audit",
    inspecting_event: "検査対象イベント:",
    exec_latency: "確定論的実行速度: < 0.2ms",
    stage_eval_detail: "ステージ別 詳細評価結果",
    stage_artifacts: "構造化テレメトリ証跡 (JSON)",

    // Threat Simulator
    sim_title: "対話型 模擬攻撃シミュレーター & サンドボックス",
    sim_sub: "FastAPI Control Planeに対して敵対的攻撃を投入し、1ミリ秒以内の確定論的遮断を直接検証します。",
    presets_label: "攻撃シナリオ プリセット:",
    target_layer: "攻撃対象 防衛層:",
    fire_btn: "敵対的プローブ発射",
    firing_btn: "防衛中...",
    telemetry_title: "リアルタイム迎撃テレメトリ",
    standby_sim: "攻撃待機中。プリセットを選択するかテキストを入力して発射ボタンを押してください。",
    det_action: "確定論的判定",
    comp_risk: "算出された危険度",
    reasons_label: "構造化理由コード (Reason Codes):",
    payload_label: "判定応答ペイロード (Artifact):",
    llm_rule_notice: "🛡️ LLMは最終決定を行いません。すべての判定は確定論的セキュリティエンジンが実行します。",

    // Worm Vault
    worm_title: "PHASE 10 WORM監査チェーン & CLOUDFLARE R2保管庫",
    worm_sub: "Cloudflare R2 audit/プレフィックス下で削除拒否が強制されるSHA-256追加専用暗号化ハッシュチェーン。",
    verify_chain_btn: "全チェーン整合性の完全検証",
    verifying_chain: "ハッシュ検証中...",
    hash_chain_label: "改ざん不能ハッシュチェーン",
    r2_worm_label: "CLOUDFLARE R2 WORM",
    redacted_secrets_label: "完全秘匿化クレデンシャル",
    block_seq_title: "暗号化連続ブロックシーケンス (WORM Blocks)",

    // Policy Console
    policy_title: "PHASE 12 ポリシーライフサイクル & 必須セキュリティ制約",
    policy_sub: "厳格な読み取り専用モードでロードされるEd25519電子署名ポリシーバンドルおよび確定論的ルール評価。",
    signature_ok: "🔒 署名検証完了 (Ed25519 VERIFIED)",
    tab_controls: "妥協不可 6大セキュリティ原則",
    tab_grants: "承認済みツール権限ホワイトリスト",
    tab_yaml: "アクティブ AISEC YAMLバンドル",

    // Footer
    footer_text: "🛡️ AI SECURITY CONTROL PLANE • ゲート: 100%完了 • PYTHON 3.12+ / FASTAPI / PYDANTIC v2",
    footer_right: "独自防衛基盤 • ANTI-SLOP規格 適合",
  },
};

export const LanguageProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [language, setLanguageState] = useState<Language>('ko'); // Default to Korean!

  useEffect(() => {
    const saved = localStorage.getItem('aisec_lang') as Language;
    if (saved && (saved === 'ko' || saved === 'en' || saved === 'ja')) {
      setLanguageState(saved);
    }
  }, []);

  const setLanguage = useCallback((lang: Language) => {
    setLanguageState(lang);
    localStorage.setItem('aisec_lang', lang);
  }, []);

  const t = useCallback(
    (key: string): string => {
      return translations[language]?.[key] || translations['en']?.[key] || key;
    },
    [language]
  );

  return (
    <LanguageContext.Provider value={{ language, setLanguage, t }}>
      {children}
    </LanguageContext.Provider>
  );
};

export const useLanguage = () => {
  const context = useContext(LanguageContext);
  if (!context) {
    throw new Error('useLanguage must be used within a LanguageProvider');
  }
  return context;
};
