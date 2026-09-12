"use client";

import React from 'react';
import {
  Shield,
  Zap,
  Lock,
  Cpu,
  Database,
  ArrowRight,
  CheckCircle,
  Layers,
  Terminal,
  ExternalLink,
  Code2,
  Sliders,
  FileCheck,
  Server,
} from 'lucide-react';
import { HeroSimulator } from '@/components/ui/HeroSimulator';
import { BenchmarkChart } from '@/components/ui/BenchmarkChart';
import { useLanguage } from '@/context/LanguageContext';

interface LandingPageViewProps {
  onEnterDashboard: () => void;
}

export const LandingPageView: React.FC<LandingPageViewProps> = ({ onEnterDashboard }) => {
  const { language } = useLanguage();
  const isKo = language === 'ko';

  const pipelineStages = [
    { num: '01', name: 'SecurityEvent', descKo: '에이전트 모든 입출력 표준화', descEn: 'Normalized audit telemetry ingest' },
    { num: '02', name: 'Normalize', descKo: '인코딩 난독화 해제 및 정규화', descEn: 'Decode obfuscated payloads' },
    { num: '03', name: 'Context', descKo: '세션·신뢰등급 컨텍스트 빌드', descEn: 'Build session & trust level state' },
    { num: '04', name: 'Detect', descKo: '정규식 + ONNX 시맨틱 탐지', descEn: 'Regex + ONNX hybrid detection' },
    { num: '05', name: 'Risk', descKo: '결정론적 다차원 위험 점수화', descEn: 'Deterministic risk scoring' },
    { num: '06', name: 'Policy', descKo: '암호화 서명 정책 규칙 매칭', descEn: 'Cryptographic policy enforcement' },
    { num: '07', name: 'Decision', descKo: 'Default Deny 사유코드 산출', descEn: 'ALLOW / DENY structured reasons' },
    { num: '08', name: 'Audit', descKo: 'SHA-256 WORM 불변 감사 체인', descEn: 'WORM immutable append-only sink' },
  ];

  const controlLayers = [
    {
      icon: <Sliders className="w-6 h-6 text-[#00F0FF]" />,
      titleKo: 'MCP 도구 권한 게이트웨이',
      titleEn: 'MCP Tool Gateway & Scopes',
      descKo: '에이전트가 외부 MCP 서버를 호출할 때 선언된 스코프와 매니페스트를 검증하고 위험 도구 호출을 사전 격리합니다.',
      descEn: 'Mediates Model Context Protocol tool execution against strictly authorized scopes and tool manifests.',
    },
    {
      icon: <FileCheck className="w-6 h-6 text-[#00FF9D]" />,
      titleKo: '실행 계획 검증 & 대리인 혼란 방어',
      titleEn: 'Plan Validator & Confused Deputy',
      descKo: 'LLM이 생성한 복합 계획 단계의 무결성을 검증하고, 비인가 권한 상승이나 간접 프롬프트 공격을 원천 차단합니다.',
      descEn: 'Inspects multi-step LLM plans to prevent authorization confusion and privilege escalation chains.',
    },
    {
      icon: <Lock className="w-6 h-6 text-[#FFB800]" />,
      titleKo: 'OS·파일시스템·네트워크 방화벽',
      titleEn: 'Multi-Resource Sandboxing',
      descKo: '프로세스 실행 시 shell=False 격리, 파일시스템 허용 디렉토리 제한, SSRF 방지 네트워크 DNS 필터를 강제합니다.',
      descEn: 'Enforces process sandboxes, strict path resolution boundaries, and outbound network SSRF filters.',
    },
    {
      icon: <Database className="w-6 h-6 text-[#FF0055]" />,
      titleKo: '암호화 정책 서명 & WORM 불변 감사',
      titleEn: 'Policy Signing & WORM Audit Vault',
      descKo: 'HMAC/Ed25519 서명 정책만 활성화하며, 모든 결정은 SHA-256 해시체인과 Cloudflare R2 WORM 버킷에 비동기 복제됩니다.',
      descEn: 'Cryptographically verifies policy bundles and records tamper-proof audit trails with Cloudflare R2 WORM replication.',
    },
  ];

  return (
    <div className="w-full bg-[#04080E] text-white">
      {/* 1. Hero Section */}
      <section className="relative pt-12 pb-20 px-6 max-w-[1440px] mx-auto overflow-hidden">
        {/* Ambient Glows */}
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[700px] h-[350px] bg-[#00F0FF]/10 blur-[120px] pointer-events-none rounded-full" />
        <div className="absolute top-40 right-10 w-[400px] h-[250px] bg-[#00FF9D]/10 blur-[100px] pointer-events-none rounded-full" />

        <div className="text-center relative z-10 max-w-4xl mx-auto">
          {/* Badge */}
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#00F0FF]/10 border border-[#00F0FF]/30 text-[#00F0FF] text-xs font-mono font-bold mb-6 tracking-wide shadow-[0_0_15px_rgba(0,240,255,0.2)]">
            <Zap className="w-3.5 h-3.5 text-[#00FF9D]" />
            <span>0.145ms IN-PROCESS SDK & ENTERPRISE CONTROL PLANE</span>
          </div>

          {/* Main Headline */}
          <h1 className="text-4xl sm:text-6xl font-extrabold tracking-tight leading-[1.15] bg-gradient-to-b from-white via-gray-100 to-gray-400 bg-clip-text text-transparent font-sans">
            {isKo ? (
              <>
                AI 에이전트의 모든 실행 사이클을 통제하는 <br />
                <span className="text-[#00F0FF] underline decoration-[#00F0FF]/40 underline-offset-8">
                  무결점 방어 제어 평면
                </span>
              </>
            ) : (
              <>
                Defensive AI Security Control Plane <br />
                <span className="text-[#00F0FF] underline decoration-[#00F0FF]/40 underline-offset-8">
                  For Autonomous Agent Systems
                </span>
              </>
            )}
          </h1>

          {/* Subtitle */}
          <p className="mt-6 text-base sm:text-lg text-[#849495] max-w-2xl mx-auto leading-relaxed">
            {isKo
              ? 'LLM의 출력과 외부 입력을 신뢰하지 마십시오. Default Deny 원칙, 0.1ms 인프로세스 방화벽, 그리고 SHA-256 불변 감사 체인으로 에이전트 시스템을 완벽히 보호합니다.'
              : 'Never trust raw LLM outputs or external prompts. Protect enterprise agents with Default Deny firewalls, 0.1ms In-Process SDK, and WORM-locked audit chains.'}
          </p>

          {/* Dual Action Buttons */}
          <div className="mt-8 flex flex-wrap items-center justify-center gap-4">
            <button
              onClick={onEnterDashboard}
              className="px-8 py-4 rounded-xl bg-gradient-to-r from-[#00F0FF] to-[#00FF9D] text-black font-mono font-bold text-sm hover:shadow-[0_0_30px_rgba(0,240,255,0.4)] transition-all flex items-center gap-2.5 cursor-pointer transform hover:-translate-y-0.5"
            >
              <span>{isKo ? '실시간 SOC 관제탑 입장' : 'Launch Live SOC Console'}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
            <a
              href="https://github.com"
              target="_blank"
              rel="noreferrer"
              className="px-7 py-4 rounded-xl bg-white/[0.05] border border-white/15 text-gray-300 font-mono font-bold text-sm hover:text-white hover:bg-white/10 transition-all flex items-center gap-2"
            >
              <Terminal className="w-4 h-4 text-[#849495]" />
              <span>{isKo ? 'GitHub 레포지토리' : 'View GitHub Repo'}</span>
              <ExternalLink className="w-3.5 h-3.5 text-[#849495]" />
            </a>
          </div>

          {/* Live Trust Metrics */}
          <div className="mt-10 pt-6 border-t border-white/10 grid grid-cols-2 sm:grid-cols-4 gap-4 text-left font-mono">
            <div>
              <div className="text-[11px] text-[#849495] uppercase">{isKo ? '평균 지연시간' : 'Avg Latency'}</div>
              <div className="text-xl font-bold text-[#00FF9D] mt-0.5">0.145 ms</div>
            </div>
            <div>
              <div className="text-[11px] text-[#849495] uppercase">{isKo ? '보안 테스트 통과' : 'Security Tests'}</div>
              <div className="text-xl font-bold text-white mt-0.5">338 / 338 <span className="text-xs text-[#00FF9D]">(100%)</span></div>
            </div>
            <div>
              <div className="text-[11px] text-[#849495] uppercase">{isKo ? '제어 파이프라인' : 'Control Pipeline'}</div>
              <div className="text-xl font-bold text-[#00F0FF] mt-0.5">8-Stage Core</div>
            </div>
            <div>
              <div className="text-[11px] text-[#849495] uppercase">{isKo ? '감사 무결성' : 'Audit Integrity'}</div>
              <div className="text-xl font-bold text-[#FFB800] mt-0.5">WORM Locked</div>
            </div>
          </div>
        </div>

        {/* Hero Interactive Simulator Component */}
        <div className="mt-12 max-w-4xl mx-auto">
          <HeroSimulator />
        </div>
      </section>

      {/* 2. Benchmark Section */}
      <section className="py-16 px-6 max-w-[1440px] mx-auto border-t border-white/10">
        <div className="text-center max-w-3xl mx-auto mb-10">
          <div className="text-xs font-mono text-[#00FF9D] uppercase tracking-widest font-bold mb-2">
            PROVEN PERFORMANCE GATE
          </div>
          <h2 className="text-3xl font-extrabold text-white">
            {isKo ? '지연시간 28.2배 단축: In-Process SDK의 속도 혁신' : '28.2x Faster: In-Process Embedded SDK'}
          </h2>
          <p className="mt-3 text-sm text-[#849495]">
            {isKo
              ? 'Docker/HTTP 마이크로서비스 호출 대신 파이썬 프로세스 내에 직접 임베딩되어, 모델 추론 체인의 체감 지연(TTFT)을 완전히 보존합니다.'
              : 'Zero HTTP roundtrips. Directly imported in agent processes to preserve real-time inference TTFT.'}
          </p>
        </div>

        <div className="max-w-4xl mx-auto">
          <BenchmarkChart />
        </div>
      </section>

      {/* 3. 8-Stage Security Pipeline Section */}
      <section className="py-16 px-6 max-w-[1440px] mx-auto border-t border-white/10 bg-[#0B131E]/40">
        <div className="text-center max-w-3xl mx-auto mb-12">
          <div className="text-xs font-mono text-[#00F0FF] uppercase tracking-widest font-bold mb-2">
            ARCHITECTURAL BACKBONE
          </div>
          <h2 className="text-3xl font-extrabold text-white">
            {isKo ? '8단계 결정론적 보안 제어 파이프라인' : '8-Stage Deterministic Security Pipeline'}
          </h2>
          <p className="mt-3 text-sm text-[#849495]">
            {isKo
              ? '보안 판정에 블랙박스 LLM을 사용하지 않습니다. 100% 검증 가능하고 사유 코드가 남는 엄격한 파이프라인을 통과합니다.'
              : 'LLMs never make final security decisions. Every request transitions through deterministic stages with structured audit reason codes.'}
          </p>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3 max-w-[1400px] mx-auto">
          {pipelineStages.map((stage, idx) => (
            <div
              key={idx}
              className="bg-[#0B131E] border border-white/10 rounded-xl p-3.5 relative group hover:border-[#00F0FF] hover:shadow-[0_0_20px_rgba(0,240,255,0.2)] transition-all"
            >
              <div className="text-[10px] font-mono text-[#00F0FF] font-bold">STAGE {stage.num}</div>
              <div className="text-xs font-mono font-bold text-white mt-1 group-hover:text-[#00F0FF] transition-colors truncate">
                {stage.name}
              </div>
              <div className="text-[10px] text-[#849495] mt-1.5 leading-snug">
                {isKo ? stage.descKo : stage.descEn}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* 4. 4 Proprietary Control Layers */}
      <section className="py-20 px-6 max-w-[1440px] mx-auto border-t border-white/10">
        <div className="text-center max-w-3xl mx-auto mb-14">
          <div className="text-xs font-mono text-[#FFB800] uppercase tracking-widest font-bold mb-2">
            NON-NEGOTIABLE PROPRIETARY ENGINES
          </div>
          <h2 className="text-3xl font-extrabold text-white">
            {isKo ? '외부 API 래퍼가 아닌, 자체 원천 보안 레이어' : 'Proprietary Zero-Trust Control Layers'}
          </h2>
          <p className="mt-3 text-sm text-[#849495]">
            {isKo
              ? '서드파티 의존성 없이 독자 설계된 4대 보안 엔진이 에이전트의 도구, 계획, OS 자원을 완전히 격리합니다.'
              : 'No third-party wrappers. Four strictly proprietary engines enforce sandboxes across MCP tools, execution plans, and OS resources.'}
          </p>
        </div>

        <div className="grid sm:grid-cols-2 gap-6 max-w-5xl mx-auto">
          {controlLayers.map((layer, idx) => (
            <div
              key={idx}
              className="bg-[#0B131E]/70 border border-white/10 rounded-2xl p-7 hover:border-[#00F0FF]/40 hover:shadow-[0_0_25px_rgba(0,240,255,0.1)] transition-all"
            >
              <div className="w-12 h-12 rounded-xl bg-white/[0.04] border border-white/10 flex items-center justify-center mb-5">
                {layer.icon}
              </div>
              <h3 className="font-mono text-base font-bold text-white mb-2">
                {isKo ? layer.titleKo : layer.titleEn}
              </h3>
              <p className="text-xs text-[#849495] leading-relaxed">
                {isKo ? layer.descKo : layer.descEn}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* 5. Developer Code Snippet */}
      <section className="py-16 px-6 max-w-[1440px] mx-auto border-t border-white/10 bg-[#0B131E]/50">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-8">
            <div className="text-xs font-mono text-[#00FF9D] uppercase tracking-widest font-bold mb-2">
              DEVELOPER EXPERIENCE
            </div>
            <h2 className="text-2xl sm:text-3xl font-extrabold text-white">
              {isKo ? '단 3줄로 끝나는 In-Process 임베딩' : 'Zero-Overhead 3-Line Integration'}
            </h2>
          </div>

          <div className="bg-black/80 border border-white/15 rounded-2xl overflow-hidden shadow-2xl">
            <div className="bg-[#0B131E] px-4 py-2.5 border-b border-white/10 flex items-center justify-between text-xs font-mono text-[#849495]">
              <div className="flex items-center gap-2">
                <div className="w-2.5 h-2.5 rounded-full bg-[#FF0055]" />
                <div className="w-2.5 h-2.5 rounded-full bg-[#FFB800]" />
                <div className="w-2.5 h-2.5 rounded-full bg-[#00FF9D]" />
                <span className="ml-2 text-gray-300">agent_pipeline.py</span>
              </div>
              <span className="text-[11px] text-[#00F0FF]">Python 3.12+</span>
            </div>
            <pre className="p-5 font-mono text-xs text-gray-200 overflow-x-auto leading-relaxed">
              <code>{`from sdk import AISecurityClient, Profile, firewall

# 1. Protect any sync or async agent function with decorators
@firewall.protect(profile=Profile.STANDARD)
async def execute_agent_step(user_prompt: str) -> str:
    # Safe to call LLM: malicious prompts are blocked in 0.1ms before reaching inference
    return await llm_client.generate(user_prompt)

# 2. Or call direct in-process APIs without spinning up HTTP services
client = AISecurityClient(Profile.STANDARD)
result = client.scan_prompt("Summarize this document")
assert result.decision.decision.value == "ALLOW"`}</code>
            </pre>
          </div>
        </div>
      </section>

      {/* 6. GEO Semantic FAQ Section */}
      <section className="py-16 px-6 max-w-[1440px] mx-auto border-t border-white/10">
        <div className="text-center max-w-3xl mx-auto mb-12">
          <div className="text-xs font-mono text-[#00F0FF] uppercase tracking-widest font-bold mb-2">
            FREQUENTLY ASKED QUESTIONS
          </div>
          <h2 className="text-3xl font-extrabold text-white">
            {isKo ? '자주 묻는 질문 & 아키텍처 FAQ' : 'Frequently Asked Questions'}
          </h2>
          <p className="mt-3 text-sm text-[#849495]">
            {isKo
              ? '엔터프라이즈 도입 및 기술 아키텍처에 대해 가장 많이 묻는 핵심 질문입니다.'
              : 'Key technical insights and enterprise adoption guidelines.'}
          </p>
        </div>

        <div className="max-w-4xl mx-auto space-y-4">
          <div className="bg-[#0B131E]/80 border border-white/10 rounded-2xl p-6">
            <h3 className="font-mono text-base font-bold text-white mb-2 text-[#00F0FF]">
              Q. {isKo ? 'AI Security Control Plane이란 정확히 무엇인가요?' : 'What is the AI Security Control Plane?'}
            </h3>
            <p className="text-xs sm:text-sm text-[#849495] leading-relaxed">
              {isKo
                ? '자율형 LLM 에이전트가 실행하는 모든 동작(사용자 프롬프트, 외부 MCP 도구 호출, 다단계 실행 계획, 파일 및 OS 자원 접근)을 실시간으로 감시하고, Default Deny 원칙에 따라 인가되지 않은 탈옥 및 권한 상승을 사전 차단하는 독자적 방어 제어 평면입니다.'
                : 'A proprietary defensive control plane that intercepts agent execution cycles in real-time, enforcing Default Deny access boundaries across prompts, MCP tools, execution plans, and OS resources.'}
            </p>
          </div>

          <div className="bg-[#0B131E]/80 border border-white/10 rounded-2xl p-6">
            <h3 className="font-mono text-base font-bold text-white mb-2 text-[#00FF9D]">
              Q. {isKo ? 'In-Process Embedded SDK는 기존 REST API와 어떻게 다른가요?' : 'How does the In-Process SDK differ from REST APIs?'}
            </h3>
            <p className="text-xs sm:text-sm text-[#849495] leading-relaxed">
              {isKo
                ? '기존 마이크로서비스 방식의 HTTP 핸드셰이크, 소켓 I/O, JSON 직렬화 병목을 100% 제거하여 평균 0.145ms(기존 REST 4.089ms 대비 28.2배 속도 혁신)로 실행됩니다. 파이썬 에이전트 프로세스 내에 직접 임베딩되어 에이전트 인퍼런스 지연을 0에 가깝게 유지합니다.'
                : 'It eliminates HTTP socket and serialization overhead entirely, achieving an average latency of 0.145ms (28.2x speedup compared to REST 4.089ms). Directly imported in agent processes with zero infrastructure overhead.'}
            </p>
          </div>

          <div className="bg-[#0B131E]/80 border border-white/10 rounded-2xl p-6">
            <h3 className="font-mono text-base font-bold text-white mb-2 text-[#FFB800]">
              Q. {isKo ? 'MCP(Model Context Protocol) 게이트웨이는 어떻게 공격을 방어하나요?' : 'How does the MCP Gateway prevent tool abuse?'}
            </h3>
            <p className="text-xs sm:text-sm text-[#849495] leading-relaxed">
              {isKo
                ? '에이전트가 호출하려는 도구의 선언된 스코프와 매니페스트 해시를 대조 검증하고, 허용되지 않은 쉘 명령어 실행(rm -rf), 경로 조작(../), 내부망 SSRF 시도를 가상화 격리 계층에서 즉각 차단합니다.'
                : 'It cryptographically verifies tool manifests against declared scopes, blocking unauthorized shell strings, path escapes, and internal SSRF probes via strict virtual sandboxing.'}
            </p>
          </div>

          <div className="bg-[#0B131E]/80 border border-white/10 rounded-2xl p-6">
            <h3 className="font-mono text-base font-bold text-white mb-2 text-[#FF0055]">
              Q. {isKo ? 'WORM 불변 감사는 왜 필수적인가요?' : 'Why is WORM Immutable Auditing mandatory?'}
            </h3>
            <p className="text-xs sm:text-sm text-[#849495] leading-relaxed">
              {isKo
                ? '보안 판정이 일어난 모든 이벤트는 SHA-256 해시체인과 Cloudflare R2 원격 WORM(Write Once, Read Many) 스토리지에 동시 복제됩니다. 공격자가 시스템을 장악하더라도 과거의 감사 기록을 변조하거나 삭제할 수 없어 완전한 법적·포렌식 증적을 보장합니다.'
                : 'All decisions are committed to append-only SHA-256 hash chains and Cloudflare R2 WORM storage. Even under system compromise, past audit entries cannot be modified or purged, guaranteeing tamper-proof forensic evidence.'}
            </p>
          </div>
        </div>
      </section>

      {/* 7. CTA Banner */}
      <section className="py-20 px-6 max-w-[1440px] mx-auto text-center relative overflow-hidden">
        <div className="max-w-3xl mx-auto bg-gradient-to-b from-[#0B131E] to-[#04080E] border border-[#00F0FF]/30 rounded-3xl p-10 relative shadow-[0_0_50px_rgba(0,240,255,0.1)]">
          <h2 className="text-3xl sm:text-4xl font-extrabold text-white">
            {isKo ? '지금 바로 실시간 관제탑을 경험하십시오' : 'Experience the Real-Time Security War-Room'}
          </h2>
          <p className="mt-4 text-sm text-[#849495] max-w-xl mx-auto">
            {isKo
              ? '위협 레이더, 파이프라인 인스펙터, 공격 시뮬레이터, WORM 감사 체인이 하나로 연결된 2026 Spatial Cyber SOC를 체험할 수 있습니다.'
              : 'Explore the full Spatial Cyber SOC with live SSE threat radar, 8-stage inspector, threat simulator, and WORM vault.'}
          </p>
          <div className="mt-8 flex justify-center">
            <button
              onClick={onEnterDashboard}
              className="px-8 py-4 rounded-xl bg-gradient-to-r from-[#00F0FF] to-[#00FF9D] text-black font-mono font-bold text-sm hover:shadow-[0_0_30px_rgba(0,240,255,0.5)] transition-all flex items-center gap-2 cursor-pointer"
            >
              <span>{isKo ? 'Cyber SOC 대시보드 입장' : 'Launch Cyber SOC Console'}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-white/10 py-8 px-6 text-center text-xs font-mono text-[#849495]">
        <div className="max-w-4xl mx-auto flex flex-wrap items-center justify-between gap-4">
          <div>AI Security Control Plane © 2026 — Defensive AI Architecture</div>
          <div className="flex items-center gap-4">
            <span className="text-[#00FF9D] flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-[#00FF9D]" />
              <span>All 338 Tests Passing</span>
            </span>
            <span className="text-[#00F0FF]">Default Deny Core</span>
          </div>
        </div>
      </footer>
    </div>
  );
};
