"use client";

import React, { useState } from 'react';
import { FileCode, CheckCircle2 } from 'lucide-react';
import { useLanguage } from '@/context/LanguageContext';

export const PolicyConsoleView: React.FC = () => {
  const { t, language } = useLanguage();
  const [activeSection, setActiveSection] = useState<'rules' | 'grants' | 'yaml'>('rules');

  const controls = [
    {
      num: 1,
      title: language === 'ko' ? '기본 차단 & 최소 권한 (Default Deny)' : language === 'ja' ? 'デフォルト拒否 & 最小権限' : 'Default Deny & Least Privilege',
      desc: language === 'ko' ? '알 수 없거나 미인증된 모든 작업은 기본적으로 DENY로 즉각 실패 차단됩니다.' : language === 'ja' ? '未知または未認証のすべての操作はデフォルトでDENYにフェイルクローズします。' : 'Unknown or unauthenticated actions fail closed to DENY.',
      verified: true,
    },
    {
      num: 2,
      title: language === 'ko' ? 'LLM 출력 불신 원칙 (Untrusted LLM)' : language === 'ja' ? 'LLM出力の完全不信原則' : 'Untrusted LLM Output',
      desc: language === 'ko' ? '도구 호출, 파일 경로, URL, SQL 등 LLM 산출물은 방화벽 검증 없이 절대 실행되지 않습니다.' : language === 'ja' ? 'ツール呼び出し、パス、URLなどのLLM生成値は防壁の検証なしに直接実行されません。' : 'Tool calls, filepaths, and URLs never execute without firewall validation.',
      verified: true,
    },
    {
      num: 3,
      title: language === 'ko' ? 'LLM 보안 결정 배제 (No LLM Final Decisions)' : language === 'ja' ? 'LLMのセキュリティ最終決定禁止' : 'No LLM Final Decisions',
      desc: language === 'ko' ? '모든 핵심 보안 결정은 100% 결정론적 엔진이 구조화된 사유 코드와 함께 수행합니다.' : language === 'ja' ? 'すべての重要な判定は100%確定論的エンジンが構造化理由コードと共に行います。' : 'All critical security decisions are strictly deterministic with structured reason codes.',
      verified: true,
    },
    {
      num: 4,
      title: language === 'ko' ? 'Ed25519 불변 정책 전자서명' : language === 'ja' ? 'Ed25519改ざん防止電子署名' : 'Immutable Ed25519 Signatures',
      desc: language === 'ko' ? '활성 정책 번들은 런타임 시작 전 반드시 검증된 키로 서명 검증을 통과해야 합니다.' : language === 'ja' ? 'アクティブポリシーは起動前に署名検証を通過しなければロードされません。' : 'Active policies must be signed and verified before runtime activation.',
      verified: true,
    },
    {
      num: 5,
      title: language === 'ko' ? 'LLM 셸 문자열 실행 금지 (shell=False)' : language === 'ja' ? 'LLMシェル文字列の実行禁止' : 'No LLM Shell Strings',
      desc: language === 'ko' ? 'SafeExecutor는 shell=False 및 승인된 인자 벡터(argument vector)만 실행합니다.' : language === 'ja' ? 'SafeExecutorはshell=Falseおよび事前承認された引数配列のみを実行します。' : 'SafeExecutor enforces shell=False and argument vector execution only.',
      verified: true,
    },
    {
      num: 6,
      title: language === 'ko' ? '원천 시크릿 로깅 금지 (Zero Raw Secrets)' : language === 'ja' ? '認証情報の平文ログ記録禁止' : 'Zero Raw Secret Logging',
      desc: language === 'ko' ? '모든 감사 싱크는 원천 비밀값을 비가역 소독하고 SHA-256 지문과 메타데이터만 기록합니다.' : language === 'ja' ? 'すべてのログ出力は平文シークレットを不可逆マスキングしハッシュのみ記録します。' : 'All audit sinks redact secrets and log sha256 fingerprints/metadata only.',
      verified: true,
    },
  ];

  const tools = [
    { name: 'read_file', tier: 'Filesystem Firewall', scope: '/workspace/**', timeout: '2.0s', maxOutput: '64 KB' },
    { name: 'write_file', tier: 'Filesystem Firewall', scope: '/workspace/output/**', timeout: '2.0s', maxOutput: '64 KB' },
    { name: 'execute_process', tier: 'Process SafeExecutor', scope: 'python.exe (Approved Vector only)', timeout: '5.0s', maxOutput: '1 MB' },
    { name: 'http_request', tier: 'Network Firewall', scope: 'https://api.trusted.internal/**', timeout: '5.0s', maxOutput: '512 KB' },
  ];

  const rawYamlPolicy = `version: "1.0.0"
bundle_id: "aisec-policy-prod-2026"
signer: "ed25519:7df4ff00dbe9...9dbdcf"
created_at: "2026-09-11T22:00:00Z"
mode: "READ_ONLY"

rules:
  - id: "RUL_INJ_001"
    match: "prompt.injection"
    action: "DENY"
    reason_code: "PROMPT_INJECTION_DETECTED"
    risk_score: 95

  - id: "RUL_SYS_002"
    match: "system.override"
    action: "DENY"
    reason_code: "SYSTEM_OVERRIDE"
    risk_score: 100

  - id: "RUL_PII_003"
    match: "output.pii"
    action: "SANITIZE"
    reason_code: "PII_REDACTED"
    risk_score: 30

  - id: "RUL_TOOL_004"
    match: "tool.unauthorized"
    action: "DENY"
    reason_code: "TOOL_UNAUTHORIZED"
    risk_score: 100`;

  return (
    <div className="space-y-6 font-mono">
      {/* Header */}
      <div className="glass-panel p-5 rounded-xl">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <FileCode className="w-5 h-5 text-[#00F0FF]" />
              <h2 className="font-['Space_Grotesk'] text-base font-bold text-white tracking-wider">
                {t('policy_title')}
              </h2>
            </div>
            <p className="text-xs text-[#849495]">
              {t('policy_sub')}
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="px-2.5 py-1 rounded bg-[#00FF9D]/15 border border-[#00FF9D]/30 text-[#00FF9D] text-xs font-bold">
              {t('signature_ok')}
            </span>
          </div>
        </div>

        {/* Section Tabs */}
        <div className="flex gap-2 mt-4 pt-3 border-t border-white/5 text-xs">
          <button
            onClick={() => setActiveSection('rules')}
            className={`px-3 py-1.5 rounded transition-colors cursor-pointer ${
              activeSection === 'rules'
                ? 'bg-[#00F0FF]/20 text-[#00F0FF] font-bold border border-[#00F0FF]/40'
                : 'text-[#849495] hover:text-white'
            }`}
          >
            {t('tab_controls')}
          </button>
          <button
            onClick={() => setActiveSection('grants')}
            className={`px-3 py-1.5 rounded transition-colors cursor-pointer ${
              activeSection === 'grants'
                ? 'bg-[#00F0FF]/20 text-[#00F0FF] font-bold border border-[#00F0FF]/40'
                : 'text-[#849495] hover:text-white'
            }`}
          >
            {t('tab_grants')}
          </button>
          <button
            onClick={() => setActiveSection('yaml')}
            className={`px-3 py-1.5 rounded transition-colors cursor-pointer ${
              activeSection === 'yaml'
                ? 'bg-[#00F0FF]/20 text-[#00F0FF] font-bold border border-[#00F0FF]/40'
                : 'text-[#849495] hover:text-white'
            }`}
          >
            {t('tab_yaml')}
          </button>
        </div>
      </div>

      {/* View: Non-Negotiable Controls */}
      {activeSection === 'rules' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {controls.map((c) => (
            <div key={c.num} className="glass-panel p-4 rounded-xl border border-white/10">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-bold text-[#00F0FF]">RULE 0{c.num}</span>
                <span className="flex items-center gap-1 text-[11px] text-[#00FF9D] font-bold">
                  <CheckCircle2 className="w-3.5 h-3.5" /> ENFORCED
                </span>
              </div>
              <h3 className="font-['Space_Grotesk'] text-sm font-bold text-white mb-1">
                {c.title}
              </h3>
              <p className="text-xs text-[#849495] leading-relaxed">
                {c.desc}
              </p>
            </div>
          ))}
        </div>
      )}

      {/* View: Tool Grants */}
      {activeSection === 'grants' && (
        <div className="glass-panel p-5 rounded-xl">
          <h3 className="text-xs font-bold text-[#849495] uppercase mb-3">
            Whitelisted Tool Capabilities (Least Privilege)
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="text-[#849495] border-b border-white/10 pb-2">
                  <th className="pb-2">TOOL NAME</th>
                  <th className="pb-2">RESOURCE TIER</th>
                  <th className="pb-2">BOUNDED SCOPE</th>
                  <th className="pb-2">TIMEOUT</th>
                  <th className="pb-2 text-right">OUTPUT CAP</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {tools.map((tItem, idx) => (
                  <tr key={idx} className="hover:bg-white/5">
                    <td className="py-2.5 font-bold text-[#00FF9D]">{tItem.name}</td>
                    <td className="py-2.5 text-white">{tItem.tier}</td>
                    <td className="py-2.5 text-[#00F0FF]">{tItem.scope}</td>
                    <td className="py-2.5 text-[#849495]">{tItem.timeout}</td>
                    <td className="py-2.5 text-right text-white">{tItem.maxOutput}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* View: Raw YAML */}
      {activeSection === 'yaml' && (
        <div className="glass-panel p-5 rounded-xl">
          <div className="flex items-center justify-between mb-3 text-xs text-[#849495]">
            <span>STORE: READ_ONLY regular file (No follow symlinks)</span>
            <span className="text-[#00FF9D]">SHA256: 7df4ff00dbe9abcbde09141e</span>
          </div>
          <pre className="p-4 bg-[#04080E] border border-white/10 rounded-lg text-xs text-[#00FF9D] overflow-x-auto leading-relaxed">
            {rawYamlPolicy}
          </pre>
        </div>
      )}
    </div>
  );
};
