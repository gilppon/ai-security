"use client";

import React, { useState } from 'react';
import { SecurityEventData } from '@/lib/types';
import { GitCommit, ArrowRight } from 'lucide-react';
import { useLanguage } from '@/context/LanguageContext';

interface PipelineInspectorViewProps {
  selectedEvent: SecurityEventData | null;
  allEvents: SecurityEventData[];
  onSelectEvent: (event: SecurityEventData) => void;
}

export const PipelineInspectorView: React.FC<PipelineInspectorViewProps> = ({
  selectedEvent,
  allEvents,
  onSelectEvent,
}) => {
  const { t } = useLanguage();

  const activeEvt = selectedEvent || allEvents[0] || {
    event_id: 'evt_sample_clean',
    event_type: 'prompt.scan',
    decision: 'ALLOW' as const,
    risk_score: 0,
    reason_codes: ['PROMPT_CLEAN'],
    length: 34,
    fingerprint: '631687f4012fbef5',
  };

  const isDeny = activeEvt.decision === 'DENY' || activeEvt.decision === 'TERMINATE';
  const isSanitize = activeEvt.decision === 'SANITIZE';

  const [activeStepIndex, setActiveStepIndex] = useState<number>(6); // Default on Decision

  const pipelineSteps = [
    {
      num: 1,
      name: 'SecurityEvent',
      desc: 'Untrusted Payload Ingestion',
      detail: `Wrapped as immutable event (${activeEvt.event_type}). Untrusted caller boundaries enforced.`,
      status: 'passed',
      meta: { event_id: activeEvt.event_id, type: activeEvt.event_type },
    },
    {
      num: 2,
      name: 'Normalize',
      desc: 'Canonical UTF-8 & Stripping',
      detail: 'Zero-width unicode, homoglyph confusables, and control characters canonicalized.',
      status: 'passed',
      meta: { normalization_changed: false, fingerprint: activeEvt.fingerprint || 'e3b0c44298fc1c14' },
    },
    {
      num: 3,
      name: 'Context',
      desc: 'Provenance & Capabilities',
      detail: 'Session boundary evaluated. Default-deny trust context bound to verified agent identity.',
      status: 'passed',
      meta: { trust_level: 'UNTRUSTED', session_bound: true },
    },
    {
      num: 4,
      name: 'Detect',
      desc: 'Heuristics, PII, Secrets, AST',
      detail: isDeny
        ? `Threat detected: ${activeEvt.reason_codes.join(', ')}`
        : isSanitize
        ? 'PII patterns identified for deterministic redaction.'
        : 'All zero-trust heuristics clean. No signature matches.',
      status: isDeny ? 'blocked' : isSanitize ? 'warning' : 'passed',
      meta: { findings_count: activeEvt.findings?.length || 0 },
    },
    {
      num: 5,
      name: 'Risk',
      desc: 'Bounded Additive Scoring',
      detail: `Cumulative score computed: ${activeEvt.risk_score} / 100. Bounds strictly enforced [0, 100].`,
      status: isDeny ? 'blocked' : isSanitize ? 'warning' : 'passed',
      meta: { risk_score: activeEvt.risk_score, ceiling: 100 },
    },
    {
      num: 6,
      name: 'Policy',
      desc: 'Ed25519 Signed AISec YAML',
      detail: 'Deterministic evaluation against immutable signed bundle. Unknown states fail closed.',
      status: 'passed',
      meta: { policy_signature: 'Ed25519_VERIFIED', store_mode: 'READ_ONLY' },
    },
    {
      num: 7,
      name: 'Decision',
      desc: 'Deterministic Action Gate',
      detail: `Final Action: ${activeEvt.decision}. Reason codes: ${activeEvt.reason_codes.join(', ')}.`,
      status: isDeny ? 'blocked' : isSanitize ? 'warning' : 'passed',
      meta: { decision: activeEvt.decision, reasons: activeEvt.reason_codes },
    },
    {
      num: 8,
      name: 'Audit',
      desc: 'WORM Chain & R2 Sync',
      detail: 'Sha-256 hash appended to local tamper-proof chain. Zero raw secrets logged.',
      status: 'passed',
      meta: { redaction: 'ENFORCED', chain_tamper_proof: true, r2_replicated: true },
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header & Event Selector */}
      <div className="glass-panel p-5 rounded-xl">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <GitCommit className="w-5 h-5 text-[#00F0FF]" />
              <h2 className="font-['Space_Grotesk'] text-base font-bold text-white tracking-wider">
                {t('inspector_title')}
              </h2>
            </div>
            <p className="text-xs font-mono text-[#849495]">
              {t('inspector_sub')}
            </p>
          </div>

          {/* Target Event Selector */}
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-[#849495]">{t('inspecting_event')}</span>
            {activeEvt.is_mock ? (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-[#FFB800]/15 text-[#FFB800] border border-[#FFB800]/30">
                <span className="w-1.5 h-1.5 rounded-full bg-[#FFB800]" />
                {t('badge_mock')}
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-[#00FF9D]/15 text-[#00FF9D] border border-[#00FF9D]/40 shadow-[0_0_8px_rgba(0,255,157,0.3)]">
                <span className="relative flex h-1.5 w-1.5">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#00FF9D] opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-[#00FF9D]"></span>
                </span>
                {t('badge_live')}
              </span>
            )}
            <select
              value={activeEvt.event_id}
              onChange={(e) => {
                const target = allEvents.find((evt) => evt.event_id === e.target.value);
                if (target) onSelectEvent(target);
              }}
              className="bg-[#08101A] border border-[#00F0FF]/30 text-white rounded-lg px-3 py-1.5 text-xs font-mono focus:outline-none focus:border-[#00F0FF]"
            >
              {allEvents.map((e) => (
                <option key={e.event_id} value={e.event_id}>
                  [{e.is_mock ? 'MOCK' : 'LIVE'}] [{e.decision}] {e.event_type} - {e.event_id.substring(0, 12)}...
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* 8-Node Flow Diagram (Horizontal Spatial Timeline) */}
      <div className="glass-panel p-6 rounded-xl overflow-x-auto">
        <div className="flex items-center justify-between min-w-[900px] gap-2">
          {pipelineSteps.map((step, idx) => {
            const isSelected = activeStepIndex === idx;
            const isLast = idx === pipelineSteps.length - 1;

            let badgeColor = 'border-[#00FF9D]/40 text-[#00FF9D] bg-[#00FF9D]/10';
            if (step.status === 'blocked') {
              badgeColor = 'border-[#FF0055] text-[#FF0055] bg-[#FF0055]/15 animate-pulse';
            } else if (step.status === 'warning') {
              badgeColor = 'border-[#FFB800] text-[#FFB800] bg-[#FFB800]/15';
            }

            return (
              <React.Fragment key={step.name}>
                <div
                  onClick={() => setActiveStepIndex(idx)}
                  className={`flex-1 p-3.5 rounded-xl border transition-all cursor-pointer text-center relative ${
                    isSelected
                      ? 'bg-[#00F0FF]/15 border-[#00F0FF] shadow-[0_0_15px_rgba(0,240,255,0.25)] scale-105 z-10'
                      : 'bg-[#08101A] border-white/10 hover:border-[#00F0FF]/40'
                  }`}
                >
                  <div className="text-[10px] font-mono text-[#849495] mb-1">
                    STEP 0{step.num}
                  </div>
                  <div className="font-['Space_Grotesk'] text-xs font-bold text-white mb-2">
                    {step.name}
                  </div>
                  <div className={`inline-block px-2 py-0.5 rounded text-[10px] font-mono font-bold ${badgeColor}`}>
                    {step.status.toUpperCase()}
                  </div>
                </div>

                {!isLast && (
                  <ArrowRight className="w-4 h-4 text-[#00F0FF]/40 shrink-0" />
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* Active Step Deep Inspector Card */}
      {pipelineSteps[activeStepIndex] && (
        <div className="glass-panel p-6 rounded-xl border border-[#00F0FF]/30">
          <div className="flex flex-wrap items-center justify-between gap-3 mb-4 pb-3 border-b border-white/10">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-[#00F0FF]/20 border border-[#00F0FF] flex items-center justify-center text-[#00F0FF] font-bold font-mono text-sm">
                0{pipelineSteps[activeStepIndex].num}
              </div>
              <div>
                <h3 className="text-base font-bold font-['Space_Grotesk'] text-white">
                  Stage {pipelineSteps[activeStepIndex].num}: {pipelineSteps[activeStepIndex].name}
                </h3>
                <p className="text-xs font-mono text-[#849495]">
                  {pipelineSteps[activeStepIndex].desc}
                </p>
              </div>
            </div>

            <div className="font-mono text-xs text-[#00F0FF]">
              {t('exec_latency')}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <h4 className="text-xs font-mono text-[#849495] uppercase mb-2">
                {t('stage_eval_detail')}
              </h4>
              <p className="text-sm text-white font-mono leading-relaxed bg-[#08101A] p-4 rounded-lg border border-white/5">
                {pipelineSteps[activeStepIndex].detail}
              </p>
            </div>

            <div>
              <h4 className="text-xs font-mono text-[#849495] uppercase mb-2">
                {t('stage_artifacts')}
              </h4>
              <pre className="text-xs font-mono text-[#00FF9D] bg-[#08101A] p-4 rounded-lg border border-white/5 overflow-x-auto">
                {JSON.stringify(pipelineSteps[activeStepIndex].meta, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
