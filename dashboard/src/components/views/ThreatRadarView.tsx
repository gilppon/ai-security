"use client";

import React, { useState } from 'react';
import { SecurityEventData } from '@/lib/types';
import { Shield, AlertTriangle, CheckCircle2, XCircle, Filter, Zap, Terminal } from 'lucide-react';
import { useLanguage } from '@/context/LanguageContext';

interface ThreatRadarViewProps {
  events: SecurityEventData[];
  onSelectEvent: (event: SecurityEventData) => void;
  isDemoFeed: boolean;
  onToggleDemoFeed: () => void;
}

export const ThreatRadarView: React.FC<ThreatRadarViewProps> = ({
  events,
  onSelectEvent,
  isDemoFeed,
  onToggleDemoFeed,
}) => {
  const { t } = useLanguage();
  const [filter, setFilter] = useState<'ALL' | 'DENY' | 'ALLOW' | 'SANITIZE'>('ALL');

  const filteredEvents = events.filter((e) => {
    if (filter === 'ALL') return true;
    return e.decision === filter;
  });

  const tiers = [
    { name: t('tier_prompt'), phase: 'Phase 2', desc: t('tier_prompt_desc'), color: '#00F0FF' },
    { name: t('tier_content'), phase: 'Phase 3', desc: t('tier_content_desc'), color: '#00FF9D' },
    { name: t('tier_tool'), phase: 'Phase 4', desc: t('tier_tool_desc'), color: '#00F0FF' },
    { name: t('tier_mcp'), phase: 'Phase 4', desc: t('tier_mcp_desc'), color: '#B259FF' },
    { name: t('tier_output'), phase: 'Phase 5', desc: t('tier_output_desc'), color: '#FFB800' },
    { name: t('tier_resource'), phase: 'Phase 6', desc: t('tier_resource_desc'), color: '#00FF9D' },
    { name: t('tier_runtime'), phase: 'Phase 7', desc: t('tier_runtime_desc'), color: '#FF0055' },
    { name: t('tier_redteam'), phase: 'Phase 8', desc: t('tier_redteam_desc'), color: '#00F0FF' },
  ];

  return (
    <div className="space-y-6">
      {/* 8-Tier Defense Perimeter Grid */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-[#00F0FF]" />
            <h2 className="font-mono text-sm font-bold tracking-wider uppercase text-white">
              {t('perimeter_title')}
            </h2>
          </div>
          <span className="font-mono text-xs text-[#849495]">
            {t('perimeter_sub')}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3.5">
          {tiers.map((tier, idx) => (
            <div
              key={idx}
              className="glass-panel glass-panel-interactive p-4 rounded-xl relative overflow-hidden"
            >
              <div
                className="absolute top-0 left-0 w-1 h-full"
                style={{ backgroundColor: tier.color }}
              />
              <div className="flex items-center justify-between text-xs font-mono text-[#849495] mb-1.5">
                <span>{tier.phase}</span>
                <span className="px-1.5 py-0.2 rounded bg-[#00FF9D]/10 text-[#00FF9D] font-bold text-[10px]">
                  {t('shielded')}
                </span>
              </div>
              <h3 className="font-['Space_Grotesk'] text-sm font-bold text-white mb-1">
                {tier.name}
              </h3>
              <p className="text-xs text-[#849495] leading-relaxed line-clamp-2">
                {tier.desc}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Data Source Notice Banner */}
      <div
        className={`p-4 rounded-xl border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 transition-all ${
          isDemoFeed
            ? 'bg-[#FFB800]/10 border-[#FFB800]/40 text-[#FFB800]'
            : 'bg-[#00FF9D]/10 border-[#00FF9D]/40 text-[#00FF9D]'
        }`}
      >
        <div className="flex items-center gap-3">
          <span className="relative flex h-3 w-3 shrink-0">
            <span
              className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                isDemoFeed ? 'bg-[#FFB800]' : 'bg-[#00FF9D]'
              }`}
            />
            <span
              className={`relative inline-flex rounded-full h-3 w-3 ${
                isDemoFeed ? 'bg-[#FFB800]' : 'bg-[#00FF9D]'
              }`}
            />
          </span>
          <div>
            <div className="font-mono text-xs font-bold uppercase tracking-wider">
              {isDemoFeed ? t('demo_mode_active') : t('live_mode_active')}
            </div>
            <p className="text-xs text-[#D5E5F2]/80 mt-0.5 font-sans leading-relaxed">
              {isDemoFeed ? t('demo_mode_desc') : t('live_mode_desc')}
            </p>
          </div>
        </div>

        <button
          onClick={onToggleDemoFeed}
          className={`shrink-0 px-3 py-1.5 rounded-lg font-mono text-xs font-bold border transition-all cursor-pointer ${
            isDemoFeed
              ? 'bg-[#00FF9D]/15 border-[#00FF9D]/40 text-[#00FF9D] hover:bg-[#00FF9D]/25 shadow-[0_0_10px_rgba(0,255,157,0.2)]'
              : 'bg-[#FFB800]/15 border-[#FFB800]/40 text-[#FFB800] hover:bg-[#FFB800]/25 shadow-[0_0_10px_rgba(255,184,0,0.2)]'
          }`}
        >
          {isDemoFeed ? t('switch_to_live_btn') : t('switch_to_demo_btn')}
        </button>
      </div>

      {/* Latency & Metrics Radar Strip */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3.5">
        <div className="glass-panel p-4 rounded-xl">
          <div className="text-xs font-mono text-[#849495] mb-1 flex items-center justify-between">
            <span>{t('metric_latency')}</span>
            <Zap className="w-3.5 h-3.5 text-[#00FF9D]" />
          </div>
          <div className="text-2xl font-bold font-mono text-[#00FF9D]">1.0 ms</div>
          <p className="text-[11px] text-[#849495] mt-1">{t('metric_latency_desc')}</p>
        </div>

        <div className="glass-panel p-4 rounded-xl">
          <div className="text-xs font-mono text-[#849495] mb-1 flex items-center justify-between">
            <span>{t('metric_total')}</span>
            <Terminal className="w-3.5 h-3.5 text-[#00F0FF]" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">{events.length}</div>
          <p className="text-[11px] text-[#849495] mt-1">{t('metric_total_desc')}</p>
        </div>

        <div className="glass-panel p-4 rounded-xl">
          <div className="text-xs font-mono text-[#849495] mb-1 flex items-center justify-between">
            <span>{t('metric_blocked')}</span>
            <XCircle className="w-3.5 h-3.5 text-[#FF0055]" />
          </div>
          <div className="text-2xl font-bold font-mono text-[#FF0055]">
            {events.filter((e) => e.decision === 'DENY' || e.decision === 'TERMINATE').length}
          </div>
          <p className="text-[11px] text-[#849495] mt-1">{t('metric_blocked_desc')}</p>
        </div>

        <div className="glass-panel p-4 rounded-xl">
          <div className="text-xs font-mono text-[#849495] mb-1 flex items-center justify-between">
            <span>{t('metric_sanitized')}</span>
            <AlertTriangle className="w-3.5 h-3.5 text-[#FFB800]" />
          </div>
          <div className="text-2xl font-bold font-mono text-[#FFB800]">
            {events.filter((e) => e.decision === 'SANITIZE').length}
          </div>
          <p className="text-[11px] text-[#849495] mt-1">{t('metric_sanitized_desc')}</p>
        </div>
      </div>

      {/* Real-time Rolling Event Stream */}
      <div className="glass-panel rounded-xl p-5">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-4 border-b border-[#00F0FF]/15 pb-3">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#00F0FF] animate-pulse" />
            <h3 className="font-mono text-sm font-bold text-white tracking-wider">
              {t('stream_title')}
            </h3>
          </div>

          {/* Filter Pills */}
          <div className="flex items-center gap-1 text-xs font-mono">
            <Filter className="w-3.5 h-3.5 text-[#849495] mr-1" />
            {(['ALL', 'DENY', 'SANITIZE', 'ALLOW'] as const).map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`px-2.5 py-1 rounded transition-colors cursor-pointer ${
                  filter === f
                    ? 'bg-[#00F0FF]/20 text-[#00F0FF] font-bold border border-[#00F0FF]/40'
                    : 'text-[#849495] hover:text-white hover:bg-white/5'
                }`}
              >
                {f}
              </button>
            ))}
          </div>
        </div>

        {filteredEvents.length === 0 ? (
          <div className="text-center py-12 text-sm font-mono text-[#849495]">
            {t('no_events')}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead>
                <tr className="text-[#849495] border-b border-white/5 pb-2">
                  <th className="pb-2">출처 (SRC)</th>
                  <th className="pb-2">{t('col_decision')}</th>
                  <th className="pb-2">{t('col_type')}</th>
                  <th className="pb-2">{t('col_id')}</th>
                  <th className="pb-2">{t('col_reason')}</th>
                  <th className="pb-2 text-right">{t('col_risk')}</th>
                  <th className="pb-2 text-right">{t('col_action')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {filteredEvents.map((evt, idx) => {
                  const isDeny = evt.decision === 'DENY' || evt.decision === 'TERMINATE';
                  const isSanitize = evt.decision === 'SANITIZE';
                  const isAllow = evt.decision === 'ALLOW' || evt.decision === 'LOG';

                  return (
                    <tr
                      key={`${evt.event_id}-${idx}`}
                      className="hover:bg-[#00F0FF]/5 transition-colors group cursor-pointer"
                      onClick={() => onSelectEvent(evt)}
                    >
                      <td className="py-2.5">
                        {evt.is_mock ? (
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
                      </td>
                      <td className="py-2.5">
                        <span
                          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold ${
                            isDeny
                              ? 'bg-[#FF0055]/15 text-[#FF0055] border border-[#FF0055]/30'
                              : isSanitize
                              ? 'bg-[#FFB800]/15 text-[#FFB800] border border-[#FFB800]/30'
                              : 'bg-[#00FF9D]/15 text-[#00FF9D] border border-[#00FF9D]/30'
                          }`}
                        >
                          {isDeny && <XCircle className="w-3 h-3" />}
                          {isSanitize && <AlertTriangle className="w-3 h-3" />}
                          {isAllow && <CheckCircle2 className="w-3 h-3" />}
                          {evt.decision}
                        </span>
                      </td>
                      <td className="py-2.5 text-white font-semibold">{evt.event_type}</td>
                      <td className="py-2.5 text-[#849495] font-mono text-[11px]">
                        {evt.event_id}
                      </td>
                      <td className="py-2.5">
                        <div className="flex flex-wrap gap-1">
                          {evt.reason_codes.slice(0, 2).map((rc, i) => (
                            <span
                              key={i}
                              className="px-1.5 py-0.5 rounded bg-[#08101A] border border-white/10 text-[10px] text-[#D5E5F2]"
                            >
                              {rc}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="py-2.5 text-right font-bold">
                        <span
                          className={
                            evt.risk_score >= 80
                              ? 'text-[#FF0055]'
                              : evt.risk_score > 0
                              ? 'text-[#FFB800]'
                              : 'text-[#00FF9D]'
                          }
                        >
                          {evt.risk_score} / 100
                        </span>
                      </td>
                      <td className="py-2.5 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectEvent(evt);
                          }}
                          className="px-2 py-1 rounded bg-[#00F0FF]/10 text-[#00F0FF] border border-[#00F0FF]/25 hover:bg-[#00F0FF]/20 text-[11px] font-bold"
                        >
                          {t('trace_btn')}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
