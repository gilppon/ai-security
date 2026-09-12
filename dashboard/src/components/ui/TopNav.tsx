"use client";

import React from 'react';
import { Shield, Activity, HardDrive, Cpu, Radio, RefreshCw, Zap, Globe } from 'lucide-react';
import { useLanguage, Language } from '@/context/LanguageContext';

interface TopNavProps {
  isOnline: boolean;
  eventCount: number;
  blockedCount: number;
  isDemoFeed: boolean;
  onToggleDemoFeed: () => void;
  onRefresh: () => void;
  isLanding?: boolean;
  onToggleLanding?: () => void;
}

export const TopNav: React.FC<TopNavProps> = ({
  isOnline,
  eventCount,
  blockedCount,
  isDemoFeed,
  onToggleDemoFeed,
  onRefresh,
  isLanding = false,
  onToggleLanding,
}) => {
  const { language, setLanguage, t } = useLanguage();
  const blockRate = eventCount > 0 ? ((blockedCount / eventCount) * 100).toFixed(1) : '100.0';

  const languages: Array<{ code: Language; label: string }> = [
    { code: 'ko', label: 'KO' },
    { code: 'en', label: 'EN' },
    { code: 'ja', label: 'JA' },
  ];

  return (
    <header className="sticky top-0 z-50 glass-panel border-b border-[#00F0FF]/15 px-6 py-3.5">
      <div className="max-w-[1600px] mx-auto flex flex-wrap items-center justify-between gap-4">
        {/* Brand & Identity */}
        <div className="flex items-center gap-3">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-lg bg-[#00F0FF]/10 border border-[#00F0FF]/30 text-[#00F0FF]">
            <Shield className="w-5 h-5" />
            <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-[#00FF9D] animate-ping" />
            <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-[#00FF9D]" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="font-['Space_Grotesk'] text-lg font-bold tracking-wider text-white">
                {t('app_title')} <span className="text-[#00F0FF]">{t('app_subtitle')}</span>
              </h1>
              <span className="px-2 py-0.5 text-[10px] font-mono font-semibold rounded bg-[#00F0FF]/15 text-[#00F0FF] border border-[#00F0FF]/30">
                PROD v1.0
              </span>
            </div>
            <p className="text-xs text-[#849495] font-mono tracking-tight">
              {t('gate_status')}
            </p>
          </div>
        </div>

        {/* Global Control Plane Badges & Controls */}
        <div className="flex items-center flex-wrap gap-3 text-xs font-mono">
          {/* Language Switcher */}
          <div className="flex items-center gap-1 rounded-md bg-[#08101A] border border-[#00F0FF]/30 p-1">
            <Globe className="w-3.5 h-3.5 text-[#00F0FF] ml-1 mr-0.5" />
            {languages.map((l) => (
              <button
                key={l.code}
                onClick={() => setLanguage(l.code)}
                className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono transition-all cursor-pointer ${
                  language === l.code
                    ? 'bg-[#00F0FF] text-[#04080E] shadow-[0_0_8px_rgba(0,240,255,0.4)]'
                    : 'text-[#849495] hover:text-white hover:bg-white/5'
                }`}
              >
                {l.label}
              </button>
            ))}
          </div>

          {/* Core Status */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-[#08101A] border border-[#00F0FF]/15">
            <Activity className={`w-3.5 h-3.5 ${isOnline ? 'text-[#00FF9D]' : 'text-[#FF0055]'}`} />
            <span className="text-[#849495]">{t('core')}:</span>
            <span className={isOnline ? 'text-[#00FF9D] font-bold' : 'text-[#FF0055] font-bold'}>
              {isOnline ? t('online') : t('offline')}
            </span>
          </div>

          {/* Latency Gate */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-[#08101A] border border-[#00F0FF]/15">
            <Zap className="w-3.5 h-3.5 text-[#00F0FF]" />
            <span className="text-[#849495]">{t('latency')}:</span>
            <span className="text-[#00F0FF] font-semibold">{t('latency_val')}</span>
          </div>

          {/* R2 WORM Replica */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-[#08101A] border border-[#00F0FF]/15">
            <HardDrive className="w-3.5 h-3.5 text-[#00FF9D]" />
            <span className="text-[#849495]">{t('r2_worm')}:</span>
            <span className="text-[#00FF9D] font-semibold">{t('synced')}</span>
          </div>

          {/* Total & Block Rate */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-[#08101A] border border-[#00F0FF]/15">
            <Cpu className="w-3.5 h-3.5 text-[#FFB800]" />
            <span className="text-[#849495]">{t('total')}:</span>
            <span className="text-white font-semibold">{eventCount}</span>
            <span className="text-[#849495]">| {t('block_rate')}:</span>
            <span className="text-[#FF0055] font-bold">{blockRate}%</span>
          </div>

          {/* Data Source Mode Toggle (LIVE vs MOCK) */}
          <button
            onClick={onToggleDemoFeed}
            title={isDemoFeed ? t('switch_to_live_btn') : t('switch_to_demo_btn')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-md border text-xs font-mono transition-all cursor-pointer ${
              isDemoFeed
                ? 'bg-[#FFB800]/15 border-[#FFB800]/50 text-[#FFB800] shadow-[0_0_12px_rgba(255,184,0,0.25)] hover:bg-[#FFB800]/25'
                : 'bg-[#00FF9D]/15 border-[#00FF9D]/50 text-[#00FF9D] shadow-[0_0_12px_rgba(0,255,157,0.25)] hover:bg-[#00FF9D]/25'
            }`}
          >
            {isDemoFeed ? (
              <>
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#FFB800] opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-[#FFB800]"></span>
                </span>
                <span className="font-bold">{t('demo_mode_active')}</span>
              </>
            ) : (
              <>
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#00FF9D] opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-[#00FF9D]"></span>
                </span>
                <span className="font-bold">{t('live_mode_active')}</span>
              </>
            )}
          </button>

          {/* Refresh */}
          <button
            onClick={onRefresh}
            title={t('refresh')}
            className="p-1.5 rounded-md bg-[#08101A] border border-[#00F0FF]/20 text-[#00F0FF] hover:bg-[#00F0FF]/10 transition-colors cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>

          {/* Landing / SOC Toggle Button */}
          {onToggleLanding && (
            <button
              onClick={onToggleLanding}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-mono text-xs font-bold transition-all cursor-pointer ${
                isLanding
                  ? 'bg-gradient-to-r from-[#00F0FF] to-[#00FF9D] text-black shadow-[0_0_15px_rgba(0,240,255,0.4)] hover:opacity-95'
                  : 'bg-white/10 border border-white/20 text-white hover:bg-white/15'
              }`}
            >
              <span>{isLanding ? (language === 'ko' ? 'SOC 관제탑 ->' : 'Launch SOC ->') : (language === 'ko' ? '<- 쇼룸 홈' : '<- Showcase')}</span>
            </button>
          )}
        </div>
      </div>
    </header>
  );
};
