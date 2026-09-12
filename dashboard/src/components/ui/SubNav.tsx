"use client";

import React from 'react';
import { Radar, GitCommit, Crosshair, Database, FileCode, Sparkles } from 'lucide-react';
import { useLanguage } from '@/context/LanguageContext';

export type ViewTab = 'landing' | 'radar' | 'pipeline' | 'simulator' | 'worm' | 'policy';

interface SubNavProps {
  activeTab: ViewTab;
  onChangeTab: (tab: ViewTab) => void;
}

export const SubNav: React.FC<SubNavProps> = ({ activeTab, onChangeTab }) => {
  const { t, language } = useLanguage();
  const isKo = language === 'ko';

  const tabs: Array<{ id: ViewTab; label: string; icon: React.ReactNode; badge?: string }> = [
    { id: 'landing', label: isKo ? '쇼룸 (Showcase)' : 'Showcase', icon: <Sparkles className="w-4 h-4 text-[#00FF9D]" />, badge: 'LANDING' },
    { id: 'radar', label: t('tab_radar'), icon: <Radar className="w-4 h-4" /> },
    { id: 'pipeline', label: t('tab_pipeline'), icon: <GitCommit className="w-4 h-4" />, badge: t('badge_8steps') },
    { id: 'simulator', label: t('tab_simulator'), icon: <Crosshair className="w-4 h-4" />, badge: t('badge_live') },
    { id: 'worm', label: t('tab_worm'), icon: <Database className="w-4 h-4" />, badge: 'SHA-256' },
    { id: 'policy', label: t('tab_policy'), icon: <FileCode className="w-4 h-4" />, badge: 'Ed25519' },
  ];

  return (
    <nav className="border-b border-[#00F0FF]/15 px-6 pt-4 pb-0 bg-[#04080E]/60 backdrop-blur-md">
      <div className="max-w-[1600px] mx-auto flex items-center gap-2 overflow-x-auto no-scrollbar">
        {tabs.map((tab) => {
          const isActive = activeTab === tab.id;

          return (
            <button
              key={tab.id}
              onClick={() => onChangeTab(tab.id)}
              className={`flex items-center gap-2.5 px-5 py-3 font-mono text-xs font-semibold uppercase tracking-wider border-b-2 transition-all cursor-pointer whitespace-nowrap ${
                isActive
                  ? 'border-[#00F0FF] text-[#00F0FF] bg-[#00F0FF]/10 shadow-[inset_0_-2px_8px_rgba(0,240,255,0.2)]'
                  : 'border-transparent text-[#849495] hover:text-white hover:bg-white/[0.03]'
              }`}
            >
              {tab.icon}
              <span>{tab.label}</span>
              {tab.badge && (
                <span
                  className={`px-1.5 py-0.5 text-[9px] rounded font-bold ${
                    isActive
                      ? 'bg-[#00F0FF]/25 text-[#00F0FF]'
                      : 'bg-[#849495]/20 text-[#849495]'
                  }`}
                >
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>
    </nav>
  );
};
