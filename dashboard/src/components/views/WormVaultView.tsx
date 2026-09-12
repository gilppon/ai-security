"use client";

import React, { useState } from 'react';
import { Database, CheckCircle2, HardDrive, Lock, ArrowDown, RefreshCw, Key } from 'lucide-react';
import { useLanguage } from '@/context/LanguageContext';

export const WormVaultView: React.FC = () => {
  const { t } = useLanguage();
  const [verifying, setVerifying] = useState(false);
  const [verifiedCount, setVerifiedCount] = useState<number>(342);

  const mockBlocks = [
    {
      seq: 342,
      hash: '3e68da3b02da03182f9a5a059341d69c570c0735',
      prevHash: 'fce6b5e7719d2a0991823719284712903847291a',
      time: '2026-09-11T22:30:15Z',
      records: 12,
      status: 'VERIFIED_IN_R2',
      event: 'output.scan [SECRET_LEAK_PREVENTED]',
    },
    {
      seq: 341,
      hash: 'fce6b5e7719d2a0991823719284712903847291a',
      prevHash: 'd42fee16489b091820491827401928374019283b',
      time: '2026-09-11T22:28:44Z',
      records: 8,
      status: 'VERIFIED_IN_R2',
      event: 'prompt.scan [PROMPT_INJECTION_DETECTED]',
    },
    {
      seq: 340,
      hash: 'd42fee16489b091820491827401928374019283b',
      prevHash: '8d2c95f0edac58921426bb165ee405944768431d',
      time: '2026-09-11T22:24:10Z',
      records: 24,
      status: 'VERIFIED_IN_R2',
      event: 'content.scan [RAG_POISONING_BLOCKED]',
    },
    {
      seq: 339,
      hash: '8d2c95f0edac58921426bb165ee405944768431d',
      prevHash: 'GENESIS_ANCHOR_PHASE10_INIT',
      time: '2026-09-11T22:00:00Z',
      records: 1,
      status: 'GENESIS_LOCKED',
      event: 'system.bootstrap [WORM_CHAIN_GENESIS]',
    },
  ];

  const handleVerifyChain = () => {
    setVerifying(true);
    setTimeout(() => {
      setVerifying(false);
      setVerifiedCount((prev) => prev + 1);
    }, 600);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="glass-panel p-5 rounded-xl">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <Database className="w-5 h-5 text-[#00FF9D]" />
              <h2 className="font-['Space_Grotesk'] text-base font-bold text-white tracking-wider">
                {t('worm_title')}
              </h2>
            </div>
            <p className="text-xs font-mono text-[#849495]">
              {t('worm_sub')}
            </p>
          </div>

          <button
            onClick={handleVerifyChain}
            disabled={verifying}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#00FF9D]/15 border border-[#00FF9D]/40 text-[#00FF9D] font-mono text-xs font-bold hover:bg-[#00FF9D]/25 transition-all cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${verifying ? 'animate-spin' : ''}`} />
            <span>{verifying ? t('verifying_chain') : t('verify_chain_btn')}</span>
          </button>
        </div>
      </div>

      {/* Durability Contracts Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
        <div className="glass-panel p-4 rounded-xl border border-[#00FF9D]/25">
          <div className="flex items-center gap-2 text-[#00FF9D] font-bold mb-1">
            <CheckCircle2 className="w-4 h-4" />
            <span>{t('hash_chain_label')}</span>
          </div>
          <p className="text-white text-sm font-bold mt-2">
            {verifiedCount} Blocks Verified
          </p>
          <p className="text-[11px] text-[#849495] mt-1">
            Zero gaps, zero tampering. Multi-process cross-lock protected.
          </p>
        </div>

        <div className="glass-panel p-4 rounded-xl border border-[#00F0FF]/25">
          <div className="flex items-center gap-2 text-[#00F0FF] font-bold mb-1">
            <HardDrive className="w-4 h-4" />
            <span>{t('r2_worm_label')}</span>
          </div>
          <p className="text-white text-sm font-bold mt-2">
            Put-Once / Locked
          </p>
          <p className="text-[11px] text-[#849495] mt-1">
            403 Forbidden enforced on DELETE. Remote replica requirement active.
          </p>
        </div>

        <div className="glass-panel p-4 rounded-xl border border-[#B259FF]/25">
          <div className="flex items-center gap-2 text-[#B259FF] font-bold mb-1">
            <Key className="w-4 h-4" />
            <span>{t('redacted_secrets_label')}</span>
          </div>
          <p className="text-white text-sm font-bold mt-2">
            100% Zero Raw Credentials
          </p>
          <p className="text-[11px] text-[#849495] mt-1">
            Hashes, fingerprints &amp; metadata only. Complies with rule 11.
          </p>
        </div>
      </div>

      {/* Cryptographic Chain Visualization */}
      <div className="glass-panel p-6 rounded-xl">
        <h3 className="font-mono text-xs font-bold text-[#849495] uppercase mb-4 tracking-wider">
          {t('block_seq_title')}
        </h3>

        <div className="space-y-4 font-mono">
          {mockBlocks.map((block, idx) => (
            <React.Fragment key={block.seq}>
              <div className="p-4 rounded-xl bg-[#08101A] border border-white/10 hover:border-[#00FF9D]/40 transition-all">
                <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded bg-[#00FF9D]/15 text-[#00FF9D] font-bold text-xs">
                      BLOCK #{block.seq}
                    </span>
                    <span className="text-xs text-white font-semibold">{block.event}</span>
                  </div>

                  <span className="text-[11px] text-[#849495]">{block.time}</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] text-[#849495]">
                  <div>
                    <span className="text-[#849495]">BLOCK HASH: </span>
                    <span className="text-[#00F0FF]">{block.hash}</span>
                  </div>
                  <div>
                    <span className="text-[#849495]">PREV HASH: </span>
                    <span className="text-[#849495]">{block.prevHash}</span>
                  </div>
                </div>

                <div className="mt-2 pt-2 border-t border-white/5 flex items-center justify-between text-[11px]">
                  <span className="text-[#849495]">{block.records} audited records inside</span>
                  <span className="text-[#00FF9D] font-bold flex items-center gap-1">
                    <Lock className="w-3 h-3" /> {block.status}
                  </span>
                </div>
              </div>

              {idx < mockBlocks.length - 1 && (
                <div className="flex justify-center -my-2 text-[#00FF9D]/40">
                  <ArrowDown className="w-4 h-4" />
                </div>
              )}
            </React.Fragment>
          ))}
        </div>
      </div>
    </div>
  );
};
