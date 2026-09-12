"use client";

import React from 'react';
import { Zap, Cpu, Server, CheckCircle2 } from 'lucide-react';
import { useLanguage } from '@/context/LanguageContext';

export const BenchmarkChart: React.FC = () => {
  const { language } = useLanguage();
  const isKo = language === 'ko';

  const metrics = [
    {
      label: isKo ? 'P50 지연시간' : 'P50 Latency',
      sdk: '0.110 ms',
      rest: '3.888 ms',
      sdkRatio: 2.8,
      restRatio: 100,
      multiplier: '35.3x',
    },
    {
      label: isKo ? '평균 지연시간' : 'Average Latency',
      sdk: '0.145 ms',
      rest: '4.089 ms',
      sdkRatio: 3.5,
      restRatio: 100,
      multiplier: '28.2x',
    },
    {
      label: isKo ? 'P95 지연시간' : 'P95 Latency',
      sdk: '0.352 ms',
      rest: '5.694 ms',
      sdkRatio: 6.2,
      restRatio: 100,
      multiplier: '16.2x',
    },
    {
      label: isKo ? '초당 처리량' : 'Throughput',
      sdk: '6,878 req/s',
      rest: '244 req/s',
      sdkRatio: 100,
      restRatio: 3.5,
      multiplier: '28.1x',
      invert: true,
    },
  ];

  return (
    <div className="bg-[#0B131E]/80 border border-[#00F0FF]/20 rounded-xl p-6 backdrop-blur-xl shadow-[0_0_30px_rgba(0,240,255,0.06)]">
      <div className="flex items-center justify-between mb-6 pb-4 border-b border-white/10">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#00FF9D]/10 border border-[#00FF9D]/30 flex items-center justify-center text-[#00FF9D]">
            <Zap className="w-5 h-5" />
          </div>
          <div>
            <h3 className="font-mono text-base font-bold text-white tracking-wide flex items-center gap-2">
              {isKo ? '실측 벤치마크: In-Process SDK vs REST API' : 'Empirical Benchmark: SDK vs REST API'}
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[#00FF9D]/20 text-[#00FF9D] border border-[#00FF9D]/30">
                28.2x FASTER
              </span>
            </h3>
            <p className="text-xs text-[#849495] mt-0.5">
              {isKo
                ? '500회 정밀 실측 기준 (HTTP 소켓 오버헤드 및 직렬화 병목 100% 제거)'
                : '500 iterations benchmark (Zero HTTP serialization and socket overhead)'}
            </p>
          </div>
        </div>
        <div className="hidden sm:flex items-center gap-4 text-xs font-mono">
          <div className="flex items-center gap-1.5 text-[#00FF9D]">
            <div className="w-2.5 h-2.5 rounded-sm bg-[#00FF9D]" />
            <span>In-Process SDK</span>
          </div>
          <div className="flex items-center gap-1.5 text-[#849495]">
            <div className="w-2.5 h-2.5 rounded-sm bg-[#849495]/40" />
            <span>FastAPI REST API</span>
          </div>
        </div>
      </div>

      <div className="space-y-5">
        {metrics.map((item, idx) => (
          <div key={idx} className="space-y-1.5">
            <div className="flex justify-between items-center text-xs font-mono">
              <span className="text-gray-300 font-semibold">{item.label}</span>
              <span className="text-[#00FF9D] font-bold text-[11px] bg-[#00FF9D]/10 px-2 py-0.5 rounded border border-[#00FF9D]/20">
                {item.multiplier} {isKo ? '성능 혁신' : 'Boost'}
              </span>
            </div>

            {/* SDK Bar */}
            <div className="flex items-center gap-3">
              <div className="w-24 text-[11px] font-mono text-[#00FF9D] flex items-center gap-1 font-semibold shrink-0">
                <Cpu className="w-3 h-3" />
                <span>{item.sdk}</span>
              </div>
              <div className="flex-1 h-3 bg-black/40 rounded-full overflow-hidden p-0.5 border border-white/5">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-[#00FF9D] to-[#00F0FF] shadow-[0_0_12px_rgba(0,255,157,0.5)] transition-all duration-1000"
                  style={{ width: `${Math.max(item.invert ? item.sdkRatio : item.sdkRatio, 4)}%` }}
                />
              </div>
            </div>

            {/* REST Bar */}
            <div className="flex items-center gap-3">
              <div className="w-24 text-[11px] font-mono text-[#849495] flex items-center gap-1 shrink-0">
                <Server className="w-3 h-3" />
                <span>{item.rest}</span>
              </div>
              <div className="flex-1 h-2 bg-black/30 rounded-full overflow-hidden p-0.5 border border-white/5">
                <div
                  className="h-full rounded-full bg-white/20 transition-all duration-1000"
                  style={{ width: `${Math.max(item.invert ? item.restRatio : item.restRatio, 4)}%` }}
                />
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="mt-6 pt-4 border-t border-white/10 flex flex-wrap items-center justify-between gap-3 text-xs text-[#849495]">
        <div className="flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-[#00FF9D]" />
          <span>{isKo ? 'Sub-millisecond (0.145ms) 지연시간 보증' : 'Sub-millisecond (0.145ms) Latency Guaranteed'}</span>
        </div>
        <div className="font-mono text-[11px] text-[#00F0FF]">
          Verified by scripts/benchmark_sdk_vs_rest.py
        </div>
      </div>
    </div>
  );
};
