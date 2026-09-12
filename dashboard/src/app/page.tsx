"use client";

import React, { useState, useEffect, useCallback } from 'react';
import { TopNav } from '@/components/ui/TopNav';
import { SubNav, ViewTab } from '@/components/ui/SubNav';
import { LandingPageView } from '@/components/views/LandingPageView';
import { ThreatRadarView } from '@/components/views/ThreatRadarView';
import { PipelineInspectorView } from '@/components/views/PipelineInspectorView';
import { ThreatSimulatorView } from '@/components/views/ThreatSimulatorView';
import { WormVaultView } from '@/components/views/WormVaultView';
import { PolicyConsoleView } from '@/components/views/PolicyConsoleView';
import {
  checkBackendHealth,
  fetchRecentEvents,
  subscribeToEvents,
  generateMockEvent,
} from '@/lib/api';
import { SecurityEventData } from '@/lib/types';
import { useLanguage } from '@/context/LanguageContext';

export default function DashboardHome() {
  const { t } = useLanguage();
  const [activeTab, setActiveTab] = useState<ViewTab>('landing');
  const [isOnline, setIsOnline] = useState<boolean>(true);
  const [events, setEvents] = useState<SecurityEventData[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEventData | null>(null);
  const [isDemoFeed, setIsDemoFeed] = useState<boolean>(true);

  // Initial load & health check (merge without overwriting live stream)
  const refreshState = useCallback(async () => {
    const health = await checkBackendHealth();
    setIsOnline(health.status === 'ok');

    const recent = await fetchRecentEvents();
    if (recent.length > 0) {
      setEvents((prev) => {
        const existingIds = new Set(prev.map((e) => e.event_id));
        const incoming = recent.filter((e) => !existingIds.has(e.event_id));
        if (incoming.length === 0) return prev;
        return [...incoming, ...prev].slice(0, 50);
      });
    } else {
      setEvents((prev) => {
        if (prev.length > 0) return prev;
        return [
          generateMockEvent(),
          generateMockEvent(),
          generateMockEvent(),
        ];
      });
    }
  }, []);

  useEffect(() => {
    refreshState();
    const interval = setInterval(refreshState, 15000);
    return () => clearInterval(interval);
  }, [refreshState]);

  // Subscribe to real-time SSE stream from FastAPI
  useEffect(() => {
    const unsubscribe = subscribeToEvents(
      (newEvent) => {
        setIsOnline(true);
        const liveEvent: SecurityEventData = {
          ...newEvent,
          is_mock: false,
        };
        setEvents((prev) => [liveEvent, ...prev].slice(0, 50));
      },
      () => {
        // SSE disconnected / fallback to offline indication
        setIsOnline(false);
      }
    );
    return () => unsubscribe();
  }, []);

  // Demo Feed Simulator interval
  useEffect(() => {
    if (!isDemoFeed) return;
    const timer = setInterval(() => {
      const mock = generateMockEvent();
      setEvents((prev) => [mock, ...prev].slice(0, 50));
    }, 4500);
    return () => clearInterval(timer);
  }, [isDemoFeed]);

  const handleAddNewEvent = (evt: SecurityEventData) => {
    const liveEvent = { ...evt, is_mock: false };
    setEvents((prev) => [liveEvent, ...prev].slice(0, 50));
    setSelectedEvent(liveEvent);
    // Switch to pipeline inspector to immediately inspect
    setActiveTab('pipeline');
  };

  const blockedCount = events.filter(
    (e) => e.decision === 'DENY' || e.decision === 'TERMINATE'
  ).length;

  return (
    <div className="min-h-screen flex flex-col justify-between">
      <div>
        {/* Top Control Bar */}
        <TopNav
          isOnline={isOnline}
          eventCount={events.length}
          blockedCount={blockedCount}
          isDemoFeed={isDemoFeed}
          onToggleDemoFeed={() => setIsDemoFeed((prev) => !prev)}
          onRefresh={refreshState}
          isLanding={activeTab === 'landing'}
          onToggleLanding={() => setActiveTab(activeTab === 'landing' ? 'radar' : 'landing')}
        />

        {/* 6-Tab Navigation Strip */}
        <SubNav activeTab={activeTab} onChangeTab={setActiveTab} />

        {/* Main Content Workspace */}
        {activeTab === 'landing' ? (
          <LandingPageView onEnterDashboard={() => setActiveTab('radar')} />
        ) : (
          <main className="max-w-[1600px] mx-auto p-6 md:p-8">
            {activeTab === 'radar' && (
              <ThreatRadarView
                events={events}
                onSelectEvent={(evt) => {
                  setSelectedEvent(evt);
                  setActiveTab('pipeline');
                }}
                isDemoFeed={isDemoFeed}
                onToggleDemoFeed={() => setIsDemoFeed((prev) => !prev)}
              />
            )}

            {activeTab === 'pipeline' && (
              <PipelineInspectorView
                selectedEvent={selectedEvent}
                allEvents={events}
                onSelectEvent={setSelectedEvent}
              />
            )}

            {activeTab === 'simulator' && (
              <ThreatSimulatorView onNewEvent={handleAddNewEvent} />
            )}

            {activeTab === 'worm' && <WormVaultView />}

            {activeTab === 'policy' && <PolicyConsoleView />}
          </main>
        )}
      </div>

      {/* Tactical Status Footer */}
      <footer className="border-t border-[#00F0FF]/15 px-6 py-4 bg-[#04080E]/80 backdrop-blur-md">
        <div className="max-w-[1600px] mx-auto flex flex-wrap items-center justify-between text-xs font-mono text-[#849495] gap-2">
          <div className="flex items-center gap-3">
            <span>{t('footer_text')}</span>
          </div>
          <div>
            <span>{t('footer_right')}</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
