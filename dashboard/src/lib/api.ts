import { SecurityEventData } from './types';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000/v1';

export async function checkBackendHealth(): Promise<{ status: string; service: string }> {
  try {
    const res = await fetch(`${API_BASE}/health`, { cache: 'no-store' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch {
    return { status: 'offline', service: 'ai-security-control-plane' };
  }
}

export async function scanPrompt(prompt: string): Promise<any> {
  const res = await fetch(`${API_BASE}/security/prompt/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ prompt }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail?.[0]?.msg || `HTTP ${res.status}`);
  }
  return await res.json();
}

export async function scanContent(content: string, contentType = 'text', sourceType = 'rag_document'): Promise<any> {
  const res = await fetch(`${API_BASE}/security/content/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      content,
      content_type: contentType,
      source_type: sourceType,
    }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail?.[0]?.msg || `HTTP ${res.status}`);
  }
  return await res.json();
}

export async function scanOutput(output: string): Promise<any> {
  const res = await fetch(`${API_BASE}/security/output/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ output }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail?.[0]?.msg || `HTTP ${res.status}`);
  }
  return await res.json();
}

export async function fetchRecentEvents(): Promise<SecurityEventData[]> {
  try {
    const res = await fetch(`${API_BASE}/security/events/recent`, { cache: 'no-store' });
    if (!res.ok) return [];
    const data = await res.json();
    return data.events || [];
  } catch {
    return [];
  }
}

// Subscribe to SSE stream
export function subscribeToEvents(
  onEvent: (event: SecurityEventData) => void,
  onError?: (err: any) => void
): () => void {
  try {
    const eventSource = new EventSource(`${API_BASE}/security/events/stream`);

    eventSource.addEventListener('security_event', (e) => {
      try {
        const parsed = JSON.parse(e.data);
        onEvent(parsed);
      } catch (err) {
        console.error('SSE JSON parse error:', err);
      }
    });

    eventSource.onerror = (err) => {
      if (onError) onError(err);
      eventSource.close();
    };

    return () => eventSource.close();
  } catch (err) {
    if (onError) onError(err);
    return () => {};
  }
}

// Demo Mock Traffic Generator for live simulations
const DEMO_EVENT_TEMPLATES = [
  {
    event_type: 'prompt.scan',
    decision: 'DENY' as const,
    risk_score: 95,
    reason_codes: ['PROMPT_INJECTION_DETECTED', 'SYSTEM_OVERRIDE'],
    findings: [{ code: 'PRM_INJ_001', category: 'JAILBREAK', severity: 'CRITICAL', risk_score: 95, detector: 'heuristic_injection_detector' }],
    length: 128,
  },
  {
    event_type: 'prompt.scan',
    decision: 'ALLOW' as const,
    risk_score: 0,
    reason_codes: ['PROMPT_CLEAN'],
    length: 45,
  },
  {
    event_type: 'content.scan',
    decision: 'DENY' as const,
    risk_score: 90,
    reason_codes: ['RAG_POISONING_BLOCKED'],
    content_type: 'markdown',
    source_type: 'rag_document',
  },
  {
    event_type: 'tool.authorize',
    decision: 'DENY' as const,
    risk_score: 100,
    reason_codes: ['TOOL_UNAUTHORIZED', 'SHELL_INJECTION_PREVENTED'],
  },
  {
    event_type: 'output.scan',
    decision: 'SANITIZE' as const,
    risk_score: 40,
    reason_codes: ['PII_REDACTED', 'EMAIL_MASKED'],
    findings: [{ code: 'SEC_PII_002', category: 'PII', severity: 'MEDIUM', risk_score: 40, detector: 'deterministic_pii_engine' }],
  },
  {
    event_type: 'output.scan',
    decision: 'DENY' as const,
    risk_score: 100,
    reason_codes: ['SECRET_LEAK_PREVENTED', 'OPENAI_API_KEY_BLOCKED'],
    findings: [{ code: 'SEC_LEAK_001', category: 'CREDENTIAL', severity: 'CRITICAL', risk_score: 100, detector: 'secret_pattern_detector' }],
  },
  {
    event_type: 'runtime.anomaly',
    decision: 'TERMINATE' as const,
    risk_score: 100,
    reason_codes: ['CALL_BURST_EXCEEDED', 'CONFUSED_DEPUTY_LOOP'],
  },
];

export function generateMockEvent(): SecurityEventData {
  const template = DEMO_EVENT_TEMPLATES[Math.floor(Math.random() * DEMO_EVENT_TEMPLATES.length)];
  const randomHex = Math.random().toString(16).substring(2, 10);
  return {
    ...template,
    event_id: `evt_demo_${randomHex}`,
    timestamp: new Date().toISOString(),
    fingerprint: `fp_${randomHex}`,
    is_mock: true,
  };
}
