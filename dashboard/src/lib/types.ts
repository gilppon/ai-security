export type DecisionAction = 'ALLOW' | 'LOG' | 'SANITIZE' | 'DENY' | 'TERMINATE';

export interface SecurityEventData {
  event_id: string;
  timestamp?: string;
  event_type: string;
  decision: DecisionAction;
  risk_score: number;
  reason_codes: string[];
  findings?: Array<{
    code: string;
    category: string;
    severity: string;
    risk_score: number;
    detector: string;
  }>;
  length?: number;
  fingerprint?: string;
  content_type?: string;
  source_type?: string;
  is_mock?: boolean;
  metadata?: Record<string, unknown>;
}

export interface DefenseTierStatus {
  id: string;
  name: string;
  phase: string;
  status: 'ACTIVE' | 'WARNING' | 'ALERT';
  blockedCount: number;
  passedCount: number;
  latencyMs: number;
  description: string;
}

export interface PipelineStep {
  name: 'SecurityEvent' | 'Normalize' | 'Context' | 'Detect' | 'Risk' | 'Policy' | 'Decision' | 'Audit';
  label: string;
  status: 'active' | 'passed' | 'blocked' | 'sanitized';
  latencyMs: number;
  description: string;
  data?: Record<string, unknown>;
}

export interface WormBlock {
  index: number;
  hash: string;
  previousHash: string;
  timestamp: string;
  recordCount: number;
  r2Synced: boolean;
}

export interface PolicyRuleInfo {
  id: string;
  name: string;
  tier: string;
  action: DecisionAction;
  riskWeight: number;
  description: string;
}
