import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

// Types
export type LLMProvider = {
  id: string; tenant_id: string; name: string; provider: string;
  base_url: string; model_id: string; region: string;
  max_tokens: number; cost_per_1k_input: number; cost_per_1k_output: number;
  priority: number; enabled: boolean; rate_limit_rpm: number; status: string;
  created_at: string;
};

export type ModelAccessRule = {
  id: string; tenant_id: string; model_ids: string[]; user_roles: string[];
  user_ids: string[]; max_tokens_per_request: number; require_approval: boolean; enabled: boolean;
};

export type TokenBudget = {
  id: string; tenant_id: string; scope: string; scope_id: string;
  max_tokens: number; max_cost_usd: number; period: string;
  alert_at_pct: number; hard_cap: boolean;
  used_tokens: number; cost_used_usd: number; reset_at: string;
};

export type TopicGuardrail = {
  id: string; tenant_id: string; name: string; action: string;
  topics: string[]; keywords: string[]; enabled: boolean;
};

export type GatewayAuditEvent = {
  id: string; tenant_id: string; user_id: string; request_id: string;
  model: string; provider: string; action: string;
  prompt_tokens: number; completion_tokens: number; cost_usd: number;
  dlp_findings: number; injection_score: number; toxicity_score: number;
  guardrail_hits: string[]; latency_ms: number; status: string; created_at: string;
};

export type GatewayHealth = {
  status: string; service: string; version: string;
  checks: Record<string, string>; timestamp: string;
};

export type ScanResult = {
  safe: boolean; finding_count: number;
  findings: Array<{
    pattern: string; category: string; match: string;
    offset: number; end_offset: number; count: number; confidence: number;
  }>;
  redacted_text: string; injection_score: number;
  toxicity_score: number; guardrail_hits: string[];
};

// API Functions
const SVC = "ai-gateway";
const BASE = "/ai-gateway/v1";

export async function getGatewayHealth(s: AuthSession): Promise<GatewayHealth> {
  return serviceRequest(s, SVC, `${BASE}/health`);
}

// Models
export async function listModels(s: AuthSession): Promise<LLMProvider[]> {
  const r = await serviceRequest<any>(s, SVC, `${BASE}/models`);
  return r.data || r.models || [];
}
export async function createModel(s: AuthSession, data: Partial<LLMProvider>): Promise<LLMProvider> {
  return serviceRequest(s, SVC, `${BASE}/models`, { method: "POST", body: JSON.stringify(data) });
}
export async function deleteModel(s: AuthSession, id: string): Promise<void> {
  return serviceRequest(s, SVC, `${BASE}/models/${id}`, { method: "DELETE" });
}
export async function testModel(s: AuthSession, id: string): Promise<any> {
  return serviceRequest(s, SVC, `${BASE}/models/${id}/test`, { method: "POST" });
}

// Access Rules
export async function listAccessRules(s: AuthSession): Promise<ModelAccessRule[]> {
  const r = await serviceRequest<any>(s, SVC, `${BASE}/access-rules`);
  return r.data || r.rules || [];
}
export async function createAccessRule(s: AuthSession, data: Partial<ModelAccessRule>): Promise<any> {
  return serviceRequest(s, SVC, `${BASE}/access-rules`, { method: "POST", body: JSON.stringify(data) });
}
export async function deleteAccessRule(s: AuthSession, id: string): Promise<void> {
  return serviceRequest(s, SVC, `${BASE}/access-rules/${id}`, { method: "DELETE" });
}

// Budgets
export async function listBudgets(s: AuthSession): Promise<TokenBudget[]> {
  const r = await serviceRequest<any>(s, SVC, `${BASE}/budgets`);
  return r.data || r.budgets || [];
}
export async function createBudget(s: AuthSession, data: Partial<TokenBudget>): Promise<any> {
  return serviceRequest(s, SVC, `${BASE}/budgets`, { method: "POST", body: JSON.stringify(data) });
}
export async function updateBudget(s: AuthSession, id: string, data: Partial<TokenBudget>): Promise<any> {
  return serviceRequest(s, SVC, `${BASE}/budgets/${id}`, { method: "PUT", body: JSON.stringify(data) });
}
export async function getBudgetUsage(s: AuthSession): Promise<any> {
  return serviceRequest(s, SVC, `${BASE}/budgets/usage`);
}

// Guardrails
export async function listGuardrails(s: AuthSession): Promise<TopicGuardrail[]> {
  const r = await serviceRequest<any>(s, SVC, `${BASE}/guardrails`);
  return r.data || r.guardrails || [];
}
export async function createGuardrail(s: AuthSession, data: Partial<TopicGuardrail>): Promise<any> {
  return serviceRequest(s, SVC, `${BASE}/guardrails`, { method: "POST", body: JSON.stringify(data) });
}
export async function deleteGuardrail(s: AuthSession, id: string): Promise<void> {
  return serviceRequest(s, SVC, `${BASE}/guardrails/${id}`, { method: "DELETE" });
}

// DLP Scan
export async function scanText(s: AuthSession, text: string, patterns?: string[]): Promise<ScanResult> {
  const r = await serviceRequest<any>(s, SVC, `${BASE}/scan`, {
    method: "POST", body: JSON.stringify({ text, patterns }),
  });
  return r.result || r;
}
export async function redactText(s: AuthSession, text: string, patterns?: string[]): Promise<ScanResult> {
  const r = await serviceRequest<any>(s, SVC, `${BASE}/redact`, {
    method: "POST", body: JSON.stringify({ text, patterns }),
  });
  return r.result || r;
}
export async function evaluateText(s: AuthSession, text: string): Promise<ScanResult> {
  const r = await serviceRequest<any>(s, SVC, `${BASE}/evaluate`, {
    method: "POST", body: JSON.stringify({ text }),
  });
  return r.result || r;
}

// Audit
export async function listAuditEvents(s: AuthSession, limit?: number): Promise<GatewayAuditEvent[]> {
  const r = await serviceRequest<any>(s, SVC, `${BASE}/audit?limit=${limit || 50}`);
  return r.data || r.events || [];
}
export async function getAuditStats(s: AuthSession): Promise<any> {
  return serviceRequest(s, SVC, `${BASE}/audit/stats`);
}

// Policies (DLP)
export async function listGatewayPolicies(s: AuthSession): Promise<any[]> {
  const r = await serviceRequest<any>(s, SVC, `${BASE}/policies`);
  return r.data || r.policies || [];
}
export async function createGatewayPolicy(s: AuthSession, data: any): Promise<any> {
  return serviceRequest(s, SVC, `${BASE}/policies`, { method: "POST", body: JSON.stringify(data) });
}
export async function deleteGatewayPolicy(s: AuthSession, id: string): Promise<void> {
  return serviceRequest(s, SVC, `${BASE}/policies/${id}`, { method: "DELETE" });
}
