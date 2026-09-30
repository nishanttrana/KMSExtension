// @ts-nocheck -- unified AI security tab: strict typing deferred
import { useCallback, useEffect, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  Clock,
  CreditCard,
  Download,
  Eye,
  FileSearch,
  Filter,
  Plus,
  Radio,
  RefreshCw,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  XCircle,
  Zap,
} from "lucide-react";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import {
  B,
  Bar,
  Btn,
  Card,
  Chk,
  FG,
  Inp,
  Row2,
  Section,
  Sel,
  Stat,
  Txt,
} from "../legacyPrimitives";
import {
  getGatewayHealth,
  listModels,
  createModel,
  deleteModel,
  testModel,
  listAccessRules,
  createAccessRule,
  deleteAccessRule,
  listBudgets,
  createBudget,
  listGuardrails,
  createGuardrail,
  deleteGuardrail,
  scanText,
  redactText,
  evaluateText,
  listAuditEvents,
  getAuditStats,
} from "../../../lib/aigateway";
// eslint-disable-next-line no-restricted-imports -- intentional: legacy direct call, refactor to typed client tracked separately
import { serviceRequest } from "../../../lib/serviceApi";
import type {
  LLMProvider,
  ModelAccessRule,
  TokenBudget,
  TopicGuardrail,
  GatewayAuditEvent,
  GatewayHealth,
  ScanResult,
} from "../../../lib/aigateway";

// ── types ──────────────────────────────────────────────────────────

type View = "overview" | "models" | "governance" | "guardrails" | "dlp_policies" | "scan" | "realtime" | "reports" | "audit";

type DLPPolicy = {
  id: string;
  name: string;
  description?: string;
  patterns: string[];
  action: "redact" | "block" | "warn";
  scope: "input" | "output" | "both";
  min_confidence: number;
  custom_regex: string[];
  exemptions: string[];
  enabled: boolean;
  created_at?: string;
};

type RealtimeRequest = {
  id: string;
  timestamp: string;
  user: string;
  model: string;
  action: string;
  tokens: number;
  cost: number;
  findings: number;
  latency_ms: number;
};

// ── constants ──────────────────────────────────────────────────────

const PROVIDERS = [
  { value: "openai", label: "OpenAI", color: "green" },
  { value: "anthropic", label: "Anthropic", color: "purple" },
  { value: "azure", label: "Azure OpenAI", color: "blue" },
  { value: "bedrock", label: "AWS Bedrock", color: "amber" },
  { value: "vertex", label: "Google Vertex AI", color: "red" },
  { value: "ollama", label: "Self-Hosted", color: "muted" },
];

const PROVIDER_MAP: Record<string, { label: string; color: string }> = {};
PROVIDERS.forEach(p => { PROVIDER_MAP[p.value] = { label: p.label, color: p.color }; });

const ROLES = ["admin", "user", "readonly", "api"];

const TOPIC_OPTIONS = [
  "weapons", "self_harm", "illegal_activity", "competitor_analysis",
  "legal_advice", "source_code", "internal_docs", "financial_advice", "medical_advice",
];

const PATTERN_GROUPS: Record<string, { label: string; patterns: string[] }> = {
  pii: {
    label: "Personally Identifiable Information",
    patterns: ["email", "ssn", "phone", "name", "address", "government_id"],
  },
  financial: {
    label: "Financial Data",
    patterns: ["credit_card", "bank_account", "routing_number", "iban", "swift_bic"],
  },
  credential: {
    label: "Credentials & Secrets",
    patterns: ["api_key", "aws_key", "private_key", "jwt", "password", "connection_string", "github_pat", "gitlab_pat", "slack_token", "gcp_service_account", "azure_connection"],
  },
  health: {
    label: "Health / HIPAA",
    patterns: ["mrn", "icd_code", "drug_name", "dob_health"],
  },
};

const ALL_PATTERNS = Object.values(PATTERN_GROUPS).flatMap(g => g.patterns);

const PATTERN_LABELS: Record<string, string> = {
  email: "Email Address", ssn: "Social Security Number", phone: "Phone Number",
  name: "Person Name", address: "Physical Address", government_id: "Government ID",
  credit_card: "Credit Card (Luhn)", bank_account: "Bank Account", routing_number: "Routing Number (ABA)",
  iban: "IBAN (ISO 7064)", swift_bic: "SWIFT/BIC Code",
  api_key: "API Key", aws_key: "AWS Access Key", private_key: "Private Key (PEM)",
  jwt: "JWT Token", password: "Password Assignment", connection_string: "Connection String",
  github_pat: "GitHub PAT", gitlab_pat: "GitLab PAT", slack_token: "Slack Token",
  gcp_service_account: "GCP Service Account", azure_connection: "Azure Connection String",
  mrn: "Medical Record Number", icd_code: "ICD Code", drug_name: "Drug Name", dob_health: "DOB (Health Context)",
};

const EMPTY_MODEL_FORM = {
  name: "", provider: "openai", api_key: "", base_url: "", model_id: "",
  region: "", max_tokens: 4096, cost_per_1k_input: 0, cost_per_1k_output: 0,
  priority: 1, rate_limit_rpm: 60,
};

const EMPTY_ACCESS_FORM = {
  model_ids: [] as string[], user_roles: [] as string[],
  max_tokens_per_request: 4096, require_approval: false,
};

const EMPTY_BUDGET_FORM = {
  scope: "tenant", scope_id: "", max_tokens: 1000000, max_cost_usd: 100,
  period: "monthly", alert_at_pct: 80, hard_cap: false,
};

const EMPTY_GUARDRAIL_FORM = {
  name: "", action: "block", topics: [] as string[],
  keywords: "", enabled: true,
};

const EMPTY_DLP_POLICY_FORM = {
  name: "", description: "",
  patterns: ALL_PATTERNS.slice(),
  action: "redact" as "redact" | "block" | "warn",
  scope: "both" as "input" | "output" | "both",
  min_confidence: 0.7,
  custom_regex: "",
  exemptions: "",
  enabled: true,
};

const VIEW_CONFIG: { key: View; label: string; icon: any }[] = [
  { key: "overview", label: "Overview", icon: Shield },
  { key: "models", label: "Models", icon: Server },
  { key: "governance", label: "Governance", icon: Settings },
  { key: "guardrails", label: "Guardrails", icon: ShieldAlert },
  { key: "dlp_policies", label: "DLP Policies", icon: ShieldCheck },
  { key: "scan", label: "Scanner", icon: FileSearch },
  { key: "realtime", label: "Real-time", icon: Radio },
  { key: "reports", label: "Reports", icon: BarChart3 },
  { key: "audit", label: "Audit", icon: Activity },
];

// ── helpers ────────────────────────────────────────────────────────

const TH: React.CSSProperties = {
  padding: "8px 12px", fontSize: 10, fontWeight: 700, color: C.muted,
  textTransform: "uppercase", letterSpacing: "0.08em", textAlign: "left",
  background: C.card, borderBottom: `1px solid ${C.border}`,
};
const TD = (i: number): React.CSSProperties => ({
  padding: "9px 12px", color: C.dim, fontSize: 11, verticalAlign: "middle",
  background: i % 2 === 0 ? C.card : "#0f1824",
  borderBottom: `1px solid ${C.border}22`,
});

function fmtDatetime(s?: string): string {
  if (!s) return "\u2014";
  const d = new Date(s);
  return isNaN(d.getTime()) ? s : d.toLocaleString();
}

function fmtCost(n?: number): string {
  if (n == null || isNaN(n)) return "$0.00";
  return `$${n.toFixed(4)}`;
}

function pctColor(pct: number): string {
  if (pct < 30) return C.green;
  if (pct < 70) return C.amber;
  return C.red;
}

function actionBadgeColor(action: string): string {
  if (action === "block") return "red";
  if (action === "warn") return "amber";
  if (action === "redact") return "purple";
  return "green";
}

function providerBadge(provider: string) {
  const p = PROVIDER_MAP[provider] || { label: provider, color: "muted" };
  return <B c={p.color}>{p.label}</B>;
}

// Simple CSS bar chart helper for sparklines
function MiniBar({ values, color }: { values: number[]; color: string }) {
  const max = Math.max(...values, 1);
  return (
    <div style={{ display: "flex", alignItems: "flex-end", gap: 2, height: 24 }}>
      {values.map((v, i) => (
        <div key={i} style={{
          width: 6, borderRadius: 2,
          height: `${Math.max(2, (v / max) * 24)}px`,
          background: color, opacity: 0.6 + (i / values.length) * 0.4,
        }} />
      ))}
    </div>
  );
}

// ── component ──────────────────────────────────────────────────────

export function AIGatewayTab({ session }: { session: any }) {
  const [view, setView] = useState<View>("overview");
  const [err, setErr] = useState("");

  // Health
  const [health, setHealth] = useState<GatewayHealth | null>(null);

  // Models
  const [models, setModels] = useState<LLMProvider[]>([]);
  const [loadingModels, setLoadingModels] = useState(false);
  const [modelForm, setModelForm] = useState({ ...EMPTY_MODEL_FORM });
  const [modelFormErr, setModelFormErr] = useState("");
  const [modelFormBusy, setModelFormBusy] = useState(false);
  const [testingModel, setTestingModel] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<Record<string, string>>({});

  // Access rules
  const [accessRules, setAccessRules] = useState<ModelAccessRule[]>([]);
  const [loadingRules, setLoadingRules] = useState(false);
  const [accessForm, setAccessForm] = useState({ ...EMPTY_ACCESS_FORM });
  const [accessFormErr, setAccessFormErr] = useState("");
  const [accessFormBusy, setAccessFormBusy] = useState(false);

  // Budgets
  const [budgets, setBudgets] = useState<TokenBudget[]>([]);
  const [loadingBudgets, setLoadingBudgets] = useState(false);
  const [budgetForm, setBudgetForm] = useState({ ...EMPTY_BUDGET_FORM });
  const [budgetFormErr, setBudgetFormErr] = useState("");
  const [budgetFormBusy, setBudgetFormBusy] = useState(false);

  // Guardrails
  const [guardrails, setGuardrails] = useState<TopicGuardrail[]>([]);
  const [loadingGuardrails, setLoadingGuardrails] = useState(false);
  const [guardrailForm, setGuardrailForm] = useState({ ...EMPTY_GUARDRAIL_FORM });
  const [guardrailFormErr, setGuardrailFormErr] = useState("");
  const [guardrailFormBusy, setGuardrailFormBusy] = useState(false);
  const [guardrailTestText, setGuardrailTestText] = useState("");
  const [guardrailTestResult, setGuardrailTestResult] = useState<ScanResult | null>(null);
  const [guardrailTestBusy, setGuardrailTestBusy] = useState(false);

  // DLP Policies (merged from AIProtectTab)
  const [dlpPolicies, setDlpPolicies] = useState<DLPPolicy[]>([]);
  const [loadingDlpPolicies, setLoadingDlpPolicies] = useState(false);
  const [dlpPolicyForm, setDlpPolicyForm] = useState({ ...EMPTY_DLP_POLICY_FORM });
  const [dlpPolicyFormErr, setDlpPolicyFormErr] = useState("");
  const [dlpPolicyFormBusy, setDlpPolicyFormBusy] = useState(false);
  const [dlpDeleteBusy, setDlpDeleteBusy] = useState<string | null>(null);

  // Scan
  const [scanInput, setScanInput] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [scanErr, setScanErr] = useState("");
  const [scanMode, setScanMode] = useState<"manual" | "simulate">("manual");
  const [simSystemPrompt, setSimSystemPrompt] = useState("");
  const [simUserPrompt, setSimUserPrompt] = useState("");
  const [simPipelineResult, setSimPipelineResult] = useState<any>(null);

  // Realtime
  const [realtimeFeed, setRealtimeFeed] = useState<RealtimeRequest[]>([]);
  const [realtimeCounters, setRealtimeCounters] = useState({ rpm: 0, tpm: 0, bpm: 0, avgLatency: 0 });
  const [realtimeHistory, setRealtimeHistory] = useState<number[]>([0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
  const realtimeTimerRef = useRef<any>(null);

  // Reports
  const [reportPeriod, setReportPeriod] = useState<"today" | "7d" | "30d">("7d");

  // Audit
  const [auditEvents, setAuditEvents] = useState<GatewayAuditEvent[]>([]);
  const [loadingAudit, setLoadingAudit] = useState(false);
  const [auditStats, setAuditStats] = useState<any>(null);
  const [auditFilter, setAuditFilter] = useState("");
  const [auditPage, setAuditPage] = useState(0);
  const AUDIT_PAGE_SIZE = 20;

  const [deleteBusy, setDeleteBusy] = useState<string | null>(null);

  // ── loaders ──────────────────────────────────────────────────────

  const loadHealth = useCallback(async () => {
    try {
      const h = await getGatewayHealth(session);
      setHealth(h);
    } catch {
      setHealth(null);
    }
  }, [session]);

  const loadModels = useCallback(async () => {
    setLoadingModels(true); setErr("");
    try {
      setModels(await listModels(session));
    } catch (e) { setErr(errMsg(e)); }
    finally { setLoadingModels(false); }
  }, [session]);

  const loadRules = useCallback(async () => {
    setLoadingRules(true);
    try { setAccessRules(await listAccessRules(session)); }
    catch (e) { setErr(errMsg(e)); }
    finally { setLoadingRules(false); }
  }, [session]);

  const loadBudgets = useCallback(async () => {
    setLoadingBudgets(true);
    try { setBudgets(await listBudgets(session)); }
    catch (e) { setErr(errMsg(e)); }
    finally { setLoadingBudgets(false); }
  }, [session]);

  const loadGuardrails = useCallback(async () => {
    setLoadingGuardrails(true);
    try { setGuardrails(await listGuardrails(session)); }
    catch (e) { setErr(errMsg(e)); }
    finally { setLoadingGuardrails(false); }
  }, [session]);

  const loadAudit = useCallback(async () => {
    setLoadingAudit(true);
    try {
      const [events, stats] = await Promise.all([
        listAuditEvents(session, 200),
        getAuditStats(session).catch(() => null),
      ]);
      setAuditEvents(events);
      setAuditStats(stats);
    } catch (e) { setErr(errMsg(e)); }
    finally { setLoadingAudit(false); }
  }, [session]);

  const loadDlpPolicies = useCallback(async () => {
    setLoadingDlpPolicies(true); setErr("");
    try {
      const data = await serviceRequest(
        session, "ai", `/ai/protect/policies?tenant_id=${encodeURIComponent(session.tenantId)}`
      );
      setDlpPolicies(data?.policies ?? []);
    } catch (e) { setErr(errMsg(e)); }
    finally { setLoadingDlpPolicies(false); }
  }, [session]);

  const loadRealtimeFeed = useCallback(async () => {
    try {
      const events = await listAuditEvents(session, 20);
      const feed: RealtimeRequest[] = events.map((e: any) => ({
        id: e.id, timestamp: e.created_at, user: e.user_id || "system",
        model: e.model || "unknown", action: e.action,
        tokens: (e.prompt_tokens || 0) + (e.completion_tokens || 0),
        cost: e.cost_usd || 0, findings: e.dlp_findings || 0, latency_ms: e.latency_ms || 0,
      }));
      setRealtimeFeed(feed);

      // Derive counters from recent events
      const now = Date.now();
      const lastMinute = feed.filter(r => now - new Date(r.timestamp).getTime() < 60000);
      setRealtimeCounters({
        rpm: lastMinute.length,
        tpm: lastMinute.reduce((a, r) => a + r.tokens, 0),
        bpm: lastMinute.filter(r => r.action === "block").length,
        avgLatency: lastMinute.length > 0 ? Math.round(lastMinute.reduce((a, r) => a + r.latency_ms, 0) / lastMinute.length) : 0,
      });

      setRealtimeHistory(prev => {
        const next = [...prev.slice(1), lastMinute.length];
        return next;
      });
    } catch {
      // Silently fail for realtime polling
    }
  }, [session]);

  useEffect(() => {
    void loadHealth();
    void loadModels();
  }, [loadHealth, loadModels]);

  // Realtime auto-refresh
  useEffect(() => {
    if (view === "realtime") {
      void loadRealtimeFeed();
      realtimeTimerRef.current = setInterval(() => { void loadRealtimeFeed(); }, 5000);
      return () => clearInterval(realtimeTimerRef.current);
    }
    return () => clearInterval(realtimeTimerRef.current);
  }, [view, loadRealtimeFeed]);

  // ── actions ──────────────────────────────────────────────────────

  async function doCreateModel() {
    setModelFormErr("");
    if (!modelForm.name.trim()) { setModelFormErr("Model name is required."); return; }
    if (!modelForm.model_id.trim()) { setModelFormErr("Model ID is required."); return; }
    setModelFormBusy(true);
    try {
      const created = await createModel(session, modelForm);
      setModels(prev => [created, ...prev]);
      setModelForm({ ...EMPTY_MODEL_FORM });
    } catch (e) { setModelFormErr(errMsg(e)); }
    finally { setModelFormBusy(false); }
  }

  async function doTestModel(id: string) {
    setTestingModel(id);
    try {
      const res = await testModel(session, id);
      setTestResult(prev => ({ ...prev, [id]: res?.status || "ok" }));
    } catch (e) {
      setTestResult(prev => ({ ...prev, [id]: `error: ${errMsg(e)}` }));
    } finally { setTestingModel(null); }
  }

  async function doDeleteModel(id: string) {
    if (!confirm("Delete this model registration?")) return;
    setDeleteBusy(id);
    try {
      await deleteModel(session, id);
      setModels(prev => prev.filter(m => m.id !== id));
    } catch (e) { setErr(errMsg(e)); }
    finally { setDeleteBusy(null); }
  }

  async function doCreateAccessRule() {
    setAccessFormErr("");
    if (accessForm.model_ids.length === 0) { setAccessFormErr("Select at least one model."); return; }
    if (accessForm.user_roles.length === 0) { setAccessFormErr("Select at least one role."); return; }
    setAccessFormBusy(true);
    try {
      const created = await createAccessRule(session, accessForm);
      setAccessRules(prev => [created, ...prev]);
      setAccessForm({ ...EMPTY_ACCESS_FORM });
    } catch (e) { setAccessFormErr(errMsg(e)); }
    finally { setAccessFormBusy(false); }
  }

  async function doDeleteAccessRule(id: string) {
    if (!confirm("Delete this access rule?")) return;
    setDeleteBusy(id);
    try {
      await deleteAccessRule(session, id);
      setAccessRules(prev => prev.filter(r => r.id !== id));
    } catch (e) { setErr(errMsg(e)); }
    finally { setDeleteBusy(null); }
  }

  async function doCreateBudget() {
    setBudgetFormErr("");
    if (!budgetForm.scope_id.trim() && budgetForm.scope !== "tenant") { setBudgetFormErr("Scope ID required for user/team budgets."); return; }
    setBudgetFormBusy(true);
    try {
      const created = await createBudget(session, budgetForm);
      setBudgets(prev => [created, ...prev]);
      setBudgetForm({ ...EMPTY_BUDGET_FORM });
    } catch (e) { setBudgetFormErr(errMsg(e)); }
    finally { setBudgetFormBusy(false); }
  }

  async function doCreateGuardrail() {
    setGuardrailFormErr("");
    if (!guardrailForm.name.trim()) { setGuardrailFormErr("Guardrail name is required."); return; }
    if (guardrailForm.topics.length === 0 && !guardrailForm.keywords.trim()) {
      setGuardrailFormErr("Add at least one topic or keyword."); return;
    }
    setGuardrailFormBusy(true);
    try {
      const data = {
        ...guardrailForm,
        keywords: guardrailForm.keywords.split(",").map(k => k.trim()).filter(Boolean),
      };
      const created = await createGuardrail(session, data);
      setGuardrails(prev => [created, ...prev]);
      setGuardrailForm({ ...EMPTY_GUARDRAIL_FORM });
    } catch (e) { setGuardrailFormErr(errMsg(e)); }
    finally { setGuardrailFormBusy(false); }
  }

  async function doDeleteGuardrail(id: string) {
    if (!confirm("Delete this guardrail?")) return;
    setDeleteBusy(id);
    try {
      await deleteGuardrail(session, id);
      setGuardrails(prev => prev.filter(g => g.id !== id));
    } catch (e) { setErr(errMsg(e)); }
    finally { setDeleteBusy(null); }
  }

  async function doScan(mode: "scan" | "redact" | "evaluate") {
    if (!scanInput.trim()) { setScanErr("Paste some text to scan."); return; }
    setScanErr(""); setScanResult(null); setScanning(true);
    try {
      let result: ScanResult;
      if (mode === "scan") result = await scanText(session, scanInput);
      else if (mode === "redact") result = await redactText(session, scanInput);
      else result = await evaluateText(session, scanInput);
      setScanResult(result);
    } catch (e) { setScanErr(errMsg(e)); }
    finally { setScanning(false); }
  }

  async function doSimulateGateway() {
    if (!simUserPrompt.trim()) { setScanErr("Enter a user prompt to simulate."); return; }
    setScanErr(""); setSimPipelineResult(null); setScanning(true);
    try {
      const fullText = simSystemPrompt ? `[System] ${simSystemPrompt}\n[User] ${simUserPrompt}` : simUserPrompt;
      const result = await evaluateText(session, fullText);
      // Build pipeline steps from the result
      const steps = [
        { name: "Authentication", status: "pass", detail: "Session validated" },
        { name: "Budget Check", status: budgets.length > 0 ? "pass" : "skip", detail: budgets.length > 0 ? "Within limits" : "No budgets configured" },
        { name: "DLP Scan", status: (result.findings?.length || 0) > 0 ? "warn" : "pass", detail: `${result.findings?.length || 0} findings` },
        { name: "Injection", status: (result.injection_score || 0) > 0.5 ? "fail" : "pass", detail: `score: ${((result.injection_score || 0) * 100).toFixed(1)}%` },
        { name: "Toxicity", status: (result.toxicity_score || 0) > 0.5 ? "fail" : "pass", detail: `score: ${((result.toxicity_score || 0) * 100).toFixed(1)}%` },
        { name: "Guardrails", status: (result.guardrail_hits?.length || 0) > 0 ? "fail" : "pass", detail: (result.guardrail_hits?.length || 0) > 0 ? `${result.guardrail_hits.length} hits` : "Clear" },
      ];
      const finalAction = result.safe ? "ALLOWED" : result.redacted_text ? "REDACTED" : "BLOCKED";
      setSimPipelineResult({ steps, finalAction, result });
    } catch (e) { setScanErr(errMsg(e)); }
    finally { setScanning(false); }
  }

  async function doTestGuardrail() {
    if (!guardrailTestText.trim()) return;
    setGuardrailTestBusy(true); setGuardrailTestResult(null);
    try {
      const result = await evaluateText(session, guardrailTestText);
      setGuardrailTestResult(result);
    } catch (e) { setErr(errMsg(e)); }
    finally { setGuardrailTestBusy(false); }
  }

  // DLP Policy actions
  async function doCreateDlpPolicy() {
    setDlpPolicyFormErr("");
    if (!dlpPolicyForm.name.trim()) { setDlpPolicyFormErr("Policy name is required."); return; }
    if (dlpPolicyForm.patterns.length === 0) { setDlpPolicyFormErr("Select at least one pattern."); return; }
    setDlpPolicyFormBusy(true);
    try {
      const payload = {
        tenant_id: session.tenantId,
        name: dlpPolicyForm.name,
        description: dlpPolicyForm.description,
        patterns: dlpPolicyForm.patterns,
        action: dlpPolicyForm.action,
        scope: dlpPolicyForm.scope,
        min_confidence: dlpPolicyForm.min_confidence,
        custom_regex: dlpPolicyForm.custom_regex ? dlpPolicyForm.custom_regex.split("\n").filter(Boolean) : [],
        exemptions: dlpPolicyForm.exemptions ? dlpPolicyForm.exemptions.split(",").map(s => s.trim()).filter(Boolean) : [],
        enabled: dlpPolicyForm.enabled,
      };
      const created = await serviceRequest(session, "ai", "/ai/protect/policies", {
        method: "POST", body: JSON.stringify(payload),
      });
      setDlpPolicies(prev => [created, ...prev]);
      setDlpPolicyForm({ ...EMPTY_DLP_POLICY_FORM });
    } catch (e) { setDlpPolicyFormErr(errMsg(e)); }
    finally { setDlpPolicyFormBusy(false); }
  }

  async function doDeleteDlpPolicy(id: string) {
    if (!confirm("Delete this DLP policy?")) return;
    setDlpDeleteBusy(id);
    try {
      await serviceRequest(session, "ai", `/ai/protect/policies/${id}`, { method: "DELETE" });
      setDlpPolicies(prev => prev.filter(p => p.id !== id));
    } catch (e) { setErr(errMsg(e)); }
    finally { setDlpDeleteBusy(null); }
  }

  function toggleDlpPolicyPattern(p: string) {
    setDlpPolicyForm(f => ({
      ...f,
      patterns: f.patterns.includes(p) ? f.patterns.filter(x => x !== p) : [...f.patterns, p],
    }));
  }

  function refreshAll() {
    void loadHealth();
    void loadModels();
    if (view === "governance") { void loadRules(); void loadBudgets(); }
    if (view === "guardrails") void loadGuardrails();
    if (view === "audit") void loadAudit();
    if (view === "dlp_policies") void loadDlpPolicies();
  }

  function exportReportJSON() {
    const data = {
      period: reportPeriod,
      exported_at: new Date().toISOString(),
      total_events: auditEvents.length,
      summary: auditStats,
      events: auditEvents,
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `ai-gateway-report-${reportPeriod}.json`; a.click();
    URL.revokeObjectURL(url);
  }

  // ── derived stats ────────────────────────────────────────────────

  const activeModels = models.filter(m => m.enabled).length;
  const activeBudgets = budgets.length;
  const guardrailCount = guardrails.filter(g => g.enabled).length;
  const activeDlpPolicies = dlpPolicies.filter(p => p.enabled).length;
  const todayEvents = auditEvents.filter(e => {
    const d = new Date(e.created_at);
    const now = new Date();
    return d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth() && d.getDate() === now.getDate();
  });
  const blockedEvents = auditEvents.filter(e => e.action === "block").length;
  const redactedEvents = auditEvents.filter(e => e.action === "redact").length;
  const allowedEvents = auditEvents.filter(e => e.action === "allow" || e.action === "success").length;

  // Security posture percentages
  const totalDecisions = blockedEvents + redactedEvents + allowedEvents || 1;
  const pctAllowed = Math.round((allowedEvents / totalDecisions) * 100);
  const pctRedacted = Math.round((redactedEvents / totalDecisions) * 100);
  const pctBlocked = Math.round((blockedEvents / totalDecisions) * 100);

  // Top DLP patterns from audit events
  const dlpPatternCounts: Record<string, number> = {};
  auditEvents.forEach(e => {
    if (e.dlp_findings > 0) {
      // Count based on model as proxy for pattern
      dlpPatternCounts[e.model] = (dlpPatternCounts[e.model] || 0) + e.dlp_findings;
    }
  });
  const topDlpPatterns = Object.entries(dlpPatternCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);

  // Top blocked topics
  const topicCounts: Record<string, number> = {};
  auditEvents.forEach(e => {
    (e.guardrail_hits || []).forEach(h => { topicCounts[h] = (topicCounts[h] || 0) + 1; });
  });
  const topBlockedTopics = Object.entries(topicCounts).sort((a, b) => b[1] - a[1]).slice(0, 3);

  // Injection attempts last 24h
  const injectionAttempts = auditEvents.filter(e => (e.injection_score || 0) > 0.5).length;

  // Quick setup checks
  const hasModels = models.length > 0;
  const hasDlpPolicies = dlpPolicies.length > 0;
  const hasBudgets = budgets.length > 0;
  const hasGuardrails = guardrails.length > 0;

  // Audit filtering / pagination
  const filteredAudit = auditEvents.filter(e => !auditFilter || e.action === auditFilter);
  const totalAuditPages = Math.max(1, Math.ceil(filteredAudit.length / AUDIT_PAGE_SIZE));
  const pageAuditEvents = filteredAudit.slice(auditPage * AUDIT_PAGE_SIZE, (auditPage + 1) * AUDIT_PAGE_SIZE);

  // Reports: breakdown by model
  const modelBreakdown: Record<string, { requests: number; tokens: number; cost: number; blocks: number; dlpFindings: number }> = {};
  const userBreakdown: Record<string, { requests: number; tokens: number; cost: number; violations: number }> = {};

  const periodMs = reportPeriod === "today" ? 86400000 : reportPeriod === "7d" ? 7 * 86400000 : 30 * 86400000;
  const periodEvents = auditEvents.filter(e => Date.now() - new Date(e.created_at).getTime() < periodMs);

  periodEvents.forEach(e => {
    const model = e.model || "unknown";
    if (!modelBreakdown[model]) modelBreakdown[model] = { requests: 0, tokens: 0, cost: 0, blocks: 0, dlpFindings: 0 };
    modelBreakdown[model].requests++;
    modelBreakdown[model].tokens += (e.prompt_tokens || 0) + (e.completion_tokens || 0);
    modelBreakdown[model].cost += e.cost_usd || 0;
    if (e.action === "block") modelBreakdown[model].blocks++;
    modelBreakdown[model].dlpFindings += e.dlp_findings || 0;

    const user = e.user_id || "system";
    if (!userBreakdown[user]) userBreakdown[user] = { requests: 0, tokens: 0, cost: 0, violations: 0 };
    userBreakdown[user].requests++;
    userBreakdown[user].tokens += (e.prompt_tokens || 0) + (e.completion_tokens || 0);
    userBreakdown[user].cost += e.cost_usd || 0;
    if (e.action === "block" || e.action === "warn") userBreakdown[user].violations++;
  });

  const reportTotalInteractions = periodEvents.length;
  const reportTotalPii = periodEvents.reduce((a, e) => a + (e.dlp_findings || 0), 0);
  const reportTotalBlocked = periodEvents.filter(e => e.action === "block").length;
  const reportTotalCost = periodEvents.reduce((a, e) => a + (e.cost_usd || 0), 0);

  // ── render ──────────────────────────────────────────────────────

  return (
    <div style={{ padding: 24, fontFamily: '"IBM Plex Sans", sans-serif', color: C.text, minHeight: "100%" }}>

      {/* ── Header ── */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
            <Shield size={18} color={C.accent} strokeWidth={2} />
            <span style={{ fontSize: 16, fontWeight: 700, color: C.text, letterSpacing: -0.3 }}>AI Security Gateway</span>
            {health && <B c={health.status === "ok" ? "green" : "red"} pulse>{health.status === "ok" ? "Healthy" : "Degraded"}</B>}
          </div>
          <div style={{ fontSize: 11, color: C.muted }}>
            Enterprise AI security: model routing, DLP scanning, PII redaction, prompt injection detection, topic guardrails, token budgets, and compliance reporting
          </div>
        </div>
        <div style={{ display: "flex", gap: 6 }}>
          <Btn small onClick={refreshAll} disabled={loadingModels}>
            <RefreshCw size={11} /> Refresh
          </Btn>
        </div>
      </div>

      {/* ── Error banner ── */}
      {err && (
        <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 8, padding: "10px 14px", color: C.red, fontSize: 11, marginBottom: 14, display: "flex", alignItems: "center", gap: 8 }}>
          <AlertTriangle size={13} /> {err}
          <button onClick={() => setErr("")} style={{ marginLeft: "auto", background: "none", border: "none", color: C.red, cursor: "pointer", fontSize: 11 }}>Dismiss</button>
        </div>
      )}

      {/* ── View tabs ── */}
      <div style={{ display: "flex", gap: 2, marginBottom: 18, borderBottom: `1px solid ${C.border}`, overflowX: "auto" }}>
        {VIEW_CONFIG.map(vc => {
          const Icon = vc.icon;
          let label = vc.label;
          if (vc.key === "models") label = `Models (${models.length})`;
          if (vc.key === "guardrails") label = `Guardrails (${guardrails.length})`;
          if (vc.key === "dlp_policies") label = `DLP Policies (${dlpPolicies.length})`;
          if (vc.key === "audit") label = `Audit (${auditEvents.length})`;
          return (
            <button key={vc.key} onClick={() => {
              setView(vc.key);
              if (vc.key === "governance" && accessRules.length === 0) { void loadRules(); void loadBudgets(); }
              if (vc.key === "guardrails" && guardrails.length === 0) void loadGuardrails();
              if (vc.key === "audit" && auditEvents.length === 0) void loadAudit();
              if (vc.key === "dlp_policies" && dlpPolicies.length === 0) void loadDlpPolicies();
              if (vc.key === "reports" && auditEvents.length === 0) void loadAudit();
            }} style={{
              padding: "8px 14px", border: "none", background: "transparent", cursor: "pointer",
              fontSize: 11, fontWeight: view === vc.key ? 700 : 400,
              color: view === vc.key ? C.accent : C.muted,
              borderBottom: view === vc.key ? `2px solid ${C.accent}` : "2px solid transparent",
              marginBottom: -1, letterSpacing: 0.1, display: "flex", alignItems: "center", gap: 4, whiteSpace: "nowrap",
            }}>
              <Icon size={11} /> {label}
            </button>
          );
        })}
      </div>

      {/* ════════════════════════════════════════════════════════════
          VIEW 1: OVERVIEW
      ════════════════════════════════════════════════════════════ */}
      {view === "overview" && (
        <>
          {/* Health card */}
          <div style={{
            background: health?.status === "ok" ? C.greenDim : C.redDim,
            border: `1px solid ${health?.status === "ok" ? C.green : C.red}`,
            borderRadius: 10, padding: "14px 18px", marginBottom: 16, display: "flex", alignItems: "center", gap: 12,
          }}>
            {health?.status === "ok"
              ? <CheckCircle2 size={20} color={C.green} />
              : <XCircle size={20} color={C.red} />
            }
            <div>
              <div style={{ fontSize: 13, fontWeight: 700, color: health?.status === "ok" ? C.green : C.red }}>
                {health ? (health.status === "ok" ? "Gateway Operational" : "Gateway Degraded") : "Gateway Status Unknown"}
              </div>
              <div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>
                {health ? `${health.service} v${health.version} \u2022 ${fmtDatetime(health.timestamp)}` : "Unable to reach the AI Security Gateway service"}
              </div>
              {health?.checks && (
                <div style={{ display: "flex", gap: 8, marginTop: 6 }}>
                  {Object.entries(health.checks).map(([k, v]) => (
                    <B key={k} c={v === "ok" ? "green" : "red"}>{k}: {v}</B>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Stats row */}
          <div style={{ display: "flex", gap: 10, marginBottom: 20 }}>
            <Stat l="Total Models" v={models.length} s={`${activeModels} active`} c="accent" i={Server} />
            <Stat l="DLP Policies" v={activeDlpPolicies} s={`${dlpPolicies.length} total`} c="blue" i={ShieldCheck} />
            <Stat l="Guardrail Rules" v={guardrailCount} s={`${guardrails.length} total`} c="purple" i={Shield} />
            <Stat l="Events Today" v={todayEvents.length} s="audit trail" c="green" i={Activity} />
            <Stat l="Blocked" v={blockedEvents} s="requests blocked" c={blockedEvents > 0 ? "red" : "green"} i={ShieldAlert} />
          </div>

          {/* Security Posture Section */}
          <Section title="Security Posture">
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              {/* Action Distribution */}
              <Card>
                <div style={{ fontSize: 11, fontWeight: 700, color: C.text, marginBottom: 10 }}>Request Action Distribution</div>
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: C.muted, marginBottom: 3 }}>
                      <span>Allowed</span><span style={{ color: C.green, fontWeight: 700 }}>{pctAllowed}%</span>
                    </div>
                    <div style={{ height: 8, borderRadius: 4, background: C.bg, overflow: "hidden" }}>
                      <div style={{ height: "100%", width: `${pctAllowed}%`, background: C.green, borderRadius: 4 }} />
                    </div>
                  </div>
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: C.muted, marginBottom: 3 }}>
                      <span>Redacted</span><span style={{ color: C.amber, fontWeight: 700 }}>{pctRedacted}%</span>
                    </div>
                    <div style={{ height: 8, borderRadius: 4, background: C.bg, overflow: "hidden" }}>
                      <div style={{ height: "100%", width: `${pctRedacted}%`, background: C.amber, borderRadius: 4 }} />
                    </div>
                  </div>
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: C.muted, marginBottom: 3 }}>
                      <span>Blocked</span><span style={{ color: C.red, fontWeight: 700 }}>{pctBlocked}%</span>
                    </div>
                    <div style={{ height: 8, borderRadius: 4, background: C.bg, overflow: "hidden" }}>
                      <div style={{ height: "100%", width: `${pctBlocked}%`, background: C.red, borderRadius: 4 }} />
                    </div>
                  </div>
                </div>
              </Card>

              {/* Threat Summary */}
              <Card>
                <div style={{ fontSize: 11, fontWeight: 700, color: C.text, marginBottom: 10 }}>Threat Summary</div>
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {topDlpPatterns.length > 0 ? (
                    <>
                      <div style={{ fontSize: 10, fontWeight: 600, color: C.accent, textTransform: "uppercase" }}>Top DLP Triggers</div>
                      {topDlpPatterns.map(([pattern, count]) => (
                        <div key={pattern} style={{ display: "flex", justifyContent: "space-between", fontSize: 10 }}>
                          <span style={{ color: C.dim }}>{pattern}</span>
                          <B c="amber">{count} findings</B>
                        </div>
                      ))}
                    </>
                  ) : (
                    <div style={{ fontSize: 10, color: C.muted }}>No DLP findings yet.</div>
                  )}
                  {topBlockedTopics.length > 0 && (
                    <>
                      <div style={{ fontSize: 10, fontWeight: 600, color: C.accent, textTransform: "uppercase", marginTop: 6 }}>Top Blocked Topics</div>
                      {topBlockedTopics.map(([topic, count]) => (
                        <div key={topic} style={{ display: "flex", justifyContent: "space-between", fontSize: 10 }}>
                          <span style={{ color: C.dim }}>{topic}</span>
                          <B c="red">{count}</B>
                        </div>
                      ))}
                    </>
                  )}
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, marginTop: 6, padding: "6px 0", borderTop: `1px solid ${C.border}` }}>
                    <span style={{ color: C.dim }}>Injection Attempts (24h)</span>
                    <B c={injectionAttempts > 0 ? "red" : "green"}>{injectionAttempts}</B>
                  </div>
                </div>
              </Card>
            </div>
          </Section>

          {/* Quick Setup Wizard */}
          <Section title="Quick Setup">
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 10 }}>
              {[
                { step: 1, label: "Register an LLM Model", done: hasModels, target: "models" as View },
                { step: 2, label: "Create a DLP Policy", done: hasDlpPolicies, target: "dlp_policies" as View },
                { step: 3, label: "Set Token Budgets", done: hasBudgets, target: "governance" as View },
                { step: 4, label: "Configure Guardrails", done: hasGuardrails, target: "guardrails" as View },
              ].map(s => (
                <Card key={s.step}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                    <div style={{
                      width: 24, height: 24, borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center",
                      background: s.done ? C.greenDim : C.card, border: `1px solid ${s.done ? C.green : C.border}`,
                      fontSize: 11, fontWeight: 700, color: s.done ? C.green : C.muted,
                    }}>
                      {s.done ? "\u2713" : s.step}
                    </div>
                    <span style={{ fontSize: 11, fontWeight: 600, color: C.text }}>{s.label}</span>
                  </div>
                  <div style={{ fontSize: 10, color: s.done ? C.green : C.muted, marginBottom: 8 }}>
                    {s.done ? "Completed" : "Not configured"}
                  </div>
                  <Btn small primary={!s.done} onClick={() => { setView(s.target); if (s.target === "dlp_policies") void loadDlpPolicies(); if (s.target === "governance") { void loadRules(); void loadBudgets(); } if (s.target === "guardrails") void loadGuardrails(); }}>
                    {s.done ? "Manage" : "Configure"}
                  </Btn>
                </Card>
              ))}
            </div>
          </Section>

          {/* Recent activity */}
          <Section title="Recent Activity" actions={
            <Btn small onClick={() => { setView("audit"); void loadAudit(); }}>View All</Btn>
          }>
            <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
              {auditEvents.length === 0 ? (
                <div style={{ padding: "32px 20px", textAlign: "center", color: C.muted, fontSize: 11 }}>No audit events yet. Events will appear as the gateway processes LLM requests.</div>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      {["Time", "Model", "Action", "Tokens", "Cost", "Status"].map(h => <th key={h} style={TH}>{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {auditEvents.slice(0, 10).map((e, i) => (
                      <tr key={e.id || i}
                        onMouseEnter={ev => ev.currentTarget.style.filter = "brightness(1.07)"}
                        onMouseLeave={ev => ev.currentTarget.style.filter = ""}>
                        <td style={{ ...TD(i), whiteSpace: "nowrap", fontSize: 10 }}>{fmtDatetime(e.created_at)}</td>
                        <td style={{ ...TD(i), fontWeight: 600, color: C.text }}>{e.model || "\u2014"}</td>
                        <td style={TD(i)}><B c={actionBadgeColor(e.action)}>{e.action}</B></td>
                        <td style={{ ...TD(i), fontSize: 10 }}>{(e.prompt_tokens || 0) + (e.completion_tokens || 0)}</td>
                        <td style={{ ...TD(i), color: C.amber, fontWeight: 600 }}>{fmtCost(e.cost_usd)}</td>
                        <td style={TD(i)}><B c={e.status === "success" ? "green" : "red"}>{e.status}</B></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </Section>

          {/* Quick Actions */}
          <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
            <Btn primary onClick={() => setView("models")}><Plus size={11} /> Register Model</Btn>
            <Btn onClick={() => { setView("dlp_policies"); void loadDlpPolicies(); }} style={{ background: C.blueDim, border: `1px solid ${C.blue}33`, color: C.blue }}>
              <ShieldCheck size={11} /> Create DLP Policy
            </Btn>
            <Btn onClick={() => setView("scan")} style={{ background: C.purpleDim, border: `1px solid ${C.purple}33`, color: C.purple }}>
              <Eye size={11} /> Scan Text
            </Btn>
            <Btn onClick={() => setView("realtime")} style={{ background: C.greenDim, border: `1px solid ${C.green}33`, color: C.green }}>
              <Radio size={11} /> Real-time Monitor
            </Btn>
          </div>
        </>
      )}

      {/* ════════════════════════════════════════════════════════════
          VIEW 2: MODELS
      ════════════════════════════════════════════════════════════ */}
      {view === "models" && (
        <>
          <Section title="Register New Model">
            <Card>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                <FG label="Model Name" required>
                  <Inp value={modelForm.name} onChange={e => setModelForm(f => ({ ...f, name: e.target.value }))} placeholder="e.g. GPT-4 Production" />
                </FG>
                <FG label="Provider" required>
                  <Sel value={modelForm.provider} onChange={e => setModelForm(f => ({ ...f, provider: e.target.value }))}>
                    {PROVIDERS.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
                  </Sel>
                </FG>
                <FG label="API Key">
                  <Inp type="password" value={modelForm.api_key} onChange={e => setModelForm(f => ({ ...f, api_key: e.target.value }))} placeholder="sk-..." />
                </FG>
                <FG label="Base URL">
                  <Inp value={modelForm.base_url} onChange={e => setModelForm(f => ({ ...f, base_url: e.target.value }))} placeholder="https://api.openai.com/v1" />
                </FG>
                <FG label="Model ID" required>
                  <Inp value={modelForm.model_id} onChange={e => setModelForm(f => ({ ...f, model_id: e.target.value }))} placeholder="gpt-4-turbo" />
                </FG>
                <FG label="Region">
                  <Inp value={modelForm.region} onChange={e => setModelForm(f => ({ ...f, region: e.target.value }))} placeholder="us-east-1" />
                </FG>
                <FG label="Max Tokens">
                  <Inp type="number" value={modelForm.max_tokens} onChange={e => setModelForm(f => ({ ...f, max_tokens: parseInt(e.target.value) || 0 }))} />
                </FG>
                <FG label="Rate Limit (RPM)">
                  <Inp type="number" value={modelForm.rate_limit_rpm} onChange={e => setModelForm(f => ({ ...f, rate_limit_rpm: parseInt(e.target.value) || 0 }))} />
                </FG>
                <FG label="Cost per 1K Input Tokens">
                  <Inp type="number" step="0.001" value={modelForm.cost_per_1k_input} onChange={e => setModelForm(f => ({ ...f, cost_per_1k_input: parseFloat(e.target.value) || 0 }))} />
                </FG>
                <FG label="Cost per 1K Output Tokens">
                  <Inp type="number" step="0.001" value={modelForm.cost_per_1k_output} onChange={e => setModelForm(f => ({ ...f, cost_per_1k_output: parseFloat(e.target.value) || 0 }))} />
                </FG>
                <FG label="Priority">
                  <Inp type="number" value={modelForm.priority} onChange={e => setModelForm(f => ({ ...f, priority: parseInt(e.target.value) || 1 }))} />
                </FG>
              </div>

              {modelFormErr && (
                <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 6, padding: "7px 10px", color: C.red, fontSize: 11, marginTop: 10, marginBottom: 10 }}>
                  {modelFormErr}
                </div>
              )}

              <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
                <Btn primary onClick={doCreateModel} disabled={modelFormBusy}>
                  <Plus size={11} /> {modelFormBusy ? "Registering..." : "Register Model"}
                </Btn>
              </div>
            </Card>
          </Section>

          <Section title={`Registered Models (${models.length})`} actions={
            <Btn small onClick={loadModels} disabled={loadingModels}><RefreshCw size={10} /></Btn>
          }>
            <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
              {loadingModels && models.length === 0 ? (
                <div style={{ padding: "32px 20px", textAlign: "center", color: C.muted, fontSize: 11 }}>Loading models...</div>
              ) : models.length === 0 ? (
                <div style={{ padding: "36px 20px", textAlign: "center" }}>
                  <Server size={28} color={C.border} style={{ marginBottom: 8 }} />
                  <div style={{ color: C.muted, fontSize: 11 }}>No models registered. Use the form above to add one.</div>
                </div>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      {["Name", "Provider", "Model ID", "Status", "Priority", "Rate Limit", "Cost/1K", "Actions"].map(h => <th key={h} style={TH}>{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {models.map((m, i) => (
                      <tr key={m.id}
                        onMouseEnter={e => e.currentTarget.style.filter = "brightness(1.07)"}
                        onMouseLeave={e => e.currentTarget.style.filter = ""}>
                        <td style={{ ...TD(i), color: C.text, fontWeight: 600 }}>
                          {m.name}
                          {m.region && <div style={{ fontSize: 10, color: C.muted, fontWeight: 400 }}>{m.region}</div>}
                        </td>
                        <td style={TD(i)}>{providerBadge(m.provider)}</td>
                        <td style={{ ...TD(i), fontFamily: "'JetBrains Mono', monospace", fontSize: 10 }}>{m.model_id}</td>
                        <td style={TD(i)}><B c={m.status === "active" || m.enabled ? "green" : "amber"}>{m.status || (m.enabled ? "active" : "disabled")}</B></td>
                        <td style={{ ...TD(i), color: C.text, fontWeight: 600, textAlign: "center" }}>{m.priority}</td>
                        <td style={{ ...TD(i), fontSize: 10 }}>{m.rate_limit_rpm} RPM</td>
                        <td style={{ ...TD(i), fontSize: 10 }}>
                          <span style={{ color: C.green }}>${m.cost_per_1k_input}</span> / <span style={{ color: C.amber }}>${m.cost_per_1k_output}</span>
                        </td>
                        <td style={{ ...TD(i) }}>
                          <div style={{ display: "flex", gap: 4 }}>
                            <Btn small onClick={() => doTestModel(m.id)} disabled={testingModel === m.id}>
                              <Zap size={10} /> {testingModel === m.id ? "..." : "Test"}
                            </Btn>
                            <Btn small danger onClick={() => doDeleteModel(m.id)} disabled={deleteBusy === m.id}>
                              <Trash2 size={10} />
                            </Btn>
                          </div>
                          {testResult[m.id] && (
                            <div style={{ fontSize: 9, marginTop: 3, color: testResult[m.id].startsWith("error") ? C.red : C.green }}>
                              {testResult[m.id]}
                            </div>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </Section>
        </>
      )}

      {/* ════════════════════════════════════════════════════════════
          VIEW 3: GOVERNANCE (Access Rules + Budgets)
      ════════════════════════════════════════════════════════════ */}
      {view === "governance" && (
        <Row2>
          {/* Left: Access Rules */}
          <div>
            <Section title="Create Access Rule">
              <Card>
                <FG label="Model IDs" required>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginBottom: 4 }}>
                    {models.map(m => (
                      <button key={m.id} onClick={() => {
                        setAccessForm(f => ({
                          ...f,
                          model_ids: f.model_ids.includes(m.model_id)
                            ? f.model_ids.filter(x => x !== m.model_id)
                            : [...f.model_ids, m.model_id],
                        }));
                      }} style={{
                        padding: "3px 8px", fontSize: 10, borderRadius: 4, cursor: "pointer",
                        background: accessForm.model_ids.includes(m.model_id) ? C.accentDim : "transparent",
                        border: `1px solid ${accessForm.model_ids.includes(m.model_id) ? C.accent : C.border}`,
                        color: accessForm.model_ids.includes(m.model_id) ? C.accent : C.muted,
                      }}>{m.model_id}</button>
                    ))}
                  </div>
                  {models.length === 0 && <div style={{ fontSize: 10, color: C.muted }}>Register models first to create access rules.</div>}
                </FG>

                <FG label="User Roles" required>
                  <div style={{ display: "flex", gap: 4 }}>
                    {ROLES.map(role => (
                      <button key={role} onClick={() => {
                        setAccessForm(f => ({
                          ...f,
                          user_roles: f.user_roles.includes(role)
                            ? f.user_roles.filter(x => x !== role)
                            : [...f.user_roles, role],
                        }));
                      }} style={{
                        padding: "4px 10px", fontSize: 10, borderRadius: 4, cursor: "pointer",
                        background: accessForm.user_roles.includes(role) ? C.blueDim : "transparent",
                        border: `1px solid ${accessForm.user_roles.includes(role) ? C.blue : C.border}`,
                        color: accessForm.user_roles.includes(role) ? C.blue : C.muted,
                      }}>{role}</button>
                    ))}
                  </div>
                </FG>

                <FG label="Max Tokens per Request">
                  <Inp type="number" value={accessForm.max_tokens_per_request} onChange={e => setAccessForm(f => ({ ...f, max_tokens_per_request: parseInt(e.target.value) || 0 }))} />
                </FG>

                <div style={{ marginBottom: 12 }}>
                  <Chk label="Require approval for access" checked={accessForm.require_approval} onChange={() => setAccessForm(f => ({ ...f, require_approval: !f.require_approval }))} />
                </div>

                {accessFormErr && (
                  <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 6, padding: "7px 10px", color: C.red, fontSize: 11, marginBottom: 10 }}>{accessFormErr}</div>
                )}

                <Btn primary full onClick={doCreateAccessRule} disabled={accessFormBusy}>
                  <Plus size={11} /> {accessFormBusy ? "Creating..." : "Create Access Rule"}
                </Btn>
              </Card>
            </Section>

            <Section title={`Access Rules (${accessRules.length})`} actions={
              <Btn small onClick={loadRules} disabled={loadingRules}><RefreshCw size={10} /></Btn>
            }>
              {accessRules.length === 0 ? (
                <Card><div style={{ textAlign: "center", padding: "24px 0", color: C.muted, fontSize: 11 }}>No access rules configured.</div></Card>
              ) : (
                <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead>
                      <tr>
                        {["Models", "Roles", "Max Tokens", "Approval", "Actions"].map(h => <th key={h} style={TH}>{h}</th>)}
                      </tr>
                    </thead>
                    <tbody>
                      {accessRules.map((r, i) => (
                        <tr key={r.id}>
                          <td style={{ ...TD(i), fontSize: 10 }}>{(r.model_ids || []).join(", ")}</td>
                          <td style={TD(i)}>
                            <div style={{ display: "flex", gap: 3, flexWrap: "wrap" }}>
                              {(r.user_roles || []).map(role => <B key={role} c="blue">{role}</B>)}
                            </div>
                          </td>
                          <td style={{ ...TD(i), color: C.text, fontWeight: 600 }}>{r.max_tokens_per_request?.toLocaleString()}</td>
                          <td style={TD(i)}><B c={r.require_approval ? "amber" : "green"}>{r.require_approval ? "Yes" : "No"}</B></td>
                          <td style={TD(i)}>
                            <Btn small danger onClick={() => doDeleteAccessRule(r.id)} disabled={deleteBusy === r.id}>
                              <Trash2 size={10} />
                            </Btn>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Section>
          </div>

          {/* Right: Token Budgets */}
          <div>
            <Section title="Create Token Budget">
              <Card>
                <FG label="Scope" required>
                  <Sel value={budgetForm.scope} onChange={e => setBudgetForm(f => ({ ...f, scope: e.target.value }))}>
                    <option value="tenant">Tenant</option>
                    <option value="user">User</option>
                    <option value="team">Team</option>
                  </Sel>
                </FG>

                {budgetForm.scope !== "tenant" && (
                  <FG label="Scope ID" required>
                    <Inp value={budgetForm.scope_id} onChange={e => setBudgetForm(f => ({ ...f, scope_id: e.target.value }))} placeholder="user-id or team-id" />
                  </FG>
                )}

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                  <FG label="Max Tokens">
                    <Inp type="number" value={budgetForm.max_tokens} onChange={e => setBudgetForm(f => ({ ...f, max_tokens: parseInt(e.target.value) || 0 }))} />
                  </FG>
                  <FG label="Max Cost (USD)">
                    <Inp type="number" step="0.01" value={budgetForm.max_cost_usd} onChange={e => setBudgetForm(f => ({ ...f, max_cost_usd: parseFloat(e.target.value) || 0 }))} />
                  </FG>
                </div>

                <FG label="Period">
                  <Sel value={budgetForm.period} onChange={e => setBudgetForm(f => ({ ...f, period: e.target.value }))}>
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                    <option value="monthly">Monthly</option>
                  </Sel>
                </FG>

                <FG label={`Alert at ${budgetForm.alert_at_pct}%`}>
                  <input type="range" min={10} max={100} step={5} value={budgetForm.alert_at_pct}
                    onChange={e => setBudgetForm(f => ({ ...f, alert_at_pct: parseInt(e.target.value) }))}
                    style={{ width: "100%" }} />
                </FG>

                <div style={{ marginBottom: 12 }}>
                  <Chk label="Hard cap (reject requests over budget)" checked={budgetForm.hard_cap} onChange={() => setBudgetForm(f => ({ ...f, hard_cap: !f.hard_cap }))} />
                </div>

                {budgetFormErr && (
                  <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 6, padding: "7px 10px", color: C.red, fontSize: 11, marginBottom: 10 }}>{budgetFormErr}</div>
                )}

                <Btn primary full onClick={doCreateBudget} disabled={budgetFormBusy}>
                  <Plus size={11} /> {budgetFormBusy ? "Creating..." : "Create Budget"}
                </Btn>
              </Card>
            </Section>

            <Section title={`Token Budgets (${budgets.length})`} actions={
              <Btn small onClick={loadBudgets} disabled={loadingBudgets}><RefreshCw size={10} /></Btn>
            }>
              {budgets.length === 0 ? (
                <Card><div style={{ textAlign: "center", padding: "24px 0", color: C.muted, fontSize: 11 }}>No budgets configured.</div></Card>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {budgets.map(b => {
                    const tokenPct = b.max_tokens > 0 ? Math.min(100, Math.round((b.used_tokens / b.max_tokens) * 100)) : 0;
                    const costPct = b.max_cost_usd > 0 ? Math.min(100, Math.round((b.cost_used_usd / b.max_cost_usd) * 100)) : 0;
                    return (
                      <Card key={b.id}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                            <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{b.scope}</span>
                            {b.scope_id && <span style={{ fontSize: 10, color: C.muted }}>({b.scope_id})</span>}
                            <B c="blue">{b.period}</B>
                            {b.hard_cap && <B c="red">Hard Cap</B>}
                          </div>
                        </div>

                        <div style={{ marginBottom: 6 }}>
                          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: C.muted, marginBottom: 3 }}>
                            <span>Tokens: {(b.used_tokens || 0).toLocaleString()} / {b.max_tokens.toLocaleString()}</span>
                            <span style={{ color: pctColor(tokenPct), fontWeight: 600 }}>{tokenPct}%</span>
                          </div>
                          <Bar pct={tokenPct} color={pctColor(tokenPct)} />
                        </div>

                        <div>
                          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: C.muted, marginBottom: 3 }}>
                            <span>Cost: {fmtCost(b.cost_used_usd)} / {fmtCost(b.max_cost_usd)}</span>
                            <span style={{ color: pctColor(costPct), fontWeight: 600 }}>{costPct}%</span>
                          </div>
                          <Bar pct={costPct} color={pctColor(costPct)} />
                        </div>

                        {b.reset_at && (
                          <div style={{ fontSize: 9, color: C.muted, marginTop: 6 }}>Resets: {fmtDatetime(b.reset_at)}</div>
                        )}
                      </Card>
                    );
                  })}
                </div>
              )}
            </Section>
          </div>
        </Row2>
      )}

      {/* ════════════════════════════════════════════════════════════
          VIEW 4: GUARDRAILS
      ════════════════════════════════════════════════════════════ */}
      {view === "guardrails" && (
        <>
          <Row2>
            {/* Create Guardrail form */}
            <div>
              <Section title="Create Guardrail">
                <Card>
                  <FG label="Guardrail Name" required>
                    <Inp value={guardrailForm.name} onChange={e => setGuardrailForm(f => ({ ...f, name: e.target.value }))} placeholder="e.g. Block Weapons Discussion" />
                  </FG>

                  <FG label="Action" required>
                    <Sel value={guardrailForm.action} onChange={e => setGuardrailForm(f => ({ ...f, action: e.target.value }))}>
                      <option value="block">Block</option>
                      <option value="warn">Warn</option>
                      <option value="log">Log Only</option>
                    </Sel>
                  </FG>

                  <FG label="Topics">
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 3 }}>
                      {TOPIC_OPTIONS.map(t => (
                        <Chk key={t} label={t.replace(/_/g, " ")}
                          checked={guardrailForm.topics.includes(t)}
                          onChange={() => setGuardrailForm(f => ({
                            ...f,
                            topics: f.topics.includes(t) ? f.topics.filter(x => x !== t) : [...f.topics, t],
                          }))} />
                      ))}
                    </div>
                  </FG>

                  <FG label="Custom Keywords (comma-separated)">
                    <Inp value={guardrailForm.keywords} onChange={e => setGuardrailForm(f => ({ ...f, keywords: e.target.value }))} placeholder="bomb, exploit, hack" />
                  </FG>

                  <div style={{ marginBottom: 12 }}>
                    <Chk label="Enable guardrail immediately" checked={guardrailForm.enabled} onChange={() => setGuardrailForm(f => ({ ...f, enabled: !f.enabled }))} />
                  </div>

                  {guardrailFormErr && (
                    <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 6, padding: "7px 10px", color: C.red, fontSize: 11, marginBottom: 10 }}>{guardrailFormErr}</div>
                  )}

                  <Btn primary full onClick={doCreateGuardrail} disabled={guardrailFormBusy}>
                    <Plus size={11} /> {guardrailFormBusy ? "Creating..." : "Create Guardrail"}
                  </Btn>
                </Card>
              </Section>
            </div>

            {/* Test Guardrail */}
            <div>
              <Section title="Test Guardrails">
                <Card>
                  <FG label="Test Text">
                    <Txt rows={5} value={guardrailTestText} onChange={e => setGuardrailTestText(e.target.value)}
                      placeholder="Paste text to check against guardrails..." />
                  </FG>
                  <Btn primary onClick={doTestGuardrail} disabled={guardrailTestBusy || !guardrailTestText.trim()}>
                    <Zap size={11} /> {guardrailTestBusy ? "Evaluating..." : "Test Against Guardrails"}
                  </Btn>

                  {guardrailTestResult && (
                    <div style={{ marginTop: 12, padding: "10px 14px", borderRadius: 8, background: guardrailTestResult.guardrail_hits?.length > 0 ? C.redDim : C.greenDim, border: `1px solid ${guardrailTestResult.guardrail_hits?.length > 0 ? C.red : C.green}` }}>
                      <div style={{ fontSize: 12, fontWeight: 700, color: guardrailTestResult.guardrail_hits?.length > 0 ? C.red : C.green, marginBottom: 4 }}>
                        {guardrailTestResult.guardrail_hits?.length > 0 ? "Guardrails triggered!" : "No guardrails triggered."}
                      </div>
                      {(guardrailTestResult.guardrail_hits || []).map((hit, i) => (
                        <div key={i} style={{ display: "flex", alignItems: "center", gap: 4, marginTop: 4 }}>
                          <B c="red">{hit}</B>
                        </div>
                      ))}
                    </div>
                  )}
                </Card>
              </Section>
            </div>
          </Row2>

          {/* Guardrails table */}
          <Section title={`Active Guardrails (${guardrails.length})`} actions={
            <Btn small onClick={loadGuardrails} disabled={loadingGuardrails}><RefreshCw size={10} /></Btn>
          }>
            <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
              {guardrails.length === 0 ? (
                <div style={{ padding: "36px 20px", textAlign: "center" }}>
                  <Shield size={28} color={C.border} style={{ marginBottom: 8 }} />
                  <div style={{ color: C.muted, fontSize: 11 }}>No guardrails configured. Create one using the form above.</div>
                </div>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      {["Name", "Topics", "Action", "Keywords", "Enabled", "Actions"].map(h => <th key={h} style={TH}>{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {guardrails.map((g, i) => (
                      <tr key={g.id}
                        onMouseEnter={e => e.currentTarget.style.filter = "brightness(1.07)"}
                        onMouseLeave={e => e.currentTarget.style.filter = ""}>
                        <td style={{ ...TD(i), color: C.text, fontWeight: 600 }}>{g.name}</td>
                        <td style={TD(i)}>
                          <div style={{ display: "flex", gap: 3, flexWrap: "wrap" }}>
                            {(g.topics || []).map(t => <B key={t} c="purple">{t.replace(/_/g, " ")}</B>)}
                          </div>
                        </td>
                        <td style={TD(i)}><B c={actionBadgeColor(g.action)}>{g.action}</B></td>
                        <td style={{ ...TD(i), fontSize: 10, color: C.dim }}>{(g.keywords || []).length} keywords</td>
                        <td style={TD(i)}><B c={g.enabled ? "green" : "amber"}>{g.enabled ? "Enabled" : "Disabled"}</B></td>
                        <td style={TD(i)}>
                          <Btn small danger onClick={() => doDeleteGuardrail(g.id)} disabled={deleteBusy === g.id}>
                            <Trash2 size={10} />
                          </Btn>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </Section>
        </>
      )}

      {/* ════════════════════════════════════════════════════════════
          VIEW 5: DLP POLICIES (merged from AIProtectTab)
      ════════════════════════════════════════════════════════════ */}
      {view === "dlp_policies" && (
        <Row2>
          {/* Left: create form */}
          <div>
            <Section title="Create DLP Policy">
              <Card>
                <FG label="Policy Name" required>
                  <Inp value={dlpPolicyForm.name} onChange={e => setDlpPolicyForm(f => ({ ...f, name: e.target.value }))} placeholder="e.g. Block PII in AI Output" />
                </FG>

                <FG label="Description">
                  <Inp value={dlpPolicyForm.description} onChange={e => setDlpPolicyForm(f => ({ ...f, description: e.target.value }))} placeholder="Optional description" />
                </FG>

                <FG label="Patterns to Enforce">
                  <div style={{ display: "flex", gap: 4, marginBottom: 8 }}>
                    <button onClick={() => setDlpPolicyForm(f => ({ ...f, patterns: ALL_PATTERNS.slice() }))} style={{
                      background: C.accentDim, border: `1px solid ${C.accent}33`, color: C.accent,
                      borderRadius: 5, padding: "3px 10px", fontSize: 10, cursor: "pointer",
                    }}>Select All</button>
                    <button onClick={() => setDlpPolicyForm(f => ({ ...f, patterns: [] }))} style={{
                      background: "transparent", border: `1px solid ${C.border}`, color: C.muted,
                      borderRadius: 5, padding: "3px 10px", fontSize: 10, cursor: "pointer",
                    }}>Clear All</button>
                  </div>
                  {Object.entries(PATTERN_GROUPS).map(([groupKey, group]) => (
                    <div key={groupKey} style={{ marginBottom: 8 }}>
                      <div style={{ fontSize: 10, fontWeight: 700, color: C.accent, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 3 }}>
                        {group.label}
                      </div>
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 2 }}>
                        {group.patterns.map(p => (
                          <Chk key={p} label={PATTERN_LABELS[p] || p} checked={dlpPolicyForm.patterns.includes(p)} onChange={() => toggleDlpPolicyPattern(p)} />
                        ))}
                      </div>
                    </div>
                  ))}
                </FG>

                <FG label="Action">
                  <Sel value={dlpPolicyForm.action} onChange={e => setDlpPolicyForm(f => ({ ...f, action: e.target.value as any }))}>
                    <option value="redact">Redact</option>
                    <option value="block">Block</option>
                    <option value="warn">Warn</option>
                  </Sel>
                </FG>

                <FG label="Scope">
                  <Sel value={dlpPolicyForm.scope} onChange={e => setDlpPolicyForm(f => ({ ...f, scope: e.target.value as any }))}>
                    <option value="input">Input (before LLM)</option>
                    <option value="output">Output (after LLM)</option>
                    <option value="both">Both</option>
                  </Sel>
                </FG>

                <FG label={`Min Confidence Threshold: ${dlpPolicyForm.min_confidence.toFixed(2)}`}>
                  <input type="range" min={0.5} max={1.0} step={0.05} value={dlpPolicyForm.min_confidence}
                    onChange={e => setDlpPolicyForm(f => ({ ...f, min_confidence: parseFloat(e.target.value) }))}
                    style={{ width: "100%" }} />
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9, color: C.muted }}>
                    <span>0.50 (Loose)</span><span>1.00 (Strict)</span>
                  </div>
                </FG>

                <FG label="Custom Regex Patterns (one per line)">
                  <Txt rows={3} value={dlpPolicyForm.custom_regex}
                    onChange={e => setDlpPolicyForm(f => ({ ...f, custom_regex: e.target.value }))}
                    placeholder={"\\b\\d{3}-\\d{2}-\\d{4}\\b\n\\bSECRET-[A-Z0-9]+\\b"} />
                </FG>

                <FG label="Pattern Exemptions (comma-separated)">
                  <Inp value={dlpPolicyForm.exemptions}
                    onChange={e => setDlpPolicyForm(f => ({ ...f, exemptions: e.target.value }))}
                    placeholder="test@example.com, 000-00-0000" />
                </FG>

                <div style={{ marginBottom: 12 }}>
                  <Chk label="Enable policy immediately" checked={dlpPolicyForm.enabled} onChange={() => setDlpPolicyForm(f => ({ ...f, enabled: !f.enabled }))} />
                </div>

                {dlpPolicyFormErr && (
                  <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 6, padding: "7px 10px", color: C.red, fontSize: 11, marginBottom: 10 }}>
                    {dlpPolicyFormErr}
                  </div>
                )}

                <Btn primary full onClick={doCreateDlpPolicy} disabled={dlpPolicyFormBusy}>
                  <Plus size={11} /> {dlpPolicyFormBusy ? "Creating..." : "Create Policy"}
                </Btn>
              </Card>
            </Section>
          </div>

          {/* Right: existing policies */}
          <div>
            <Section title={`Active DLP Policies (${dlpPolicies.length})`} actions={
              <Btn small onClick={loadDlpPolicies} disabled={loadingDlpPolicies}><RefreshCw size={10} /></Btn>
            }>
              {loadingDlpPolicies && dlpPolicies.length === 0 ? (
                <Card><div style={{ textAlign: "center", padding: "24px 0", color: C.muted, fontSize: 11 }}>Loading...</div></Card>
              ) : dlpPolicies.length === 0 ? (
                <Card>
                  <div style={{ textAlign: "center", padding: "24px 0" }}>
                    <ShieldCheck size={24} color={C.border} style={{ marginBottom: 6 }} />
                    <div style={{ color: C.muted, fontSize: 11 }}>No DLP policies yet. Create one using the form.</div>
                  </div>
                </Card>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {dlpPolicies.map(p => (
                    <Card key={p.id}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                        <div style={{ flex: 1, minWidth: 0, marginRight: 8 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                            <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{p.name}</span>
                            <B c={p.enabled ? "green" : "amber"}>{p.enabled ? "Active" : "Disabled"}</B>
                          </div>
                          {p.description && <div style={{ fontSize: 10, color: C.muted, marginBottom: 4 }}>{p.description}</div>}
                          <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 4 }}>
                            <B c={actionBadgeColor(p.action)}>{p.action}</B>
                            <B c="blue">{p.scope}</B>
                            {p.min_confidence && <B c="muted">conf &ge; {(p.min_confidence * 100).toFixed(0)}%</B>}
                          </div>
                          <div style={{ fontSize: 10, color: C.dim, marginTop: 2 }}>
                            {p.patterns?.join(", ")}
                          </div>
                          {p.custom_regex && p.custom_regex.length > 0 && (
                            <div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>+{p.custom_regex.length} custom regex</div>
                          )}
                          {p.exemptions && p.exemptions.length > 0 && (
                            <div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>{p.exemptions.length} exemptions</div>
                          )}
                        </div>
                        <Btn small danger onClick={() => doDeleteDlpPolicy(p.id)} disabled={dlpDeleteBusy === p.id}>
                          <Trash2 size={10} /> {dlpDeleteBusy === p.id ? "..." : "Delete"}
                        </Btn>
                      </div>
                    </Card>
                  ))}
                </div>
              )}
            </Section>
          </div>
        </Row2>
      )}

      {/* ════════════════════════════════════════════════════════════
          VIEW 6: DLP SCANNER (enhanced with simulate mode)
      ════════════════════════════════════════════════════════════ */}
      {view === "scan" && (
        <>
          {/* Mode toggle */}
          <div style={{ display: "flex", gap: 2, marginBottom: 16 }}>
            {(["manual", "simulate"] as const).map(m => (
              <button key={m} onClick={() => setScanMode(m)} style={{
                padding: "8px 18px", fontSize: 11, fontWeight: scanMode === m ? 700 : 400, cursor: "pointer",
                background: scanMode === m ? C.accentDim : "transparent",
                border: `1px solid ${scanMode === m ? C.accent : C.border}`,
                borderRadius: 6, color: scanMode === m ? C.accent : C.muted,
              }}>
                {m === "manual" ? "Manual Scan" : "Simulate Gateway"}
              </button>
            ))}
          </div>

          {scanMode === "manual" && (
            <>
              <Section title="AI Text Scanner (DLP + Injection + Toxicity + Guardrails)">
                <Card>
                  <FG label="Text to Analyze" required>
                    <Txt rows={10} value={scanInput} onChange={e => setScanInput(e.target.value)}
                      placeholder="Paste AI prompt, completion, or any text to scan for sensitive data, prompt injection, and guardrail violations..." />
                  </FG>

                  {scanErr && (
                    <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 6, padding: "8px 12px", color: C.red, fontSize: 11, marginBottom: 10 }}>{scanErr}</div>
                  )}

                  <div style={{ display: "flex", gap: 8 }}>
                    <Btn primary onClick={() => doScan("scan")} disabled={scanning}>
                      <Eye size={12} /> {scanning ? "Scanning..." : "Scan (Detect Only)"}
                    </Btn>
                    <Btn onClick={() => doScan("redact")} disabled={scanning} style={{ background: C.purpleDim, border: `1px solid ${C.purple}33`, color: C.purple }}>
                      <ShieldCheck size={12} /> {scanning ? "Scanning..." : "Scan & Redact"}
                    </Btn>
                    <Btn onClick={() => doScan("evaluate")} disabled={scanning} style={{ background: C.amberDim, border: `1px solid ${C.amber}33`, color: C.amber }}>
                      <Zap size={12} /> {scanning ? "Scanning..." : "Full Evaluate"}
                    </Btn>
                  </div>
                </Card>
              </Section>

              {scanResult && (
                <Section title="Scan Results">
                  <Card>
                    <div style={{
                      display: "flex", alignItems: "center", gap: 10, padding: "10px 14px", borderRadius: 8,
                      border: `1px solid ${scanResult.safe ? C.green : C.red}`,
                      background: scanResult.safe ? C.greenDim : C.redDim,
                      marginBottom: 14,
                    }}>
                      {scanResult.safe ? <CheckCircle2 size={16} color={C.green} /> : <XCircle size={16} color={C.red} />}
                      <div>
                        <div style={{ fontSize: 12, fontWeight: 700, color: scanResult.safe ? C.green : C.red }}>
                          {scanResult.safe ? "No issues detected -- text appears safe." : `${scanResult.finding_count || 0} finding(s) detected.`}
                        </div>
                      </div>
                    </div>

                    {scanResult.findings && scanResult.findings.length > 0 && (
                      <div style={{ marginBottom: 14 }}>
                        <div style={{ fontSize: 10, fontWeight: 700, color: C.accent, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6 }}>DLP Findings</div>
                        <div style={{ border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
                          <table style={{ width: "100%", borderCollapse: "collapse" }}>
                            <thead>
                              <tr>
                                {["Pattern", "Category", "Match Preview", "Confidence", "Position", "Count"].map(h => <th key={h} style={TH}>{h}</th>)}
                              </tr>
                            </thead>
                            <tbody>
                              {scanResult.findings.map((f, i) => {
                                const conf = typeof f.confidence === "number" ? f.confidence : 0;
                                const confColor = conf >= 0.9 ? C.red : conf >= 0.7 ? C.amber : C.muted;
                                return (
                                  <tr key={i}>
                                    <td style={TD(i)}><B c="amber">{f.pattern}</B></td>
                                    <td style={TD(i)}><B c="blue">{f.category || "pii"}</B></td>
                                    <td style={{ ...TD(i), fontFamily: "'JetBrains Mono', monospace", color: C.text, fontSize: 10 }}>{f.match || "\u2014"}</td>
                                    <td style={{ ...TD(i), color: confColor, fontWeight: 700 }}>{(conf * 100).toFixed(0)}%</td>
                                    <td style={{ ...TD(i), fontSize: 10 }}>{f.offset ?? "\u2014"}\u2013{f.end_offset ?? ""}</td>
                                    <td style={{ ...TD(i), color: C.text, fontWeight: 700 }}>{f.count ?? 1}</td>
                                  </tr>
                                );
                              })}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}

                    {scanResult.injection_score != null && (
                      <div style={{ marginBottom: 14 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                          <span style={{ fontSize: 10, fontWeight: 700, color: C.accent, textTransform: "uppercase", letterSpacing: "0.06em" }}>Prompt Injection Score</span>
                          <span style={{ fontSize: 12, fontWeight: 700, color: pctColor(scanResult.injection_score * 100) }}>
                            {(scanResult.injection_score * 100).toFixed(1)}%
                          </span>
                        </div>
                        <Bar pct={scanResult.injection_score * 100} color={pctColor(scanResult.injection_score * 100)} />
                      </div>
                    )}

                    {scanResult.toxicity_score != null && (
                      <div style={{ marginBottom: 14 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                          <span style={{ fontSize: 10, fontWeight: 700, color: C.accent, textTransform: "uppercase", letterSpacing: "0.06em" }}>Toxicity Score</span>
                          <span style={{ fontSize: 12, fontWeight: 700, color: pctColor(scanResult.toxicity_score * 100) }}>
                            {(scanResult.toxicity_score * 100).toFixed(1)}%
                          </span>
                        </div>
                        <Bar pct={scanResult.toxicity_score * 100} color={pctColor(scanResult.toxicity_score * 100)} />
                      </div>
                    )}

                    {scanResult.guardrail_hits && scanResult.guardrail_hits.length > 0 && (
                      <div style={{ marginBottom: 14 }}>
                        <div style={{ fontSize: 10, fontWeight: 700, color: C.accent, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6 }}>Guardrail Hits</div>
                        <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                          {scanResult.guardrail_hits.map((h, i) => <B key={i} c="red">{h}</B>)}
                        </div>
                      </div>
                    )}

                    {scanResult.redacted_text != null && (
                      <div>
                        <div style={{ fontSize: 10, fontWeight: 700, color: C.accent, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6 }}>Redacted Output</div>
                        <pre style={{
                          background: C.bg, border: `1px solid ${C.border}`, borderRadius: 8,
                          padding: "10px 12px", color: C.text, fontSize: 11, overflowX: "auto",
                          whiteSpace: "pre-wrap", wordBreak: "break-all",
                          fontFamily: "'JetBrains Mono', monospace", margin: 0,
                        }}>
                          {scanResult.redacted_text}
                        </pre>
                      </div>
                    )}
                  </Card>
                </Section>
              )}
            </>
          )}

          {scanMode === "simulate" && (
            <>
              <Section title="Simulate Gateway Pipeline">
                <Card>
                  <div style={{ fontSize: 10, color: C.muted, marginBottom: 12 }}>
                    Enter a full chat message to simulate the complete gateway pipeline: DLP scan, injection detection, toxicity check, and guardrail evaluation.
                  </div>
                  <FG label="System Prompt (optional)">
                    <Txt rows={3} value={simSystemPrompt} onChange={e => setSimSystemPrompt(e.target.value)}
                      placeholder="You are a helpful assistant..." />
                  </FG>
                  <FG label="User Prompt" required>
                    <Txt rows={6} value={simUserPrompt} onChange={e => setSimUserPrompt(e.target.value)}
                      placeholder="Enter user message to simulate..." />
                  </FG>

                  {scanErr && (
                    <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 6, padding: "8px 12px", color: C.red, fontSize: 11, marginBottom: 10 }}>{scanErr}</div>
                  )}

                  <Btn primary onClick={doSimulateGateway} disabled={scanning}>
                    <Zap size={12} /> {scanning ? "Simulating..." : "Run Full Pipeline Simulation"}
                  </Btn>
                </Card>
              </Section>

              {simPipelineResult && (
                <Section title="Pipeline Results">
                  <Card>
                    {/* Step-by-step pipeline visualization */}
                    <div style={{ display: "flex", alignItems: "center", gap: 0, marginBottom: 18, overflowX: "auto", padding: "8px 0" }}>
                      {simPipelineResult.steps.map((step: any, idx: number) => {
                        const icon = step.status === "pass" ? "\u2713" : step.status === "warn" ? "\u26A0" : step.status === "skip" ? "\u2014" : "\u2717";
                        const color = step.status === "pass" ? C.green : step.status === "warn" ? C.amber : step.status === "skip" ? C.muted : C.red;
                        const bgColor = step.status === "pass" ? C.greenDim : step.status === "warn" ? C.amberDim : step.status === "skip" ? C.card : C.redDim;
                        return (
                          <div key={idx} style={{ display: "flex", alignItems: "center" }}>
                            <div style={{
                              padding: "8px 14px", borderRadius: 8, border: `1px solid ${color}`,
                              background: bgColor, minWidth: 100, textAlign: "center",
                            }}>
                              <div style={{ fontSize: 14, fontWeight: 700, color }}>{icon}</div>
                              <div style={{ fontSize: 10, fontWeight: 600, color: C.text, marginTop: 2 }}>{step.name}</div>
                              <div style={{ fontSize: 9, color: C.muted, marginTop: 1 }}>{step.detail}</div>
                            </div>
                            {idx < simPipelineResult.steps.length - 1 && (
                              <div style={{ width: 24, height: 2, background: C.border, margin: "0 2px" }} />
                            )}
                          </div>
                        );
                      })}
                      <div style={{ display: "flex", alignItems: "center" }}>
                        <div style={{ width: 24, height: 2, background: C.border, margin: "0 2px" }} />
                        <div style={{
                          padding: "8px 18px", borderRadius: 8, fontWeight: 700, fontSize: 12,
                          background: simPipelineResult.finalAction === "ALLOWED" ? C.greenDim : simPipelineResult.finalAction === "REDACTED" ? C.amberDim : C.redDim,
                          color: simPipelineResult.finalAction === "ALLOWED" ? C.green : simPipelineResult.finalAction === "REDACTED" ? C.amber : C.red,
                          border: `1px solid ${simPipelineResult.finalAction === "ALLOWED" ? C.green : simPipelineResult.finalAction === "REDACTED" ? C.amber : C.red}`,
                        }}>
                          {simPipelineResult.finalAction}
                        </div>
                      </div>
                    </div>

                    {/* Detailed results from the underlying scan */}
                    {simPipelineResult.result?.findings?.length > 0 && (
                      <div style={{ marginBottom: 14 }}>
                        <div style={{ fontSize: 10, fontWeight: 700, color: C.accent, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6 }}>DLP Findings</div>
                        <div style={{ border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
                          <table style={{ width: "100%", borderCollapse: "collapse" }}>
                            <thead><tr>{["Pattern", "Category", "Match", "Confidence"].map(h => <th key={h} style={TH}>{h}</th>)}</tr></thead>
                            <tbody>
                              {simPipelineResult.result.findings.map((f: any, i: number) => (
                                <tr key={i}>
                                  <td style={TD(i)}><B c="amber">{f.pattern}</B></td>
                                  <td style={TD(i)}><B c="blue">{f.category || "pii"}</B></td>
                                  <td style={{ ...TD(i), fontFamily: "'JetBrains Mono', monospace", fontSize: 10 }}>{f.match || "\u2014"}</td>
                                  <td style={{ ...TD(i), fontWeight: 700 }}>{((f.confidence || 0) * 100).toFixed(0)}%</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}

                    {simPipelineResult.result?.redacted_text != null && (
                      <div>
                        <div style={{ fontSize: 10, fontWeight: 700, color: C.accent, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6 }}>Redacted Output</div>
                        <pre style={{
                          background: C.bg, border: `1px solid ${C.border}`, borderRadius: 8,
                          padding: "10px 12px", color: C.text, fontSize: 11, overflowX: "auto",
                          whiteSpace: "pre-wrap", wordBreak: "break-all",
                          fontFamily: "'JetBrains Mono', monospace", margin: 0,
                        }}>
                          {simPipelineResult.result.redacted_text}
                        </pre>
                      </div>
                    )}
                  </Card>
                </Section>
              )}
            </>
          )}
        </>
      )}

      {/* ════════════════════════════════════════════════════════════
          VIEW 7: REAL-TIME MONITORING
      ════════════════════════════════════════════════════════════ */}
      {view === "realtime" && (
        <>
          {/* Live counters */}
          <div style={{ display: "flex", gap: 10, marginBottom: 16 }}>
            <Stat l="Requests/min" v={realtimeCounters.rpm} s="live" c="accent" i={Activity} />
            <Stat l="Tokens/min" v={realtimeCounters.tpm.toLocaleString()} s="live" c="blue" i={Zap} />
            <Stat l="Blocked/min" v={realtimeCounters.bpm} s="live" c={realtimeCounters.bpm > 0 ? "red" : "green"} i={ShieldAlert} />
            <Stat l="Avg Latency" v={`${realtimeCounters.avgLatency}ms`} s="live" c={realtimeCounters.avgLatency > 500 ? "amber" : "green"} i={Clock} />
          </div>

          {/* Mini sparklines */}
          <div style={{ display: "flex", gap: 16, marginBottom: 20 }}>
            <Card>
              <div style={{ fontSize: 10, fontWeight: 600, color: C.muted, marginBottom: 6 }}>Requests (last 10 intervals)</div>
              <MiniBar values={realtimeHistory} color={C.accent} />
            </Card>
          </div>

          {/* Live request feed */}
          <Section title="Live Request Feed" actions={
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <B c="green" pulse>Auto-refresh: 5s</B>
              <Btn small onClick={loadRealtimeFeed}><RefreshCw size={10} /></Btn>
            </div>
          }>
            <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
              {realtimeFeed.length === 0 ? (
                <div style={{ padding: "32px 20px", textAlign: "center", color: C.muted, fontSize: 11 }}>
                  Waiting for requests... Feed will auto-refresh every 5 seconds.
                </div>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      {["Time", "User", "Model", "Action", "Tokens", "Cost", "Findings", "Latency"].map(h => <th key={h} style={TH}>{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {realtimeFeed.map((r, i) => {
                      const isBlocked = r.action === "block";
                      return (
                        <tr key={r.id || i} style={isBlocked ? { background: `${C.red}11` } : undefined}>
                          <td style={{ ...TD(i), whiteSpace: "nowrap", fontSize: 10, ...(isBlocked ? { background: `${C.red}11` } : {}) }}>{fmtDatetime(r.timestamp)}</td>
                          <td style={{ ...TD(i), fontSize: 10, ...(isBlocked ? { background: `${C.red}11` } : {}) }}>{r.user}</td>
                          <td style={{ ...TD(i), fontWeight: 600, color: C.text, ...(isBlocked ? { background: `${C.red}11` } : {}) }}>{r.model}</td>
                          <td style={{ ...TD(i), ...(isBlocked ? { background: `${C.red}11` } : {}) }}><B c={actionBadgeColor(r.action)}>{r.action}</B></td>
                          <td style={{ ...TD(i), fontSize: 10, ...(isBlocked ? { background: `${C.red}11` } : {}) }}>{r.tokens.toLocaleString()}</td>
                          <td style={{ ...TD(i), color: C.amber, fontWeight: 600, ...(isBlocked ? { background: `${C.red}11` } : {}) }}>{fmtCost(r.cost)}</td>
                          <td style={{ ...TD(i), color: r.findings > 0 ? C.red : C.green, fontWeight: 700, ...(isBlocked ? { background: `${C.red}11` } : {}) }}>{r.findings}</td>
                          <td style={{ ...TD(i), fontSize: 10, ...(isBlocked ? { background: `${C.red}11` } : {}) }}>{r.latency_ms}ms</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
          </Section>
        </>
      )}

      {/* ════════════════════════════════════════════════════════════
          VIEW 8: COMPLIANCE REPORTS
      ════════════════════════════════════════════════════════════ */}
      {view === "reports" && (
        <>
          {/* Period selector + export */}
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
            <div style={{ display: "flex", gap: 4 }}>
              {([["today", "Today"], ["7d", "Last 7 Days"], ["30d", "Last 30 Days"]] as const).map(([val, label]) => (
                <button key={val} onClick={() => setReportPeriod(val)} style={{
                  padding: "6px 14px", fontSize: 10, borderRadius: 5, cursor: "pointer",
                  background: reportPeriod === val ? C.accentDim : "transparent",
                  border: `1px solid ${reportPeriod === val ? C.accent : C.border}`,
                  color: reportPeriod === val ? C.accent : C.muted, fontWeight: reportPeriod === val ? 700 : 400,
                }}>{label}</button>
              ))}
            </div>
            <Btn small onClick={exportReportJSON}>
              <Download size={10} /> Export JSON
            </Btn>
          </div>

          {/* Summary cards */}
          <div style={{ display: "flex", gap: 10, marginBottom: 20 }}>
            <Stat l="Total Interactions" v={reportTotalInteractions} s="this period" c="accent" i={Activity} />
            <Stat l="PII Detected" v={reportTotalPii} s="findings" c={reportTotalPii > 0 ? "amber" : "green"} i={ShieldCheck} />
            <Stat l="Prompts Blocked" v={reportTotalBlocked} s="blocked requests" c={reportTotalBlocked > 0 ? "red" : "green"} i={ShieldAlert} />
            <Stat l="Total Cost" v={fmtCost(reportTotalCost)} s="all models" c="blue" i={CreditCard} />
          </div>

          {/* Breakdown by model */}
          <Section title="Breakdown by Model">
            <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
              {Object.keys(modelBreakdown).length === 0 ? (
                <div style={{ padding: "32px 20px", textAlign: "center", color: C.muted, fontSize: 11 }}>No data for this period.</div>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      {["Model", "Requests", "Tokens", "Cost", "Blocks", "DLP Findings"].map(h => <th key={h} style={TH}>{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(modelBreakdown).sort((a, b) => b[1].requests - a[1].requests).map(([model, data], i) => (
                      <tr key={model}>
                        <td style={{ ...TD(i), fontWeight: 600, color: C.text }}>{model}</td>
                        <td style={{ ...TD(i), color: C.text }}>{data.requests}</td>
                        <td style={{ ...TD(i), fontSize: 10 }}>{data.tokens.toLocaleString()}</td>
                        <td style={{ ...TD(i), color: C.amber, fontWeight: 600 }}>{fmtCost(data.cost)}</td>
                        <td style={{ ...TD(i), color: data.blocks > 0 ? C.red : C.green, fontWeight: 700 }}>{data.blocks}</td>
                        <td style={{ ...TD(i), color: data.dlpFindings > 0 ? C.amber : C.green, fontWeight: 700 }}>{data.dlpFindings}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </Section>

          {/* Breakdown by user */}
          <Section title="Breakdown by User">
            <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
              {Object.keys(userBreakdown).length === 0 ? (
                <div style={{ padding: "32px 20px", textAlign: "center", color: C.muted, fontSize: 11 }}>No data for this period.</div>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      {["User", "Requests", "Tokens", "Cost", "Policy Violations"].map(h => <th key={h} style={TH}>{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(userBreakdown).sort((a, b) => b[1].requests - a[1].requests).map(([user, data], i) => (
                      <tr key={user}>
                        <td style={{ ...TD(i), fontWeight: 600, color: C.text }}>{user}</td>
                        <td style={{ ...TD(i), color: C.text }}>{data.requests}</td>
                        <td style={{ ...TD(i), fontSize: 10 }}>{data.tokens.toLocaleString()}</td>
                        <td style={{ ...TD(i), color: C.amber, fontWeight: 600 }}>{fmtCost(data.cost)}</td>
                        <td style={{ ...TD(i), color: data.violations > 0 ? C.red : C.green, fontWeight: 700 }}>{data.violations}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </Section>
        </>
      )}

      {/* ════════════════════════════════════════════════════════════
          VIEW 9: AUDIT
      ════════════════════════════════════════════════════════════ */}
      {view === "audit" && (
        <>
          {/* Stats summary */}
          {auditStats && (
            <div style={{ display: "flex", gap: 10, marginBottom: 16 }}>
              <Stat l="Total Requests" v={auditStats.total_requests ?? auditEvents.length} s="all time" c="accent" i={Activity} />
              <Stat l="Blocked %" v={auditStats.blocked_pct != null ? `${auditStats.blocked_pct}%` : (auditEvents.length > 0 ? `${((blockedEvents / auditEvents.length) * 100).toFixed(1)}%` : "0%")} s="requests blocked" c="red" i={ShieldAlert} />
              <Stat l="Avg Cost" v={auditStats.avg_cost != null ? fmtCost(auditStats.avg_cost) : fmtCost(auditEvents.length > 0 ? auditEvents.reduce((a, e) => a + (e.cost_usd || 0), 0) / auditEvents.length : 0)} s="per request" c="amber" i={CreditCard} />
              <Stat l="Top Model" v={auditStats.top_model || (auditEvents.length > 0 ? auditEvents[0].model : "\u2014")} s="most used" c="blue" i={Server} />
            </div>
          )}

          {/* Filter bar */}
          <div style={{ display: "flex", gap: 8, marginBottom: 14, alignItems: "center" }}>
            <Filter size={12} color={C.muted} />
            <span style={{ fontSize: 10, color: C.muted }}>Filter by action:</span>
            {["", "allow", "redact", "block", "warn"].map(f => (
              <button key={f} onClick={() => { setAuditFilter(f); setAuditPage(0); }} style={{
                padding: "3px 10px", fontSize: 10, borderRadius: 4, cursor: "pointer",
                background: auditFilter === f ? C.accentDim : "transparent",
                border: `1px solid ${auditFilter === f ? C.accent : C.border}`,
                color: auditFilter === f ? C.accent : C.muted,
              }}>{f || "All"}</button>
            ))}
            <div style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
              <Btn small onClick={loadAudit} disabled={loadingAudit}><RefreshCw size={10} /> Refresh</Btn>
              <Btn small onClick={exportReportJSON}><Download size={10} /> Export</Btn>
            </div>
          </div>

          {/* Audit table */}
          <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
            {loadingAudit && auditEvents.length === 0 ? (
              <div style={{ padding: "32px 20px", textAlign: "center", color: C.muted, fontSize: 11 }}>Loading audit trail...</div>
            ) : filteredAudit.length === 0 ? (
              <div style={{ padding: "36px 20px", textAlign: "center" }}>
                <Activity size={28} color={C.border} style={{ marginBottom: 8 }} />
                <div style={{ color: C.muted, fontSize: 11 }}>No audit events found.</div>
              </div>
            ) : (
              <>
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", minWidth: 900 }}>
                    <thead>
                      <tr>
                        {["Time", "User", "Model", "Provider", "Action", "Prompt Tok", "Compl Tok", "Cost", "DLP", "Injection", "Latency", "Status"].map(h => <th key={h} style={TH}>{h}</th>)}
                      </tr>
                    </thead>
                    <tbody>
                      {pageAuditEvents.map((e, i) => (
                        <tr key={e.id || i}
                          onMouseEnter={ev => ev.currentTarget.style.filter = "brightness(1.07)"}
                          onMouseLeave={ev => ev.currentTarget.style.filter = ""}>
                          <td style={{ ...TD(i), whiteSpace: "nowrap", fontSize: 10 }}>{fmtDatetime(e.created_at)}</td>
                          <td style={{ ...TD(i), fontSize: 10 }}>{e.user_id || "\u2014"}</td>
                          <td style={{ ...TD(i), fontWeight: 600, color: C.text, fontSize: 10 }}>{e.model}</td>
                          <td style={TD(i)}>{providerBadge(e.provider)}</td>
                          <td style={TD(i)}><B c={actionBadgeColor(e.action)}>{e.action}</B></td>
                          <td style={{ ...TD(i), textAlign: "right", fontSize: 10 }}>{(e.prompt_tokens || 0).toLocaleString()}</td>
                          <td style={{ ...TD(i), textAlign: "right", fontSize: 10 }}>{(e.completion_tokens || 0).toLocaleString()}</td>
                          <td style={{ ...TD(i), color: C.amber, fontWeight: 600, fontSize: 10 }}>{fmtCost(e.cost_usd)}</td>
                          <td style={{ ...TD(i), color: (e.dlp_findings || 0) > 0 ? C.red : C.green, fontWeight: 700 }}>{e.dlp_findings || 0}</td>
                          <td style={{ ...TD(i), fontSize: 10 }}>
                            <span style={{ color: pctColor((e.injection_score || 0) * 100) }}>
                              {((e.injection_score || 0) * 100).toFixed(0)}%
                            </span>
                          </td>
                          <td style={{ ...TD(i), fontSize: 10 }}>{e.latency_ms || 0}ms</td>
                          <td style={TD(i)}><B c={e.status === "success" ? "green" : "red"}>{e.status}</B></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {/* Pagination */}
                {totalAuditPages > 1 && (
                  <div style={{ display: "flex", justifyContent: "center", gap: 8, padding: "10px 0", borderTop: `1px solid ${C.border}` }}>
                    <Btn small onClick={() => setAuditPage(p => Math.max(0, p - 1))} disabled={auditPage === 0}>Prev</Btn>
                    <span style={{ fontSize: 10, color: C.muted, lineHeight: "28px" }}>Page {auditPage + 1} of {totalAuditPages}</span>
                    <Btn small onClick={() => setAuditPage(p => Math.min(totalAuditPages - 1, p + 1))} disabled={auditPage >= totalAuditPages - 1}>Next</Btn>
                  </div>
                )}
              </>
            )}
          </div>
        </>
      )}
    </div>
  );
}
