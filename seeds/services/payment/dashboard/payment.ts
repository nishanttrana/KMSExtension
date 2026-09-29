import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

type PaymentKey = {
  id: string;
  tenant_id: string;
  key_id: string;
  payment_type: string;
  usage_code: string;
  mode_of_use: string;
  key_version_num: string;
  exportability: string;
  tr31_header: string;
  kcv: string;
};

type PaymentKeyListResponse = { items: PaymentKey[] };
type PaymentPolicyResponse = { policy: PaymentPolicy };
type PaymentAP2ProfileResponse = { profile: PaymentAP2Profile };

export type PaymentPolicy = {
  tenant_id: string;
  allowed_tr31_versions: string[];
  require_kbpk_for_tr31: boolean;
  allowed_kbpk_classes: string[];
  allowed_tr31_exportability: string[];
  tr31_exportability_matrix: Record<string, string[]>;
  payment_key_purpose_matrix: Record<string, string[]>;
  allow_inline_key_material: boolean;
  max_iso20022_payload_bytes: number;
  require_iso20022_lau_context: boolean;
  allowed_iso20022_canonicalization: string[];
  allowed_iso20022_signature_suites: string[];
  strict_pci_dss_4_0: boolean;
  require_key_id_for_operations: boolean;
  allow_tcp_interface: boolean;
  require_jwt_on_tcp: boolean;
  max_tcp_payload_bytes: number;
  allowed_tcp_operations: string[];
  allowed_pin_block_formats: string[];
  allowed_pin_translation_pairs: string[];
  disable_iso0_pin_block: boolean;
  allowed_cvv_service_codes: string[];
  pvki_min: number;
  pvki_max: number;
  allowed_issuer_profiles: string[];
  allowed_mac_domains: string[];
  allowed_mac_padding_profiles: string[];
  dual_control_required_operations: string[];
  hsm_required_operations: string[];
  rotation_interval_days_by_class: Record<string, number>;
  runtime_environment: string;
  disallow_test_keys_in_prod: boolean;
  disallow_prod_keys_in_test: boolean;
  decimalization_table: string;
  block_wildcard_pan: boolean;
  updated_by?: string;
  updated_at?: string;
};

export type PaymentAP2Profile = {
  tenant_id: string;
  enabled: boolean;
  allowed_protocol_bindings: string[];
  allowed_transaction_modes: string[];
  allowed_payment_rails: string[];
  allowed_currencies: string[];
  default_currency: string;
  require_intent_mandate: boolean;
  require_cart_mandate: boolean;
  require_payment_mandate: boolean;
  require_merchant_signature: boolean;
  require_verifiable_credential: boolean;
  require_wallet_attestation: boolean;
  require_risk_signals: boolean;
  require_tokenized_instrument: boolean;
  allow_x402_extension: boolean;
  max_human_present_amount_minor: number;
  max_human_not_present_amount_minor: number;
  trusted_credential_issuers: string[];
  updated_by?: string;
  updated_at?: string;
};

export type PaymentAP2Evaluation = {
  decision: string;
  allowed: boolean;
  required_mandates: string[];
  missing_artifacts: string[];
  reasons: string[];
  applied_controls: string[];
  recommended_next_steps: string[];
  max_permitted_amount_minor: number;
  request_fingerprint: string;
  profile: PaymentAP2Profile;
};

export type PaymentInjectionTerminal = {
  id: string;
  tenant_id: string;
  terminal_id: string;
  name: string;
  status: string;
  transport: string;
  key_algorithm: string;
  public_key_fingerprint: string;
  metadata_json?: string;
  verified_at?: string;
  last_seen_at?: string;
  created_at?: string;
  updated_at?: string;
};

export type PaymentInjectionJob = {
  id: string;
  tenant_id: string;
  terminal_id: string;
  payment_key_id: string;
  key_id: string;
  tr31_version: string;
  tr31_usage_code: string;
  tr31_kcv: string;
  status: string;
  ack_detail?: string;
  created_at?: string;
  updated_at?: string;
  delivered_at?: string;
  acked_at?: string;
};

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

export async function listPaymentKeys(session: AuthSession): Promise<PaymentKey[]> {
  const out = await serviceRequest<PaymentKeyListResponse>(
    session,
    "payment",
    `/payment/keys?${tenantQuery(session)}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

export async function getPaymentPolicy(session: AuthSession): Promise<PaymentPolicy> {
  const out = await serviceRequest<PaymentPolicyResponse>(session, "payment", `/payment/policy?${tenantQuery(session)}`);
  return (out?.policy || {}) as PaymentPolicy;
}

export async function updatePaymentPolicy(
  session: AuthSession,
  input: Partial<PaymentPolicy>
): Promise<PaymentPolicy> {
  const out = await serviceRequest<PaymentPolicyResponse>(session, "payment", `/payment/policy?${tenantQuery(session)}`, {
    method: "PUT",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return (out?.policy || {}) as PaymentPolicy;
}

export async function getPaymentAP2Profile(session: AuthSession): Promise<PaymentAP2Profile> {
  const out = await serviceRequest<PaymentAP2ProfileResponse>(session, "payment", `/payment/ap2/profile?${tenantQuery(session)}`);
  return (out?.profile || {}) as PaymentAP2Profile;
}

export async function updatePaymentAP2Profile(
  session: AuthSession,
  input: Partial<PaymentAP2Profile>
): Promise<PaymentAP2Profile> {
  const out = await serviceRequest<PaymentAP2ProfileResponse>(session, "payment", `/payment/ap2/profile?${tenantQuery(session)}`, {
    method: "PUT",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return (out?.profile || {}) as PaymentAP2Profile;
}

export async function evaluatePaymentAP2(
  session: AuthSession,
  input: {
    agent_id?: string;
    merchant_id?: string;
    operation?: string;
    protocol_binding: string;
    transaction_mode: string;
    payment_rail: string;
    currency: string;
    amount_minor: number;
    has_intent_mandate?: boolean;
    has_cart_mandate?: boolean;
    has_payment_mandate?: boolean;
    has_merchant_signature?: boolean;
    has_verifiable_credential?: boolean;
    has_wallet_attestation?: boolean;
    has_risk_signals?: boolean;
    payment_instrument_tokenized?: boolean;
    credential_issuer?: string;
  }
): Promise<PaymentAP2Evaluation> {
  const out = await serviceRequest<{ result: PaymentAP2Evaluation }>(session, "payment", "/payment/ap2/evaluate", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return (out?.result || {}) as PaymentAP2Evaluation;
}

export async function createTR31(
  session: AuthSession,
  input: {
    key_id: string;
    tr31_version?: string;
    algorithm?: string;
    usage_code?: string;
    mode_of_use?: string;
    exportability?: string;
    kbpk_key_id?: string;
    kbpk_key_b64?: string;
    kek_key_id?: string;
    kek_key_b64?: string;
    source_format?: string;
    material_b64?: string;
  }
): Promise<any> {
  const out = await serviceRequest<{ result: any }>(session, "payment", "/payment/tr31/create", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out?.result || {};
}

export async function translateTR31(
  session: AuthSession,
  input: {
    source_key_id?: string;
    source_block?: string;
    source_format: string;
    target_format: string;
    source_kbpk_key_id?: string;
    source_kbpk_key_b64?: string;
    target_kbpk_key_id?: string;
    target_kbpk_key_b64?: string;
    kek_key_id?: string;
    kek_key_b64?: string;
    tr31_version?: string;
    algorithm?: string;
    usage_code?: string;
    mode_of_use?: string;
    exportability?: string;
  }
): Promise<any> {
  const out = await serviceRequest<{ result: any }>(session, "payment", "/payment/tr31/translate", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out?.result || {};
}

export async function validateTR31(
  session: AuthSession,
  keyBlock: string,
  input?: {
    kbpk_key_id?: string;
    kbpk_key_b64?: string;
    kek_key_id?: string;
    kek_key_b64?: string;
  }
): Promise<any> {
  const out = await serviceRequest<{ result: any }>(session, "payment", "/payment/tr31/validate", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      key_block: keyBlock,
      ...(input || {})
    })
  });
  return out?.result || {};
}

export async function translatePIN(
  session: AuthSession,
  input: {
    source_format: string;
    target_format: string;
    pin_block: string;
    pan?: string;
    source_zpk_key_id?: string;
    source_zpk_key_b64?: string;
    target_zpk_key_id?: string;
    target_zpk_key_b64?: string;
  }
): Promise<string> {
  const out = await serviceRequest<{ pin_block: string }>(session, "payment", "/payment/pin/translate", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return String(out?.pin_block || "");
}

export async function generatePVV(
  session: AuthSession,
  input: {
    pin: string;
    pan: string;
    pvki: string;
    pvk_key_id?: string;
    pvk_key_b64?: string;
  }
): Promise<string> {
  const out = await serviceRequest<{ pvv: string }>(session, "payment", "/payment/pin/pvv/generate", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return String(out?.pvv || "");
}

export async function verifyPVV(
  session: AuthSession,
  input: {
    pin: string;
    pan: string;
    pvki: string;
    pvv: string;
    pvk_key_id?: string;
    pvk_key_b64?: string;
  }
): Promise<boolean> {
  const out = await serviceRequest<{ verified: boolean }>(session, "payment", "/payment/pin/pvv/verify", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return Boolean(out?.verified);
}

export async function computeCVV(
  session: AuthSession,
  input: {
    pan: string;
    expiry_yymm: string;
    service_code: string;
    cvk_key_id?: string;
    cvk_key_b64?: string;
  }
): Promise<string> {
  const out = await serviceRequest<{ cvv: string }>(session, "payment", "/payment/pin/cvv/compute", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return String(out?.cvv || "");
}

export async function verifyCVV(
  session: AuthSession,
  input: {
    pan: string;
    expiry_yymm: string;
    service_code: string;
    cvv: string;
    cvk_key_id?: string;
    cvk_key_b64?: string;
  }
): Promise<boolean> {
  const out = await serviceRequest<{ verified: boolean }>(session, "payment", "/payment/pin/cvv/verify", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return Boolean(out?.verified);
}

export async function computeMAC(
  session: AuthSession,
  input: {
    type: "retail" | "iso9797" | "cmac";
    key_id?: string;
    key_b64?: string;
    data_b64: string;
    algorithm?: number;
  }
): Promise<string> {
  const endpoint =
    input.type === "cmac"
      ? "/payment/mac/cmac"
      : input.type === "iso9797"
        ? "/payment/mac/iso9797"
        : "/payment/mac/retail";
  const out = await serviceRequest<{ mac_b64: string }>(session, "payment", endpoint, {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return String(out?.mac_b64 || "");
}

export async function verifyMAC(
  session: AuthSession,
  input: {
    type: "retail" | "iso9797" | "cmac";
    key_id?: string;
    key_b64?: string;
    data_b64: string;
    mac_b64: string;
    algorithm?: number;
  }
): Promise<boolean> {
  const out = await serviceRequest<{ verified: boolean }>(session, "payment", "/payment/mac/verify", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return Boolean(out?.verified);
}

export async function signISO20022(
  session: AuthSession,
  input: {
    key_id: string;
    xml: string;
  }
): Promise<any> {
  const out = await serviceRequest<{ result: any }>(session, "payment", "/payment/iso20022/sign", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out?.result || {};
}

export async function verifyISO20022(
  session: AuthSession,
  input: {
    key_id: string;
    xml: string;
    signature_b64: string;
  }
): Promise<boolean> {
  const out = await serviceRequest<{ verified: boolean }>(session, "payment", "/payment/iso20022/verify", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return Boolean(out?.verified);
}

export async function encryptISO20022(
  session: AuthSession,
  input: {
    key_id: string;
    xml: string;
    iv?: string;
    reference_id?: string;
  }
): Promise<any> {
  const out = await serviceRequest<{ result: any }>(session, "payment", "/payment/iso20022/encrypt", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out?.result || {};
}

export async function decryptISO20022(
  session: AuthSession,
  input: {
    key_id: string;
    ciphertext: string;
    iv?: string;
  }
): Promise<string> {
  const out = await serviceRequest<{ xml: string }>(session, "payment", "/payment/iso20022/decrypt", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return String(out?.xml || "");
}

export async function generateLAU(
  session: AuthSession,
  input: {
    key_id?: string;
    lau_key_b64?: string;
    message: string;
    context?: string;
  }
): Promise<string> {
  const out = await serviceRequest<{ lau_b64: string }>(session, "payment", "/payment/iso20022/lau/generate", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return String(out?.lau_b64 || "");
}

export async function verifyLAU(
  session: AuthSession,
  input: {
    key_id?: string;
    lau_key_b64?: string;
    message: string;
    context?: string;
    lau_b64: string;
  }
): Promise<boolean> {
  const out = await serviceRequest<{ verified: boolean }>(session, "payment", "/payment/iso20022/lau/verify", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return Boolean(out?.verified);
}

export async function listInjectionTerminals(session: AuthSession): Promise<PaymentInjectionTerminal[]> {
  const out = await serviceRequest<{ items: PaymentInjectionTerminal[] }>(
    session,
    "payment",
    `/payment/injection/terminals?${tenantQuery(session)}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

export async function registerInjectionTerminal(
  session: AuthSession,
  input: {
    terminal_id: string;
    name: string;
    public_key_pem: string;
    transport?: string;
    key_algorithm?: string;
    metadata_json?: string;
  }
): Promise<PaymentInjectionTerminal> {
  const out = await serviceRequest<{ item: PaymentInjectionTerminal }>(
    session,
    "payment",
    `/payment/injection/terminals?${tenantQuery(session)}`,
    {
      method: "POST",
      body: JSON.stringify({
        tenant_id: session.tenantId,
        ...input
      })
    }
  );
  return (out?.item || {}) as PaymentInjectionTerminal;
}

export async function issueInjectionChallenge(
  session: AuthSession,
  terminalRowID: string
): Promise<{ nonce: string; expires_at: string }> {
  const out = await serviceRequest<{ challenge: { nonce: string; expires_at: string } }>(
    session,
    "payment",
    `/payment/injection/terminals/${encodeURIComponent(String(terminalRowID || ""))}/challenge?${tenantQuery(session)}`,
    {
      method: "POST",
      body: JSON.stringify({})
    }
  );
  return out?.challenge || { nonce: "", expires_at: "" };
}

export async function verifyInjectionChallenge(
  session: AuthSession,
  terminalRowID: string,
  signatureB64: string
): Promise<{ terminal: PaymentInjectionTerminal; auth_token: string; token_type: string }> {
  const out = await serviceRequest<{ result: { terminal: PaymentInjectionTerminal; auth_token: string; token_type: string } }>(
    session,
    "payment",
    `/payment/injection/terminals/${encodeURIComponent(String(terminalRowID || ""))}/verify?${tenantQuery(session)}`,
    {
      method: "POST",
      body: JSON.stringify({
        tenant_id: session.tenantId,
        signature_b64: signatureB64
      })
    }
  );
  return out?.result || { terminal: {} as PaymentInjectionTerminal, auth_token: "", token_type: "" };
}

export async function listInjectionJobs(
  session: AuthSession,
  terminalRowID?: string
): Promise<PaymentInjectionJob[]> {
  const qp = new URLSearchParams();
  qp.set("tenant_id", session.tenantId);
  if (String(terminalRowID || "").trim()) {
    qp.set("terminal_id", String(terminalRowID).trim());
  }
  const out = await serviceRequest<{ items: PaymentInjectionJob[] }>(
    session,
    "payment",
    `/payment/injection/jobs?${qp.toString()}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

export async function createInjectionJob(
  session: AuthSession,
  input: {
    terminal_id: string;
    payment_key_id: string;
    tr31_version?: string;
    kbpk_key_id?: string;
    kbpk_key_b64?: string;
    kek_key_id?: string;
    kek_key_b64?: string;
  }
): Promise<PaymentInjectionJob> {
  const out = await serviceRequest<{ item: PaymentInjectionJob }>(
    session,
    "payment",
    `/payment/injection/jobs?${tenantQuery(session)}`,
    {
      method: "POST",
      body: JSON.stringify({
        tenant_id: session.tenantId,
        ...input
      })
    }
  );
  return (out?.item || {}) as PaymentInjectionJob;
}
