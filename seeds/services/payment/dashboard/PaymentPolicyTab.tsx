// @ts-nocheck -- legacy tab: strict typing deferred, do not add new suppressions
import { useEffect, useMemo, useState } from "react";
import {
  CreditCard,
  Landmark,
  ShieldCheck,
  Sparkles,
  Workflow,
  Wallet
} from "lucide-react";
import {
  B,
  Btn,
  Card,
  Chk,
  FG,
  Inp,
  Section,
  Sel,
  Tabs,
  Txt
} from "../legacyPrimitives";
import { C } from "../theme";
import { errMsg } from "../runtimeUtils";
import {
  getPaymentAP2Profile,
  getPaymentPolicy,
  updatePaymentAP2Profile,
  updatePaymentPolicy
} from "../../../lib/payment";

const tr31VersionOptions = ["B", "C", "D"];
const paymentKeyClassOptions = ["ZMK", "TMK", "TPK", "BMK", "BDK", "IPEK", "ZPK", "ZAK", "ZEK", "TAK", "CVK", "PVK", "KBPK"];
const tr31ExportabilityOptions = ["E", "N", "S"];
const isoCanonicalizationOptions = ["exc-c14n", "c14n11"];
const isoSignatureSuiteOptions = ["rsa-pss-sha256", "rsa-pkcs1-sha256", "ecdsa-sha256", "ecdsa-sha384"];
const macDomainOptions = ["retail", "iso9797", "cmac"];
const macPaddingOptions = ["ansi-x9.19-m1", "iso9797-m2", "cmac"];
const traditionalTCPOperations = [
  "tr31.create", "tr31.parse", "tr31.translate", "tr31.validate", "tr31.key-usages",
  "pin.translate", "pin.pvv.generate", "pin.pvv.verify", "pin.offset.generate", "pin.offset.verify", "pin.cvv.compute", "pin.cvv.verify",
  "mac.retail", "mac.iso9797", "mac.cmac", "mac.verify"
];
const modernTCPOperations = [
  "iso20022.sign", "iso20022.verify", "iso20022.encrypt", "iso20022.decrypt", "iso20022.lau.generate", "iso20022.lau.verify"
];
const allTCPOperations = [...traditionalTCPOperations, ...modernTCPOperations];
const traditionalSensitiveOperations = [...traditionalTCPOperations, "key.rotate"];
const modernSensitiveOperations = [...modernTCPOperations, "key.rotate"];
const pinFormatOptions = ["ISO-0", "ISO-1", "ISO-3"];

const defaultAP2ProfileState = {
  tenant_id: "",
  enabled: false,
  allowed_protocol_bindings: ["a2a", "mcp"],
  allowed_transaction_modes: ["human_present", "human_not_present"],
  allowed_payment_rails: ["card", "ach", "rtp"],
  allowed_currencies: ["USD"],
  default_currency: "USD",
  require_intent_mandate: true,
  require_cart_mandate: true,
  require_payment_mandate: true,
  require_merchant_signature: true,
  require_verifiable_credential: true,
  require_wallet_attestation: false,
  require_risk_signals: true,
  require_tokenized_instrument: true,
  allow_x402_extension: false,
  max_human_present_amount_minor: 1000000,
  max_human_not_present_amount_minor: 250000,
  trusted_credential_issuers: []
};

function toggleStringList(list: string[] | undefined, value: string) {
  const current = Array.isArray(list) ? [...list] : [];
  return current.includes(value) ? current.filter((item) => item !== value) : [...current, value];
}

function parseCSVList(raw: string) {
  return Array.from(
    new Set(
      String(raw || "")
        .split(/[\n,]/g)
        .map((value) => String(value || "").trim())
        .filter(Boolean)
    )
  );
}

function csvList(value: any): string {
  return Array.isArray(value) ? value.map((item) => String(item || "").trim()).filter(Boolean).join(", ") : "";
}

function toPrettyJSON(input: any) {
  const value = input && typeof input === "object" && !Array.isArray(input) ? input : {};
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return "{}";
  }
}

function parseStringArrayMap(raw: string, label: string): Record<string, string[]> {
  let parsed: any;
  try {
    parsed = JSON.parse(String(raw || "{}"));
  } catch {
    throw new Error(`${label} must be valid JSON object.`);
  }
  if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new Error(`${label} must be a JSON object.`);
  }
  const out: Record<string, string[]> = {};
  Object.entries(parsed).forEach(([key, val]) => {
    const mapKey = String(key || "").trim();
    if (!mapKey) {
      return;
    }
    if (!Array.isArray(val)) {
      throw new Error(`${label}.${mapKey} must be an array of strings.`);
    }
    const normalized = Array.from(new Set(val.map((item) => String(item || "").trim()).filter(Boolean)));
    if (normalized.length) {
      out[mapKey] = normalized;
    }
  });
  return out;
}

function parseStringIntMap(raw: string, label: string): Record<string, number> {
  let parsed: any;
  try {
    parsed = JSON.parse(String(raw || "{}"));
  } catch {
    throw new Error(`${label} must be valid JSON object.`);
  }
  if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new Error(`${label} must be a JSON object.`);
  }
  const out: Record<string, number> = {};
  Object.entries(parsed).forEach(([key, val]) => {
    const mapKey = String(key || "").trim();
    if (!mapKey) {
      return;
    }
    const parsedNum = Math.floor(Number(val));
    if (!Number.isFinite(parsedNum) || parsedNum <= 0) {
      throw new Error(`${label}.${mapKey} must be a positive integer.`);
    }
    out[mapKey] = parsedNum;
  });
  return out;
}

export const PaymentPolicyTab = ({ session, onToast }) => {
  const [policyTab, setPolicyTab] = useState("Traditional Payment");
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [payPolicy, setPayPolicy] = useState<any>(null);
  const [ap2Profile, setAp2Profile] = useState<any>(defaultAP2ProfileState);
  const [tr31ExportabilityMatrixText, setTR31ExportabilityMatrixText] = useState("{}");
  const [paymentKeyPurposeMatrixText, setPaymentKeyPurposeMatrixText] = useState("{}");
  const [rotationDaysByClassText, setRotationDaysByClassText] = useState("{}");
  const [pinTranslationPairsText, setPINTranslationPairsText] = useState("");
  const [cvvServiceCodesText, setCVVServiceCodesText] = useState("");
  const [issuerProfilesText, setIssuerProfilesText] = useState("");
  const [ap2BindingsText, setAP2BindingsText] = useState("a2a, mcp");
  const [ap2ModesText, setAP2ModesText] = useState("human_present, human_not_present");
  const [ap2RailsText, setAP2RailsText] = useState("card, ach, rtp");
  const [ap2CurrenciesText, setAP2CurrenciesText] = useState("USD");
  const [ap2IssuersText, setAP2IssuersText] = useState("");

  const hydrateAP2Profile = (profile: any) => {
    const merged = { ...defaultAP2ProfileState, ...(profile || {}) };
    setAp2Profile(merged);
    setAP2BindingsText(csvList(merged.allowed_protocol_bindings) || "a2a, mcp");
    setAP2ModesText(csvList(merged.allowed_transaction_modes) || "human_present, human_not_present");
    setAP2RailsText(csvList(merged.allowed_payment_rails) || "card, ach, rtp");
    setAP2CurrenciesText(csvList(merged.allowed_currencies) || String(merged.default_currency || "USD"));
    setAP2IssuersText(csvList(merged.trusted_credential_issuers));
  };

  const loadAll = async (silent = false) => {
    if (!session?.token) {
      setPayPolicy(null);
      hydrateAP2Profile(defaultAP2ProfileState);
      setTR31ExportabilityMatrixText("{}");
      setPaymentKeyPurposeMatrixText("{}");
      setRotationDaysByClassText("{}");
      setPINTranslationPairsText("");
      setCVVServiceCodesText("");
      setIssuerProfilesText("");
      return;
    }
    if (!silent) {
      setLoading(true);
    }
    try {
      const [pp, ap2] = await Promise.all([
        getPaymentPolicy(session),
        getPaymentAP2Profile(session)
      ]);
      setPayPolicy({
        tenant_id: String(pp?.tenant_id || session?.tenantId || ""),
        allowed_tr31_versions: Array.isArray(pp?.allowed_tr31_versions) && pp.allowed_tr31_versions.length ? pp.allowed_tr31_versions : tr31VersionOptions,
        require_kbpk_for_tr31: Boolean(pp?.require_kbpk_for_tr31),
        allowed_kbpk_classes: Array.isArray(pp?.allowed_kbpk_classes) ? pp.allowed_kbpk_classes : [],
        allowed_tr31_exportability: Array.isArray(pp?.allowed_tr31_exportability) && pp.allowed_tr31_exportability.length ? pp.allowed_tr31_exportability : tr31ExportabilityOptions,
        allow_inline_key_material: Boolean(pp?.allow_inline_key_material),
        max_iso20022_payload_bytes: Math.max(1024, Number(pp?.max_iso20022_payload_bytes || 262144)),
        require_iso20022_lau_context: Boolean(pp?.require_iso20022_lau_context),
        allowed_iso20022_canonicalization: Array.isArray(pp?.allowed_iso20022_canonicalization) ? pp.allowed_iso20022_canonicalization : [],
        allowed_iso20022_signature_suites: Array.isArray(pp?.allowed_iso20022_signature_suites) ? pp.allowed_iso20022_signature_suites : [],
        strict_pci_dss_4_0: Boolean(pp?.strict_pci_dss_4_0),
        require_key_id_for_operations: Boolean(pp?.require_key_id_for_operations),
        allow_tcp_interface: Boolean(pp?.allow_tcp_interface ?? true),
        require_jwt_on_tcp: Boolean(pp?.require_jwt_on_tcp ?? true),
        max_tcp_payload_bytes: Math.max(4096, Number(pp?.max_tcp_payload_bytes || 262144)),
        allowed_tcp_operations: Array.isArray(pp?.allowed_tcp_operations) && pp.allowed_tcp_operations.length ? pp.allowed_tcp_operations : allTCPOperations,
        allowed_pin_block_formats: Array.isArray(pp?.allowed_pin_block_formats) && pp.allowed_pin_block_formats.length ? pp.allowed_pin_block_formats : pinFormatOptions,
        allowed_pin_translation_pairs: Array.isArray(pp?.allowed_pin_translation_pairs) ? pp.allowed_pin_translation_pairs : [],
        disable_iso0_pin_block: Boolean(pp?.disable_iso0_pin_block),
        allowed_cvv_service_codes: Array.isArray(pp?.allowed_cvv_service_codes) ? pp.allowed_cvv_service_codes : [],
        pvki_min: Number.isFinite(Number(pp?.pvki_min)) ? Math.max(0, Math.min(9, Number(pp?.pvki_min))) : 0,
        pvki_max: Number.isFinite(Number(pp?.pvki_max)) ? Math.max(0, Math.min(9, Number(pp?.pvki_max))) : 9,
        allowed_issuer_profiles: Array.isArray(pp?.allowed_issuer_profiles) ? pp.allowed_issuer_profiles : [],
        allowed_mac_domains: Array.isArray(pp?.allowed_mac_domains) ? pp.allowed_mac_domains : [],
        allowed_mac_padding_profiles: Array.isArray(pp?.allowed_mac_padding_profiles) ? pp.allowed_mac_padding_profiles : [],
        dual_control_required_operations: Array.isArray(pp?.dual_control_required_operations) ? pp.dual_control_required_operations : [],
        hsm_required_operations: Array.isArray(pp?.hsm_required_operations) ? pp.hsm_required_operations : [],
        runtime_environment: String(pp?.runtime_environment || "prod").toLowerCase() === "test" ? "test" : "prod",
        disallow_test_keys_in_prod: Boolean(pp?.disallow_test_keys_in_prod),
        disallow_prod_keys_in_test: Boolean(pp?.disallow_prod_keys_in_test),
        decimalization_table: String(pp?.decimalization_table || "0123456789012345"),
        block_wildcard_pan: Boolean(pp?.block_wildcard_pan ?? true)
      });
      setTR31ExportabilityMatrixText(toPrettyJSON(pp?.tr31_exportability_matrix));
      setPaymentKeyPurposeMatrixText(toPrettyJSON(pp?.payment_key_purpose_matrix));
      setRotationDaysByClassText(toPrettyJSON(pp?.rotation_interval_days_by_class));
      setPINTranslationPairsText(Array.isArray(pp?.allowed_pin_translation_pairs) ? pp.allowed_pin_translation_pairs.join(", ") : "");
      setCVVServiceCodesText(Array.isArray(pp?.allowed_cvv_service_codes) ? pp.allowed_cvv_service_codes.join(", ") : "");
      setIssuerProfilesText(Array.isArray(pp?.allowed_issuer_profiles) ? pp.allowed_issuer_profiles.join(", ") : "");
      hydrateAP2Profile(ap2);
    } catch (error) {
      if (!silent) {
        onToast?.(`Payment policy load failed: ${errMsg(error)}`);
      }
    } finally {
      if (!silent) {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    void loadAll();
  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: intentional refetch on listed keys / run-once-on-mount; the only omitted dep is a per-render load/refresh closure (wrap in useCallback to drop this suppression). behaviour verified correct.
  }, [session?.token, session?.tenantId]);

  const summaryCards = useMemo(() => {
    if (policyTab === "Traditional Payment") {
      return [
        {
          label: "TR-31 Versions",
          value: String((payPolicy?.allowed_tr31_versions || []).length || 0),
          sub: (payPolicy?.allowed_tr31_versions || []).join(", ") || "No versions configured",
          icon: CreditCard,
          color: C.accent
        },
        {
          label: "Payment TCP",
          value: payPolicy?.allow_tcp_interface ? "On" : "Off",
          sub: payPolicy?.allow_tcp_interface ? (payPolicy?.require_jwt_on_tcp ? "JWT required" : "JWT optional") : "Interface disabled",
          icon: Workflow,
          color: payPolicy?.allow_tcp_interface ? C.blue : C.amber
        },
        {
          label: "PIN Formats",
          value: String((payPolicy?.allowed_pin_block_formats || []).length || 0),
          sub: (payPolicy?.allowed_pin_block_formats || []).join(", ") || "No formats allowed",
          icon: Wallet,
          color: C.purple
        },
        {
          label: "Dual Control",
          value: String((payPolicy?.dual_control_required_operations || []).filter((item: string) => traditionalSensitiveOperations.includes(item)).length || 0),
          sub: "Traditional approvals",
          icon: ShieldCheck,
          color: C.amber
        },
        {
          label: "HSM Required",
          value: String((payPolicy?.hsm_required_operations || []).filter((item: string) => traditionalSensitiveOperations.includes(item)).length || 0),
          sub: "Hardware-bound classic ops",
          icon: Landmark,
          color: C.green
        },
        {
          label: "Runtime",
          value: String(payPolicy?.runtime_environment || "-").toUpperCase(),
          sub: payPolicy?.require_key_id_for_operations ? "Key ID enforced" : "Inline key material allowed",
          icon: CreditCard,
          color: C.yellow
        }
      ];
    }
    return [
      {
        label: "ISO 20022",
        value: String((payPolicy?.allowed_iso20022_signature_suites || []).length || 0),
        sub: "Signature suites allowed",
        icon: Sparkles,
        color: C.accent
      },
      {
        label: "LAU Context",
        value: payPolicy?.require_iso20022_lau_context ? "Required" : "Optional",
        sub: `Max payload ${String(payPolicy?.max_iso20022_payload_bytes || 262144)}`,
        icon: Workflow,
        color: C.blue
      },
      {
        label: "AP2 Profile",
        value: ap2Profile?.enabled ? "Enabled" : "Disabled",
        sub: csvList(ap2Profile?.allowed_protocol_bindings) || "No bindings configured",
        icon: Sparkles,
        color: ap2Profile?.enabled ? C.green : C.amber
      },
      {
        label: "AP2 Rails",
        value: String((ap2Profile?.allowed_payment_rails || []).length || 0),
        sub: csvList(ap2Profile?.allowed_payment_rails) || "No rails configured",
        icon: CreditCard,
        color: C.purple
      },
      {
        label: "Modern Guardrails",
        value: String((payPolicy?.dual_control_required_operations || []).filter((item: string) => modernSensitiveOperations.includes(item)).length || 0),
        sub: "Approval-gated modern ops",
        icon: ShieldCheck,
        color: C.amber
      },
      {
        label: "Trusted Issuers",
        value: String((ap2Profile?.trusted_credential_issuers || []).length || 0),
        sub: csvList(ap2Profile?.trusted_credential_issuers) || "Optional",
        icon: Landmark,
        color: C.yellow
      }
    ];
  }, [ap2Profile, payPolicy, policyTab]);

  const saveAll = async () => {
    if (!session?.token) {
      onToast?.("Login is required to update payment policy.");
      return;
    }
    if (!payPolicy) {
      onToast?.("Policy settings are not loaded.");
      return;
    }
    let parsedTR31Matrix: Record<string, string[]> = {};
    let parsedPurposeMatrix: Record<string, string[]> = {};
    let parsedRotationByClass: Record<string, number> = {};
    try {
      parsedTR31Matrix = parseStringArrayMap(tr31ExportabilityMatrixText, "TR-31 exportability matrix");
      parsedPurposeMatrix = parseStringArrayMap(paymentKeyPurposeMatrixText, "Payment key purpose matrix");
      parsedRotationByClass = parseStringIntMap(rotationDaysByClassText, "Rotation interval by class");
    } catch (parseError) {
      onToast?.(errMsg(parseError));
      return;
    }
    const pvkiMin = Math.max(0, Math.min(9, Math.floor(Number(payPolicy?.pvki_min || 0))));
    const pvkiMax = Math.max(0, Math.min(9, Math.floor(Number(payPolicy?.pvki_max || 9))));
    if (pvkiMin > pvkiMax) {
      onToast?.("PVKI min cannot be greater than PVKI max.");
      return;
    }
    setSaving(true);
    try {
      const updatedPolicy = await updatePaymentPolicy(session, {
        tenant_id: session.tenantId,
        allowed_tr31_versions: Array.isArray(payPolicy?.allowed_tr31_versions) ? payPolicy.allowed_tr31_versions : tr31VersionOptions,
        require_kbpk_for_tr31: Boolean(payPolicy?.require_kbpk_for_tr31),
        allowed_kbpk_classes: Array.isArray(payPolicy?.allowed_kbpk_classes) ? payPolicy.allowed_kbpk_classes : [],
        allowed_tr31_exportability: Array.isArray(payPolicy?.allowed_tr31_exportability) ? payPolicy.allowed_tr31_exportability : tr31ExportabilityOptions,
        tr31_exportability_matrix: parsedTR31Matrix,
        payment_key_purpose_matrix: parsedPurposeMatrix,
        allow_inline_key_material: Boolean(payPolicy?.allow_inline_key_material),
        max_iso20022_payload_bytes: Math.max(1024, Math.min(4194304, Number(payPolicy?.max_iso20022_payload_bytes || 262144))),
        require_iso20022_lau_context: Boolean(payPolicy?.require_iso20022_lau_context),
        allowed_iso20022_canonicalization: Array.isArray(payPolicy?.allowed_iso20022_canonicalization) ? payPolicy.allowed_iso20022_canonicalization : [],
        allowed_iso20022_signature_suites: Array.isArray(payPolicy?.allowed_iso20022_signature_suites) ? payPolicy.allowed_iso20022_signature_suites : [],
        strict_pci_dss_4_0: Boolean(payPolicy?.strict_pci_dss_4_0),
        require_key_id_for_operations: Boolean(payPolicy?.require_key_id_for_operations),
        allow_tcp_interface: Boolean(payPolicy?.allow_tcp_interface),
        require_jwt_on_tcp: Boolean(payPolicy?.require_jwt_on_tcp),
        max_tcp_payload_bytes: Math.max(4096, Math.min(1048576, Number(payPolicy?.max_tcp_payload_bytes || 262144))),
        allowed_tcp_operations: Array.isArray(payPolicy?.allowed_tcp_operations) ? payPolicy.allowed_tcp_operations : allTCPOperations,
        allowed_pin_block_formats: Array.isArray(payPolicy?.allowed_pin_block_formats) ? payPolicy.allowed_pin_block_formats : pinFormatOptions,
        allowed_pin_translation_pairs: parseCSVList(pinTranslationPairsText),
        disable_iso0_pin_block: Boolean(payPolicy?.disable_iso0_pin_block),
        allowed_cvv_service_codes: parseCSVList(cvvServiceCodesText),
        pvki_min: pvkiMin,
        pvki_max: pvkiMax,
        allowed_issuer_profiles: parseCSVList(issuerProfilesText),
        allowed_mac_domains: Array.isArray(payPolicy?.allowed_mac_domains) ? payPolicy.allowed_mac_domains : [],
        allowed_mac_padding_profiles: Array.isArray(payPolicy?.allowed_mac_padding_profiles) ? payPolicy.allowed_mac_padding_profiles : [],
        dual_control_required_operations: Array.isArray(payPolicy?.dual_control_required_operations) ? payPolicy.dual_control_required_operations : [],
        hsm_required_operations: Array.isArray(payPolicy?.hsm_required_operations) ? payPolicy.hsm_required_operations : [],
        rotation_interval_days_by_class: parsedRotationByClass,
        runtime_environment: String(payPolicy?.runtime_environment || "prod").toLowerCase() === "test" ? "test" : "prod",
        disallow_test_keys_in_prod: Boolean(payPolicy?.disallow_test_keys_in_prod),
        disallow_prod_keys_in_test: Boolean(payPolicy?.disallow_prod_keys_in_test),
        decimalization_table: String(payPolicy?.decimalization_table || "0123456789012345").trim(),
        block_wildcard_pan: Boolean(payPolicy?.block_wildcard_pan),
        updated_by: session?.username || "dashboard"
      });
      const updatedAP2 = await updatePaymentAP2Profile(session, {
        ...ap2Profile,
        tenant_id: session.tenantId,
        allowed_protocol_bindings: parseCSVList(ap2BindingsText),
        allowed_transaction_modes: parseCSVList(ap2ModesText),
        allowed_payment_rails: parseCSVList(ap2RailsText),
        allowed_currencies: parseCSVList(ap2CurrenciesText),
        trusted_credential_issuers: parseCSVList(ap2IssuersText),
        max_human_present_amount_minor: Number(ap2Profile?.max_human_present_amount_minor || 0),
        max_human_not_present_amount_minor: Number(ap2Profile?.max_human_not_present_amount_minor || 0),
        updated_by: session?.username || "dashboard"
      });
      setPayPolicy((prev: any) => ({ ...prev, ...updatedPolicy }));
      setTR31ExportabilityMatrixText(toPrettyJSON(updatedPolicy?.tr31_exportability_matrix));
      setPaymentKeyPurposeMatrixText(toPrettyJSON(updatedPolicy?.payment_key_purpose_matrix));
      setRotationDaysByClassText(toPrettyJSON(updatedPolicy?.rotation_interval_days_by_class));
      setPINTranslationPairsText(Array.isArray(updatedPolicy?.allowed_pin_translation_pairs) ? updatedPolicy.allowed_pin_translation_pairs.join(", ") : "");
      setCVVServiceCodesText(Array.isArray(updatedPolicy?.allowed_cvv_service_codes) ? updatedPolicy.allowed_cvv_service_codes.join(", ") : "");
      setIssuerProfilesText(Array.isArray(updatedPolicy?.allowed_issuer_profiles) ? updatedPolicy.allowed_issuer_profiles.join(", ") : "");
      hydrateAP2Profile(updatedAP2);
      onToast?.("Traditional and modern payment policy updated.");
    } catch (error) {
      onToast?.(`Payment policy update failed: ${errMsg(error)}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div style={{ display: "grid", gap: 12 }}>
      <Section
        title="Payment Policy"
        actions={
          <>
            <Btn small onClick={() => void loadAll(false)} disabled={loading || saving}>{loading ? "Refreshing..." : "Refresh"}</Btn>
            <Btn small primary onClick={saveAll} disabled={loading || saving}>{saving ? "Saving..." : "Save Policy"}</Btn>
          </>
        }
      />

      <div style={{ display: "grid", gridTemplateColumns: "repeat(6,1fr)", gap: 10 }}>
        {summaryCards.map((item) => {
          const Icon = item.icon;
          return (
            <Card key={item.label} style={{ padding: "12px 14px", display: "flex", alignItems: "center", gap: 10 }}>
              <Icon size={18} style={{ color: item.color, flexShrink: 0 }} />
              <div>
                <div style={{ fontSize: 20, fontWeight: 800, color: C.text, fontFamily: "'Inter',sans-serif", lineHeight: 1 }}>{item.value ?? "-"}</div>
                <div style={{ fontSize: 9, color: C.muted, letterSpacing: 0.5, textTransform: "uppercase" }}>{item.label}</div>
                <div style={{ fontSize: 9, color: C.dim, marginTop: 2 }}>{item.sub}</div>
              </div>
            </Card>
          );
        })}
      </div>

      <Tabs tabs={["Traditional Payment", "Modern Payment"]} active={policyTab} onChange={setPolicyTab} />

      {policyTab === "Traditional Payment" ? (
        <div style={{ display: "grid", gap: 12 }}>
          <Section title="Traditional Runtime Controls">
            <Card style={{ display: "grid", gap: 8 }}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                <Chk label="Disable ISO-0 PIN block format" checked={Boolean(payPolicy?.disable_iso0_pin_block)} onChange={() => setPayPolicy((prev: any) => {
                  const disable = !Boolean(prev?.disable_iso0_pin_block);
                  const current = Array.isArray(prev?.allowed_pin_block_formats) ? [...prev.allowed_pin_block_formats] : pinFormatOptions;
                  const nextFormats = disable ? current.filter((fmt) => fmt !== "ISO-0") : current;
                  return { ...prev, disable_iso0_pin_block: disable, allowed_pin_block_formats: nextFormats };
                })} />
                <Chk label="Require KBPK / KEK for TR-31 operations" checked={Boolean(payPolicy?.require_kbpk_for_tr31)} onChange={() => setPayPolicy((prev: any) => ({ ...prev, require_kbpk_for_tr31: !Boolean(prev?.require_kbpk_for_tr31) }))} />
                <Chk label="Allow inline key material in payment API" checked={Boolean(payPolicy?.allow_inline_key_material)} onChange={() => setPayPolicy((prev: any) => ({ ...prev, allow_inline_key_material: !Boolean(prev?.allow_inline_key_material) }))} />
                <Chk label="Require key_id for payment crypto operations" checked={Boolean(payPolicy?.require_key_id_for_operations)} onChange={() => setPayPolicy((prev: any) => ({ ...prev, require_key_id_for_operations: !Boolean(prev?.require_key_id_for_operations) }))} />
                <Chk label="Allow Payment TCP interface" checked={Boolean(payPolicy?.allow_tcp_interface)} onChange={() => setPayPolicy((prev: any) => ({ ...prev, allow_tcp_interface: !Boolean(prev?.allow_tcp_interface) }))} />
                <Chk label="Require JWT on Payment TCP interface" checked={Boolean(payPolicy?.require_jwt_on_tcp)} onChange={() => setPayPolicy((prev: any) => ({ ...prev, require_jwt_on_tcp: !Boolean(prev?.require_jwt_on_tcp) }))} />
                <Chk label="Strict PCI DSS 4.0 payment handling" checked={Boolean(payPolicy?.strict_pci_dss_4_0)} onChange={() => setPayPolicy((prev: any) => ({ ...prev, strict_pci_dss_4_0: !Boolean(prev?.strict_pci_dss_4_0) }))} />
                <Chk label="Block wildcard / non-digit PAN values" checked={Boolean(payPolicy?.block_wildcard_pan)} onChange={() => setPayPolicy((prev: any) => ({ ...prev, block_wildcard_pan: !Boolean(prev?.block_wildcard_pan) }))} />
                <Chk label="Block test payment keys in prod runtime" checked={Boolean(payPolicy?.disallow_test_keys_in_prod)} onChange={() => setPayPolicy((prev: any) => ({ ...prev, disallow_test_keys_in_prod: !Boolean(prev?.disallow_test_keys_in_prod) }))} />
                <Chk label="Block prod payment keys in test runtime" checked={Boolean(payPolicy?.disallow_prod_keys_in_test)} onChange={() => setPayPolicy((prev: any) => ({ ...prev, disallow_prod_keys_in_test: !Boolean(prev?.disallow_prod_keys_in_test) }))} />
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 10 }}>
                <FG label="Runtime Environment">
                  <Sel value={String(payPolicy?.runtime_environment || "prod")} onChange={(e) => setPayPolicy((prev: any) => ({ ...prev, runtime_environment: e.target.value === "test" ? "test" : "prod" }))}>
                    <option value="prod">Production</option>
                    <option value="test">Test / Sandbox</option>
                  </Sel>
                </FG>
                <FG label="Max Payment TCP payload bytes">
                  <Inp type="number" min={4096} max={1048576} value={String(payPolicy?.max_tcp_payload_bytes ?? 262144)} onChange={(e) => setPayPolicy((prev: any) => ({ ...prev, max_tcp_payload_bytes: Number(e.target.value || 262144) }))} />
                </FG>
                <FG label="Decimalization Table (16 digits)">
                  <Inp value={String(payPolicy?.decimalization_table || "0123456789012345")} onChange={(e) => setPayPolicy((prev: any) => ({ ...prev, decimalization_table: String(e.target.value || "").replace(/\s+/g, "") }))} placeholder="0123456789012345" mono />
                </FG>
              </div>
            </Card>
          </Section>

          <Section title="TR-31, KBPK, PIN, and MAC">
            <Card style={{ display: "grid", gap: 10 }}>
              <div>
                <div style={{ fontSize: 10, color: C.text, fontWeight: 700, marginBottom: 8 }}>Allowed TR-31 Versions</div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 8 }}>
                  {tr31VersionOptions.map((ver) => {
                    const selected = (Array.isArray(payPolicy?.allowed_tr31_versions) ? payPolicy.allowed_tr31_versions : []).includes(ver);
                    return <Chk key={`pay-pol-ver-${ver}`} label={`TR-31 ${ver}`} checked={selected} onChange={() => setPayPolicy((prev: any) => ({ ...prev, allowed_tr31_versions: toggleStringList(prev?.allowed_tr31_versions, ver) }))} />;
                  })}
                </div>
              </div>
              <div>
                <div style={{ fontSize: 10, color: C.text, fontWeight: 700, marginBottom: 8 }}>Allowed KBPK Classes</div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(4,minmax(0,1fr))", gap: 8 }}>
                  {paymentKeyClassOptions.map((klass) => {
                    const selected = (Array.isArray(payPolicy?.allowed_kbpk_classes) ? payPolicy.allowed_kbpk_classes : []).includes(klass);
                    return <Chk key={`pay-pol-kbpk-${klass}`} label={klass} checked={selected} onChange={() => setPayPolicy((prev: any) => ({ ...prev, allowed_kbpk_classes: toggleStringList(prev?.allowed_kbpk_classes, klass) }))} />;
                  })}
                </div>
              </div>
              <div>
                <div style={{ fontSize: 10, color: C.text, fontWeight: 700, marginBottom: 8 }}>Allowed TR-31 Exportability Flags</div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 8 }}>
                  {tr31ExportabilityOptions.map((flag) => {
                    const selected = (Array.isArray(payPolicy?.allowed_tr31_exportability) ? payPolicy.allowed_tr31_exportability : []).includes(flag);
                    return <Chk key={`pay-pol-exp-${flag}`} label={flag} checked={selected} onChange={() => setPayPolicy((prev: any) => ({ ...prev, allowed_tr31_exportability: toggleStringList(prev?.allowed_tr31_exportability, flag) }))} />;
                  })}
                </div>
              </div>
              <div>
                <div style={{ fontSize: 10, color: C.text, fontWeight: 700, marginBottom: 8 }}>Allowed PIN block formats</div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 8 }}>
                  {pinFormatOptions.map((fmt) => {
                    const selected = (Array.isArray(payPolicy?.allowed_pin_block_formats) ? payPolicy.allowed_pin_block_formats : []).includes(fmt);
                    const locked = Boolean(payPolicy?.disable_iso0_pin_block) && fmt === "ISO-0";
                    return <Chk key={`pay-pol-pin-${fmt}`} label={locked ? `${fmt} (disabled by policy)` : fmt} checked={locked ? false : selected} disabled={locked} onChange={() => setPayPolicy((prev: any) => ({ ...prev, allowed_pin_block_formats: toggleStringList(prev?.allowed_pin_block_formats, fmt) }))} />;
                  })}
                </div>
              </div>
              <div>
                <div style={{ fontSize: 10, color: C.text, fontWeight: 700, marginBottom: 8 }}>Allowed MAC Domains</div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 8 }}>
                  {macDomainOptions.map((item) => {
                    const selected = (Array.isArray(payPolicy?.allowed_mac_domains) ? payPolicy.allowed_mac_domains : []).includes(item);
                    return <Chk key={`pay-pol-mac-dom-${item}`} label={item} checked={selected} onChange={() => setPayPolicy((prev: any) => ({ ...prev, allowed_mac_domains: toggleStringList(prev?.allowed_mac_domains, item) }))} />;
                  })}
                </div>
              </div>
              <div>
                <div style={{ fontSize: 10, color: C.text, fontWeight: 700, marginBottom: 8 }}>Allowed MAC Padding Profiles</div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 8 }}>
                  {macPaddingOptions.map((item) => {
                    const selected = (Array.isArray(payPolicy?.allowed_mac_padding_profiles) ? payPolicy.allowed_mac_padding_profiles : []).includes(item);
                    return <Chk key={`pay-pol-mac-pad-${item}`} label={item} checked={selected} onChange={() => setPayPolicy((prev: any) => ({ ...prev, allowed_mac_padding_profiles: toggleStringList(prev?.allowed_mac_padding_profiles, item) }))} />;
                  })}
                </div>
              </div>
            </Card>
          </Section>

          <Section title="Traditional Runtime Operations">
            <Card style={{ display: "grid", gap: 10 }}>
              <div>
                <div style={{ fontSize: 10, color: C.text, fontWeight: 700, marginBottom: 8 }}>Allowed operations over Payment TCP</div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 8 }}>
                  {traditionalTCPOperations.map((op) => {
                    const selected = (Array.isArray(payPolicy?.allowed_tcp_operations) ? payPolicy.allowed_tcp_operations : []).includes(op);
                    return <Chk key={`pay-pol-op-${op}`} label={op} checked={selected} onChange={() => setPayPolicy((prev: any) => ({ ...prev, allowed_tcp_operations: toggleStringList(prev?.allowed_tcp_operations, op) }))} />;
                  })}
                </div>
              </div>
              <div>
                <div style={{ fontSize: 10, color: C.text, fontWeight: 700, marginBottom: 8 }}>Dual-control Required Operations</div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 8 }}>
                  {traditionalSensitiveOperations.map((op) => {
                    const selected = (Array.isArray(payPolicy?.dual_control_required_operations) ? payPolicy.dual_control_required_operations : []).includes(op);
                    return <Chk key={`pay-pol-dual-${op}`} label={op} checked={selected} onChange={() => setPayPolicy((prev: any) => ({ ...prev, dual_control_required_operations: toggleStringList(prev?.dual_control_required_operations, op) }))} />;
                  })}
                </div>
              </div>
              <div>
                <div style={{ fontSize: 10, color: C.text, fontWeight: 700, marginBottom: 8 }}>HSM-required Operations</div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 8 }}>
                  {traditionalSensitiveOperations.map((op) => {
                    const selected = (Array.isArray(payPolicy?.hsm_required_operations) ? payPolicy.hsm_required_operations : []).includes(op);
                    return <Chk key={`pay-pol-hsm-${op}`} label={op} checked={selected} onChange={() => setPayPolicy((prev: any) => ({ ...prev, hsm_required_operations: toggleStringList(prev?.hsm_required_operations, op) }))} />;
                  })}
                </div>
              </div>
            </Card>
          </Section>

          <Section title="Issuer, PAN, and Rotation Guardrails">
            <Card style={{ display: "grid", gap: 10 }}>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 10 }}>
                <FG label="PVKI Min">
                  <Inp type="number" min={0} max={9} value={String(payPolicy?.pvki_min ?? 0)} onChange={(e) => setPayPolicy((prev: any) => ({ ...prev, pvki_min: Number(e.target.value || 0) }))} />
                </FG>
                <FG label="PVKI Max">
                  <Inp type="number" min={0} max={9} value={String(payPolicy?.pvki_max ?? 9)} onChange={(e) => setPayPolicy((prev: any) => ({ ...prev, pvki_max: Number(e.target.value || 9) }))} />
                </FG>
              </div>
              <FG label="Allowed PIN Translation Pairs (CSV or newline; e.g. ISO-0>ISO-1)">
                <Txt rows={3} value={pinTranslationPairsText} onChange={(e) => setPINTranslationPairsText(e.target.value)} placeholder="ISO-0>ISO-1, ISO-1>ISO-3" />
              </FG>
              <FG label="Allowed CVV Service Codes (CSV or newline)">
                <Txt rows={3} value={cvvServiceCodesText} onChange={(e) => setCVVServiceCodesText(e.target.value)} placeholder="101, 201" />
              </FG>
              <FG label="Allowed Issuer Profiles (CSV or newline)">
                <Txt rows={3} value={issuerProfilesText} onChange={(e) => setIssuerProfilesText(e.target.value)} placeholder="issuer-alpha, issuer-beta" />
              </FG>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 10 }}>
                <FG label="TR-31 Exportability Matrix (JSON)">
                  <Txt rows={8} value={tr31ExportabilityMatrixText} onChange={(e) => setTR31ExportabilityMatrixText(e.target.value)} placeholder='{"D0":["E","N"],"K0":["N"]}' />
                </FG>
                <FG label="Payment Key Purpose Matrix (JSON)">
                  <Txt rows={8} value={paymentKeyPurposeMatrixText} onChange={(e) => setPaymentKeyPurposeMatrixText(e.target.value)} placeholder='{"ZPK":["pin.translate"],"*":["mac.verify"]}' />
                </FG>
                <FG label="Rotation Interval Days by Key Class (JSON)">
                  <Txt rows={8} value={rotationDaysByClassText} onChange={(e) => setRotationDaysByClassText(e.target.value)} placeholder='{"ZPK":90,"PVK":60}' />
                </FG>
              </div>
            </Card>
          </Section>
        </div>
      ) : (
        <div style={{ display: "grid", gap: 12 }}>
          <Section title="Modern Payment Runtime Policy">
            <Card style={{ display: "grid", gap: 10 }}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                <Chk label="Require ISO 20022 LAU context" checked={Boolean(payPolicy?.require_iso20022_lau_context)} onChange={() => setPayPolicy((prev: any) => ({ ...prev, require_iso20022_lau_context: !Boolean(prev?.require_iso20022_lau_context) }))} />
                <Chk label="Strict PCI DSS 4.0 payment handling" checked={Boolean(payPolicy?.strict_pci_dss_4_0)} onChange={() => setPayPolicy((prev: any) => ({ ...prev, strict_pci_dss_4_0: !Boolean(prev?.strict_pci_dss_4_0) }))} />
              </div>
              <FG label="Max ISO 20022 payload bytes">
                <Inp type="number" min={1024} max={4194304} value={String(payPolicy?.max_iso20022_payload_bytes ?? 262144)} onChange={(e) => setPayPolicy((prev: any) => ({ ...prev, max_iso20022_payload_bytes: Number(e.target.value || 262144) }))} />
              </FG>
              <div>
                <div style={{ fontSize: 10, color: C.text, fontWeight: 700, marginBottom: 8 }}>Allowed ISO 20022 Canonicalization</div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 8 }}>
                  {isoCanonicalizationOptions.map((item) => {
                    const selected = (Array.isArray(payPolicy?.allowed_iso20022_canonicalization) ? payPolicy.allowed_iso20022_canonicalization : []).includes(item);
                    return <Chk key={`pay-pol-canon-${item}`} label={item} checked={selected} onChange={() => setPayPolicy((prev: any) => ({ ...prev, allowed_iso20022_canonicalization: toggleStringList(prev?.allowed_iso20022_canonicalization, item) }))} />;
                  })}
                </div>
              </div>
              <div>
                <div style={{ fontSize: 10, color: C.text, fontWeight: 700, marginBottom: 8 }}>Allowed ISO 20022 Signature Suites</div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 8 }}>
                  {isoSignatureSuiteOptions.map((item) => {
                    const selected = (Array.isArray(payPolicy?.allowed_iso20022_signature_suites) ? payPolicy.allowed_iso20022_signature_suites : []).includes(item);
                    return <Chk key={`pay-pol-suite-${item}`} label={item} checked={selected} onChange={() => setPayPolicy((prev: any) => ({ ...prev, allowed_iso20022_signature_suites: toggleStringList(prev?.allowed_iso20022_signature_suites, item) }))} />;
                  })}
                </div>
              </div>
            </Card>
          </Section>

          <Section title="Modern Payment TCP and Approval Gates">
            <Card style={{ display: "grid", gap: 10 }}>
              <div>
                <div style={{ fontSize: 10, color: C.text, fontWeight: 700, marginBottom: 8 }}>Allowed modern operations over Payment TCP</div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 8 }}>
                  {modernTCPOperations.map((op) => {
                    const selected = (Array.isArray(payPolicy?.allowed_tcp_operations) ? payPolicy.allowed_tcp_operations : []).includes(op);
                    return <Chk key={`pay-pol-modern-op-${op}`} label={op} checked={selected} onChange={() => setPayPolicy((prev: any) => ({ ...prev, allowed_tcp_operations: toggleStringList(prev?.allowed_tcp_operations, op) }))} />;
                  })}
                </div>
              </div>
              <div>
                <div style={{ fontSize: 10, color: C.text, fontWeight: 700, marginBottom: 8 }}>Dual-control Required Modern Operations</div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 8 }}>
                  {modernSensitiveOperations.map((op) => {
                    const selected = (Array.isArray(payPolicy?.dual_control_required_operations) ? payPolicy.dual_control_required_operations : []).includes(op);
                    return <Chk key={`pay-pol-modern-dual-${op}`} label={op} checked={selected} onChange={() => setPayPolicy((prev: any) => ({ ...prev, dual_control_required_operations: toggleStringList(prev?.dual_control_required_operations, op) }))} />;
                  })}
                </div>
              </div>
              <div>
                <div style={{ fontSize: 10, color: C.text, fontWeight: 700, marginBottom: 8 }}>HSM-required Modern Operations</div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 8 }}>
                  {modernSensitiveOperations.map((op) => {
                    const selected = (Array.isArray(payPolicy?.hsm_required_operations) ? payPolicy.hsm_required_operations : []).includes(op);
                    return <Chk key={`pay-pol-modern-hsm-${op}`} label={op} checked={selected} onChange={() => setPayPolicy((prev: any) => ({ ...prev, hsm_required_operations: toggleStringList(prev?.hsm_required_operations, op) }))} />;
                  })}
                </div>
              </div>
            </Card>
          </Section>

          <Section title="AP2 Agent Payment Policy">
            <Card style={{ display: "grid", gap: 10 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 10 }}>
                <div>
                  <div style={{ fontSize: 11, color: C.text, fontWeight: 700, marginBottom: 4 }}>Modern Agentic Payment Controls</div>
                  <div style={{ fontSize: 10, color: C.dim, lineHeight: 1.6 }}>
                    AP2 policy is part of the modern payment control plane. Configure protocol bindings, rails, currencies, limits, mandates, trust proofs, and tokenization requirements here.
                  </div>
                </div>
                <B c={ap2Profile?.enabled ? "green" : "amber"}>{ap2Profile?.enabled ? "AP2 ENABLED" : "AP2 DISABLED"}</B>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                <FG label="Protocol Bindings" hint="Comma-separated: a2a, mcp, x402">
                  <Inp value={ap2BindingsText} onChange={(e) => setAP2BindingsText(e.target.value)} />
                </FG>
                <FG label="Transaction Modes" hint="Comma-separated: human_present, human_not_present">
                  <Inp value={ap2ModesText} onChange={(e) => setAP2ModesText(e.target.value)} />
                </FG>
                <FG label="Payment Rails" hint="Comma-separated: card, ach, rtp, wire, stablecoin">
                  <Inp value={ap2RailsText} onChange={(e) => setAP2RailsText(e.target.value)} />
                </FG>
                <FG label="Allowed Currencies" hint="Comma-separated ISO currency codes">
                  <Inp value={ap2CurrenciesText} onChange={(e) => setAP2CurrenciesText(e.target.value)} />
                </FG>
                <FG label="Default Currency">
                  <Inp value={String(ap2Profile?.default_currency || "USD")} onChange={(e) => setAp2Profile((prev: any) => ({ ...prev, default_currency: e.target.value.toUpperCase() }))} mono />
                </FG>
                <FG label="Trusted Credential Issuers" hint="Optional comma-separated issuer IDs / URIs">
                  <Inp value={ap2IssuersText} onChange={(e) => setAP2IssuersText(e.target.value)} />
                </FG>
                <FG label="Max Human-Present Amount (minor units)">
                  <Inp type="number" value={String(ap2Profile?.max_human_present_amount_minor || 0)} onChange={(e) => setAp2Profile((prev: any) => ({ ...prev, max_human_present_amount_minor: Number(e.target.value || 0) }))} mono />
                </FG>
                <FG label="Max Human-Not-Present Amount (minor units)">
                  <Inp type="number" value={String(ap2Profile?.max_human_not_present_amount_minor || 0)} onChange={(e) => setAp2Profile((prev: any) => ({ ...prev, max_human_not_present_amount_minor: Number(e.target.value || 0) }))} mono />
                </FG>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6, padding: 10, border: `1px solid ${C.border}`, borderRadius: 10 }}>
                <Chk label="Enable AP2 policy" checked={Boolean(ap2Profile?.enabled)} onChange={() => setAp2Profile((prev: any) => ({ ...prev, enabled: !Boolean(prev?.enabled) }))} />
                <Chk label="Allow x402 binding" checked={Boolean(ap2Profile?.allow_x402_extension)} onChange={() => setAp2Profile((prev: any) => ({ ...prev, allow_x402_extension: !Boolean(prev?.allow_x402_extension) }))} />
                <Chk label="Require intent mandate" checked={Boolean(ap2Profile?.require_intent_mandate)} onChange={() => setAp2Profile((prev: any) => ({ ...prev, require_intent_mandate: !Boolean(prev?.require_intent_mandate) }))} />
                <Chk label="Require cart mandate" checked={Boolean(ap2Profile?.require_cart_mandate)} onChange={() => setAp2Profile((prev: any) => ({ ...prev, require_cart_mandate: !Boolean(prev?.require_cart_mandate) }))} />
                <Chk label="Require payment mandate" checked={Boolean(ap2Profile?.require_payment_mandate)} onChange={() => setAp2Profile((prev: any) => ({ ...prev, require_payment_mandate: !Boolean(prev?.require_payment_mandate) }))} />
                <Chk label="Require merchant signature" checked={Boolean(ap2Profile?.require_merchant_signature)} onChange={() => setAp2Profile((prev: any) => ({ ...prev, require_merchant_signature: !Boolean(prev?.require_merchant_signature) }))} />
                <Chk label="Require verifiable credential" checked={Boolean(ap2Profile?.require_verifiable_credential)} onChange={() => setAp2Profile((prev: any) => ({ ...prev, require_verifiable_credential: !Boolean(prev?.require_verifiable_credential) }))} />
                <Chk label="Require wallet attestation" checked={Boolean(ap2Profile?.require_wallet_attestation)} onChange={() => setAp2Profile((prev: any) => ({ ...prev, require_wallet_attestation: !Boolean(prev?.require_wallet_attestation) }))} />
                <Chk label="Require risk signals" checked={Boolean(ap2Profile?.require_risk_signals)} onChange={() => setAp2Profile((prev: any) => ({ ...prev, require_risk_signals: !Boolean(prev?.require_risk_signals) }))} />
                <Chk label="Require tokenized instrument" checked={Boolean(ap2Profile?.require_tokenized_instrument)} onChange={() => setAp2Profile((prev: any) => ({ ...prev, require_tokenized_instrument: !Boolean(prev?.require_tokenized_instrument) }))} />
              </div>
            </Card>
          </Section>
        </div>
      )}
    </div>
  );
};

export default PaymentPolicyTab;
