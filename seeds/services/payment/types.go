package main

import (
	"encoding/json"
	"time"
)

const (
	TR31FormatVariant = "variant"
	TR31FormatB       = "tr31-b"
	TR31FormatC       = "tr31-c"
	TR31FormatD       = "tr31-d"
	TR31FormatAESKWP  = "aes-kwp"
)

type PaymentKey struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id"`
	KeyID            string    `json:"key_id"`
	PaymentType      string    `json:"payment_type"`
	KeyEnvironment   string    `json:"key_environment"`
	UsageCode        string    `json:"usage_code"`
	ModeOfUse        string    `json:"mode_of_use"`
	KeyVersionNum    string    `json:"key_version_num"`
	Exportability    string    `json:"exportability"`
	TR31Header       string    `json:"tr31_header"`
	KCV              []byte    `json:"-"`
	KCVHex           string    `json:"kcv"`
	ISO20022PartyID  string    `json:"iso20022_party_id"`
	ISO20022MsgTypes string    `json:"iso20022_msg_types"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type PaymentPolicy struct {
	TenantID                        string              `json:"tenant_id"`
	AllowedTR31Versions             []string            `json:"allowed_tr31_versions"`
	RequireKBPKForTR31              bool                `json:"require_kbpk_for_tr31"`
	AllowedKBPKClasses              []string            `json:"allowed_kbpk_classes"`
	AllowedTR31Exportability        []string            `json:"allowed_tr31_exportability"`
	TR31ExportabilityMatrix         map[string][]string `json:"tr31_exportability_matrix"`
	PaymentKeyPurposeMatrix         map[string][]string `json:"payment_key_purpose_matrix"`
	AllowInlineKeyMaterial          bool                `json:"allow_inline_key_material"`
	MaxISO20022PayloadBytes         int                 `json:"max_iso20022_payload_bytes"`
	RequireISO20022LAUContext       bool                `json:"require_iso20022_lau_context"`
	AllowedISO20022Canonicalization []string            `json:"allowed_iso20022_canonicalization"`
	AllowedISO20022SignatureSuites  []string            `json:"allowed_iso20022_signature_suites"`
	StrictPCIDSS40                  bool                `json:"strict_pci_dss_4_0"` // legacy compatibility flag (no auto-bundle enforcement)
	RequireKeyIDForOperations       bool                `json:"require_key_id_for_operations"`
	AllowTCPInterface               bool                `json:"allow_tcp_interface"`
	RequireJWTOnTCP                 bool                `json:"require_jwt_on_tcp"`
	MaxTCPPayloadBytes              int                 `json:"max_tcp_payload_bytes"`
	AllowedTCPOperations            []string            `json:"allowed_tcp_operations"`
	AllowedPINBlockFormats          []string            `json:"allowed_pin_block_formats"`
	AllowedPINTranslationPairs      []string            `json:"allowed_pin_translation_pairs"`
	DisableISO0PINBlock             bool                `json:"disable_iso0_pin_block"`
	AllowedCVVServiceCodes          []string            `json:"allowed_cvv_service_codes"`
	PVKIMin                         int                 `json:"pvki_min"`
	PVKIMax                         int                 `json:"pvki_max"`
	AllowedIssuerProfiles           []string            `json:"allowed_issuer_profiles"`
	AllowedMACDomains               []string            `json:"allowed_mac_domains"`
	AllowedMACPaddingProfiles       []string            `json:"allowed_mac_padding_profiles"`
	DualControlRequiredOperations   []string            `json:"dual_control_required_operations"`
	HSMRequiredOperations           []string            `json:"hsm_required_operations"`
	RotationIntervalDaysByClass     map[string]int      `json:"rotation_interval_days_by_class"`
	RuntimeEnvironment              string              `json:"runtime_environment"`
	DisallowTestKeysInProd          bool                `json:"disallow_test_keys_in_prod"`
	DisallowProdKeysInTest          bool                `json:"disallow_prod_keys_in_test"`
	DecimalizationTable             string              `json:"decimalization_table"`
	BlockWildcardPAN                bool                `json:"block_wildcard_pan"`
	UpdatedBy                       string              `json:"updated_by,omitempty"`
	UpdatedAt                       time.Time           `json:"updated_at"`
}

type PaymentAP2Profile struct {
	TenantID                      string    `json:"tenant_id"`
	Enabled                       bool      `json:"enabled"`
	AllowedProtocolBindings       []string  `json:"allowed_protocol_bindings"`
	AllowedTransactionModes       []string  `json:"allowed_transaction_modes"`
	AllowedPaymentRails           []string  `json:"allowed_payment_rails"`
	AllowedCurrencies             []string  `json:"allowed_currencies"`
	DefaultCurrency               string    `json:"default_currency"`
	RequireIntentMandate          bool      `json:"require_intent_mandate"`
	RequireCartMandate            bool      `json:"require_cart_mandate"`
	RequirePaymentMandate         bool      `json:"require_payment_mandate"`
	RequireMerchantSignature      bool      `json:"require_merchant_signature"`
	RequireVerifiableCredential   bool      `json:"require_verifiable_credential"`
	RequireWalletAttestation      bool      `json:"require_wallet_attestation"`
	RequireRiskSignals            bool      `json:"require_risk_signals"`
	RequireTokenizedInstrument    bool      `json:"require_tokenized_instrument"`
	AllowX402Extension            bool      `json:"allow_x402_extension"`
	MaxHumanPresentAmountMinor    int64     `json:"max_human_present_amount_minor"`
	MaxHumanNotPresentAmountMinor int64     `json:"max_human_not_present_amount_minor"`
	TrustedCredentialIssuers      []string  `json:"trusted_credential_issuers"`
	UpdatedBy                     string    `json:"updated_by,omitempty"`
	UpdatedAt                     time.Time `json:"updated_at"`
}

type PaymentAP2EvaluateRequest struct {
	TenantID                   string `json:"tenant_id"`
	AgentID                    string `json:"agent_id"`
	MerchantID                 string `json:"merchant_id"`
	Operation                  string `json:"operation"`
	ProtocolBinding            string `json:"protocol_binding"`
	TransactionMode            string `json:"transaction_mode"`
	PaymentRail                string `json:"payment_rail"`
	Currency                   string `json:"currency"`
	AmountMinor                int64  `json:"amount_minor"`
	HasIntentMandate           bool   `json:"has_intent_mandate"`
	HasCartMandate             bool   `json:"has_cart_mandate"`
	HasPaymentMandate          bool   `json:"has_payment_mandate"`
	HasMerchantSignature       bool   `json:"has_merchant_signature"`
	HasVerifiableCredential    bool   `json:"has_verifiable_credential"`
	HasWalletAttestation       bool   `json:"has_wallet_attestation"`
	HasRiskSignals             bool   `json:"has_risk_signals"`
	PaymentInstrumentTokenized bool   `json:"payment_instrument_tokenized"`
	CredentialIssuer           string `json:"credential_issuer"`
}

type PaymentAP2EvaluateResponse struct {
	Decision                string            `json:"decision"`
	Allowed                 bool              `json:"allowed"`
	RequiredMandates        []string          `json:"required_mandates"`
	MissingArtifacts        []string          `json:"missing_artifacts"`
	Reasons                 []string          `json:"reasons"`
	AppliedControls         []string          `json:"applied_controls"`
	RecommendedNextSteps    []string          `json:"recommended_next_steps"`
	MaxPermittedAmountMinor int64             `json:"max_permitted_amount_minor"`
	RequestFingerprint      string            `json:"request_fingerprint"`
	Profile                 PaymentAP2Profile `json:"profile"`
}

type PaymentCryptoDispatchRequest struct {
	TenantID  string          `json:"tenant_id"`
	Operation string          `json:"operation"`
	Payload   json.RawMessage `json:"payload"`
}

type TR31Translation struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	SourceKeyID  string    `json:"source_key_id"`
	SourceFormat string    `json:"source_format"`
	TargetFormat string    `json:"target_format"`
	KEKKeyID     string    `json:"kek_key_id"`
	ResultBlock  string    `json:"result_block"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
}

type PINOperationLog struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	Operation    string    `json:"operation"`
	SourceFormat string    `json:"source_format"`
	TargetFormat string    `json:"target_format"`
	ZPKKeyID     string    `json:"zpk_key_id"`
	Result       string    `json:"result"`
	CreatedAt    time.Time `json:"created_at"`
}

type RegisterPaymentKeyRequest struct {
	TenantID         string   `json:"tenant_id"`
	KeyID            string   `json:"key_id"`
	PaymentType      string   `json:"payment_type"`
	KeyEnvironment   string   `json:"key_environment"`
	UsageCode        string   `json:"usage_code"`
	ModeOfUse        string   `json:"mode_of_use"`
	KeyVersionNum    string   `json:"key_version_num"`
	Exportability    string   `json:"exportability"`
	TR31Header       string   `json:"tr31_header"`
	ISO20022PartyID  string   `json:"iso20022_party_id"`
	ISO20022MsgTypes []string `json:"iso20022_msg_types"`
}

type UpdatePaymentKeyRequest struct {
	TenantID         string   `json:"tenant_id"`
	PaymentType      string   `json:"payment_type"`
	KeyEnvironment   string   `json:"key_environment"`
	UsageCode        string   `json:"usage_code"`
	ModeOfUse        string   `json:"mode_of_use"`
	KeyVersionNum    string   `json:"key_version_num"`
	Exportability    string   `json:"exportability"`
	TR31Header       string   `json:"tr31_header"`
	ISO20022PartyID  string   `json:"iso20022_party_id"`
	ISO20022MsgTypes []string `json:"iso20022_msg_types"`
}

type RotatePaymentKeyRequest struct {
	TenantID string `json:"tenant_id"`
	Reason   string `json:"reason"`
}

type RotatePaymentKeyResponse struct {
	PaymentKeyID string `json:"payment_key_id"`
	KeyID        string `json:"key_id"`
	VersionID    string `json:"version_id"`
}

type CreateTR31Request struct {
	TenantID      string `json:"tenant_id"`
	KeyID         string `json:"key_id"`
	TR31Version   string `json:"tr31_version"`
	Algorithm     string `json:"algorithm"`
	UsageCode     string `json:"usage_code"`
	ModeOfUse     string `json:"mode_of_use"`
	KeyVersionNum string `json:"key_version_num"`
	Exportability string `json:"exportability"`
	KBPKKeyID     string `json:"kbpk_key_id"`
	KBPKKeyB64    string `json:"kbpk_key_b64"`
	KEKKeyID      string `json:"kek_key_id"`
	KEKKeyB64     string `json:"kek_key_b64"`
	SourceFormat  string `json:"source_format"`
	MaterialB64   string `json:"material_b64"`
}

type CreateTR31Response struct {
	Version      string `json:"version"`
	Algorithm    string `json:"algorithm"`
	UsageCode    string `json:"usage_code"`
	TR31Header   string `json:"tr31_header"`
	KeyBlock     string `json:"key_block"`
	KCV          string `json:"kcv"`
	SourceFormat string `json:"source_format"`
}

type ParseTR31Request struct {
	TenantID      string `json:"tenant_id"`
	KeyBlock      string `json:"key_block"`
	KBPKKeyID     string `json:"kbpk_key_id"`
	KBPKKeyB64    string `json:"kbpk_key_b64"`
	KEKKeyID      string `json:"kek_key_id"`
	KEKKeyB64     string `json:"kek_key_b64"`
	ImportToKMS   bool   `json:"import_to_kms"`
	ImportName    string `json:"import_name"`
	ImportPurpose string `json:"import_purpose"`
}

type ParseTR31Response struct {
	Version       string `json:"version"`
	Algorithm     string `json:"algorithm"`
	UsageCode     string `json:"usage_code"`
	KCV           string `json:"kcv"`
	ImportedKeyID string `json:"imported_key_id"`
	Valid         bool   `json:"valid"`
}

type TranslateTR31Request struct {
	TenantID         string `json:"tenant_id"`
	SourceKeyID      string `json:"source_key_id"`
	SourceBlock      string `json:"source_block"`
	SourceFormat     string `json:"source_format"`
	TargetFormat     string `json:"target_format"`
	SourceKBPKKeyID  string `json:"source_kbpk_key_id"`
	SourceKBPKKeyB64 string `json:"source_kbpk_key_b64"`
	TargetKBPKKeyID  string `json:"target_kbpk_key_id"`
	TargetKBPKKeyB64 string `json:"target_kbpk_key_b64"`
	KEKKeyID         string `json:"kek_key_id"`
	KEKKeyB64        string `json:"kek_key_b64"`
	TR31Version      string `json:"tr31_version"`
	Algorithm        string `json:"algorithm"`
	UsageCode        string `json:"usage_code"`
	ModeOfUse        string `json:"mode_of_use"`
	KeyVersionNum    string `json:"key_version_num"`
	Exportability    string `json:"exportability"`
}

type TranslateTR31Response struct {
	ID           string `json:"id"`
	SourceFormat string `json:"source_format"`
	TargetFormat string `json:"target_format"`
	ResultBlock  string `json:"result_block"`
	Status       string `json:"status"`
}

type ValidateTR31Request struct {
	TenantID   string `json:"tenant_id"`
	KeyBlock   string `json:"key_block"`
	KBPKKeyID  string `json:"kbpk_key_id"`
	KBPKKeyB64 string `json:"kbpk_key_b64"`
	KEKKeyID   string `json:"kek_key_id"`
	KEKKeyB64  string `json:"kek_key_b64"`
}

type ValidateTR31Response struct {
	Valid     bool   `json:"valid"`
	Version   string `json:"version"`
	Algorithm string `json:"algorithm"`
	UsageCode string `json:"usage_code"`
	KCV       string `json:"kcv"`
	Reason    string `json:"reason"`
}

type TranslatePINRequest struct {
	TenantID        string `json:"tenant_id"`
	SourceFormat    string `json:"source_format"`
	TargetFormat    string `json:"target_format"`
	PINBlock        string `json:"pin_block"`
	PAN             string `json:"pan"`
	SourceZPKKeyID  string `json:"source_zpk_key_id"`
	SourceZPKKeyB64 string `json:"source_zpk_key_b64"`
	TargetZPKKeyID  string `json:"target_zpk_key_id"`
	TargetZPKKeyB64 string `json:"target_zpk_key_b64"`
	ZPKKeyID        string `json:"zpk_key_id"`
	ZPKKeyB64       string `json:"zpk_key_b64"`
}

type PVVGenerateRequest struct {
	TenantID  string `json:"tenant_id"`
	PVKKeyID  string `json:"pvk_key_id"`
	PVKKeyB64 string `json:"pvk_key_b64"`
	PIN       string `json:"pin"`
	PAN       string `json:"pan"`
	PVKI      string `json:"pvki"`
	SourceFmt string `json:"source_format"`
	ZPKKeyID  string `json:"zpk_key_id"`
}

type PVVVerifyRequest struct {
	TenantID  string `json:"tenant_id"`
	PVKKeyID  string `json:"pvk_key_id"`
	PVKKeyB64 string `json:"pvk_key_b64"`
	PIN       string `json:"pin"`
	PAN       string `json:"pan"`
	PVKI      string `json:"pvki"`
	PVV       string `json:"pvv"`
	ZPKKeyID  string `json:"zpk_key_id"`
}

type OffsetGenerateRequest struct {
	TenantID     string `json:"tenant_id"`
	PIN          string `json:"pin"`
	ReferencePIN string `json:"reference_pin"`
	ZPKKeyID     string `json:"zpk_key_id"`
}

type OffsetVerifyRequest struct {
	TenantID     string `json:"tenant_id"`
	PIN          string `json:"pin"`
	ReferencePIN string `json:"reference_pin"`
	Offset       string `json:"offset"`
	ZPKKeyID     string `json:"zpk_key_id"`
}

type CVVComputeRequest struct {
	TenantID    string `json:"tenant_id"`
	CVKKeyID    string `json:"cvk_key_id"`
	CVKKeyB64   string `json:"cvk_key_b64"`
	PAN         string `json:"pan"`
	ExpiryYYMM  string `json:"expiry_yymm"`
	ServiceCode string `json:"service_code"`
}

type CVVVerifyRequest struct {
	TenantID    string `json:"tenant_id"`
	CVKKeyID    string `json:"cvk_key_id"`
	CVKKeyB64   string `json:"cvk_key_b64"`
	PAN         string `json:"pan"`
	ExpiryYYMM  string `json:"expiry_yymm"`
	ServiceCode string `json:"service_code"`
	CVV         string `json:"cvv"`
}

type MACRequest struct {
	TenantID       string `json:"tenant_id"`
	KeyID          string `json:"key_id"`
	KeyB64         string `json:"key_b64"`
	DataB64        string `json:"data_b64"`
	Algorithm      int    `json:"algorithm"`
	Type           string `json:"type"`
	Domain         string `json:"domain"`
	PaddingProfile string `json:"padding_profile"`
}

type VerifyMACRequest struct {
	TenantID       string `json:"tenant_id"`
	KeyID          string `json:"key_id"`
	KeyB64         string `json:"key_b64"`
	DataB64        string `json:"data_b64"`
	MACB64         string `json:"mac_b64"`
	Algorithm      int    `json:"algorithm"`
	Type           string `json:"type"`
	Domain         string `json:"domain"`
	PaddingProfile string `json:"padding_profile"`
}

type ISO20022SignRequest struct {
	TenantID         string `json:"tenant_id"`
	KeyID            string `json:"key_id"`
	XML              string `json:"xml"`
	Canonicalization string `json:"canonicalization"`
	SignatureSuite   string `json:"signature_suite"`
}

type ISO20022VerifyRequest struct {
	TenantID         string `json:"tenant_id"`
	KeyID            string `json:"key_id"`
	XML              string `json:"xml"`
	SignatureB64     string `json:"signature_b64"`
	Canonicalization string `json:"canonicalization"`
	SignatureSuite   string `json:"signature_suite"`
}

type ISO20022EncryptRequest struct {
	TenantID    string `json:"tenant_id"`
	KeyID       string `json:"key_id"`
	XML         string `json:"xml"`
	IVB64       string `json:"iv"`
	ReferenceID string `json:"reference_id"`
}

type ISO20022DecryptRequest struct {
	TenantID      string `json:"tenant_id"`
	KeyID         string `json:"key_id"`
	CiphertextB64 string `json:"ciphertext"`
	IVB64         string `json:"iv"`
}

type LAUGenerateRequest struct {
	TenantID  string `json:"tenant_id"`
	KeyID     string `json:"key_id"`
	LAUKeyB64 string `json:"lau_key_b64"`
	Message   string `json:"message"`
	Context   string `json:"context"`
}

type LAUVerifyRequest struct {
	TenantID  string `json:"tenant_id"`
	KeyID     string `json:"key_id"`
	LAUKeyB64 string `json:"lau_key_b64"`
	Message   string `json:"message"`
	Context   string `json:"context"`
	LAUB64    string `json:"lau_b64"`
}

type PaymentInjectionTerminal struct {
	ID                         string    `json:"id"`
	TenantID                   string    `json:"tenant_id"`
	TerminalID                 string    `json:"terminal_id"`
	Name                       string    `json:"name"`
	Status                     string    `json:"status"`
	Transport                  string    `json:"transport"`
	KeyAlgorithm               string    `json:"key_algorithm"`
	PublicKeyPEM               string    `json:"public_key_pem,omitempty"`
	PublicKeyFingerprint       string    `json:"public_key_fingerprint"`
	RegistrationNonce          string    `json:"registration_nonce,omitempty"`
	RegistrationNonceExpiresAt time.Time `json:"registration_nonce_expires_at,omitempty"`
	VerifiedAt                 time.Time `json:"verified_at,omitempty"`
	AuthTokenHash              string    `json:"-"`
	AuthTokenIssuedAt          time.Time `json:"auth_token_issued_at,omitempty"`
	LastSeenAt                 time.Time `json:"last_seen_at,omitempty"`
	MetadataJSON               string    `json:"metadata_json"`
	CreatedAt                  time.Time `json:"created_at"`
	UpdatedAt                  time.Time `json:"updated_at"`
}

type PaymentInjectionJob struct {
	ID                   string    `json:"id"`
	TenantID             string    `json:"tenant_id"`
	TerminalID           string    `json:"terminal_id"`
	PaymentKeyID         string    `json:"payment_key_id"`
	KeyID                string    `json:"key_id"`
	TR31Version          string    `json:"tr31_version"`
	TR31UsageCode        string    `json:"tr31_usage_code"`
	TR31KeyBlock         string    `json:"tr31_key_block"`
	TR31KCV              string    `json:"tr31_kcv"`
	PayloadCiphertextB64 string    `json:"payload_ciphertext_b64"`
	PayloadIVB64         string    `json:"payload_iv_b64"`
	WrappedDEKB64        string    `json:"wrapped_dek_b64"`
	DEKWrapAlg           string    `json:"dek_wrap_alg"`
	Status               string    `json:"status"`
	DeliveredAt          time.Time `json:"delivered_at,omitempty"`
	AckedAt              time.Time `json:"acked_at,omitempty"`
	AckDetail            string    `json:"ack_detail,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

type RegisterInjectionTerminalRequest struct {
	TenantID     string `json:"tenant_id"`
	TerminalID   string `json:"terminal_id"`
	Name         string `json:"name"`
	Transport    string `json:"transport"`
	PublicKeyPEM string `json:"public_key_pem"`
	KeyAlgorithm string `json:"key_algorithm"`
	MetadataJSON string `json:"metadata_json"`
}

type VerifyInjectionChallengeRequest struct {
	TenantID     string `json:"tenant_id"`
	SignatureB64 string `json:"signature_b64"`
}

type VerifyInjectionChallengeResponse struct {
	Terminal  PaymentInjectionTerminal `json:"terminal"`
	AuthToken string                   `json:"auth_token"`
	TokenType string                   `json:"token_type"`
}

type CreateInjectionJobRequest struct {
	TenantID     string `json:"tenant_id"`
	TerminalID   string `json:"terminal_id"`
	PaymentKeyID string `json:"payment_key_id"`
	TR31Version  string `json:"tr31_version"`
	KBPKKeyID    string `json:"kbpk_key_id"`
	KBPKKeyB64   string `json:"kbpk_key_b64"`
	KEKKeyID     string `json:"kek_key_id"`
	KEKKeyB64    string `json:"kek_key_b64"`
}

type AckInjectionJobRequest struct {
	TenantID   string `json:"tenant_id"`
	TerminalID string `json:"terminal_id"`
	Status     string `json:"status"`
	Detail     string `json:"detail"`
}
