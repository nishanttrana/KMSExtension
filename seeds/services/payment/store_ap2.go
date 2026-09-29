package main

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

func (s *SQLStore) GetPaymentAP2Profile(ctx context.Context, tenantID string) (PaymentAP2Profile, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id,
       enabled,
       allowed_protocol_bindings_json,
       allowed_transaction_modes_json,
       allowed_payment_rails_json,
       allowed_currencies_json,
       default_currency,
       require_intent_mandate,
       require_cart_mandate,
       require_payment_mandate,
       require_merchant_signature,
       require_verifiable_credential,
       require_wallet_attestation,
       require_risk_signals,
       require_tokenized_instrument,
       allow_x402_extension,
       max_human_present_amount_minor,
       max_human_not_present_amount_minor,
       trusted_credential_issuers_json,
       COALESCE(updated_by,''),
       updated_at
FROM payment_ap2_profile
WHERE tenant_id = $1
`, strings.TrimSpace(tenantID))

	var (
		out                  PaymentAP2Profile
		protocolBindingsJSON string
		transactionModesJSON string
		paymentRailsJSON     string
		currenciesJSON       string
		trustedIssuersJSON   string
		updatedRaw           interface{}
	)
	if err := row.Scan(
		&out.TenantID,
		&out.Enabled,
		&protocolBindingsJSON,
		&transactionModesJSON,
		&paymentRailsJSON,
		&currenciesJSON,
		&out.DefaultCurrency,
		&out.RequireIntentMandate,
		&out.RequireCartMandate,
		&out.RequirePaymentMandate,
		&out.RequireMerchantSignature,
		&out.RequireVerifiableCredential,
		&out.RequireWalletAttestation,
		&out.RequireRiskSignals,
		&out.RequireTokenizedInstrument,
		&out.AllowX402Extension,
		&out.MaxHumanPresentAmountMinor,
		&out.MaxHumanNotPresentAmountMinor,
		&trustedIssuersJSON,
		&out.UpdatedBy,
		&updatedRaw,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PaymentAP2Profile{}, errNotFound
		}
		return PaymentAP2Profile{}, err
	}
	out.AllowedProtocolBindings = parseJSONArrayString(protocolBindingsJSON)
	out.AllowedTransactionModes = parseJSONArrayString(transactionModesJSON)
	out.AllowedPaymentRails = parseJSONArrayString(paymentRailsJSON)
	out.AllowedCurrencies = parseJSONArrayString(currenciesJSON)
	out.TrustedCredentialIssuers = parseJSONArrayString(trustedIssuersJSON)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	return out, nil
}

func (s *SQLStore) UpsertPaymentAP2Profile(ctx context.Context, item PaymentAP2Profile) (PaymentAP2Profile, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO payment_ap2_profile (
    tenant_id,
    enabled,
    allowed_protocol_bindings_json,
    allowed_transaction_modes_json,
    allowed_payment_rails_json,
    allowed_currencies_json,
    default_currency,
    require_intent_mandate,
    require_cart_mandate,
    require_payment_mandate,
    require_merchant_signature,
    require_verifiable_credential,
    require_wallet_attestation,
    require_risk_signals,
    require_tokenized_instrument,
    allow_x402_extension,
    max_human_present_amount_minor,
    max_human_not_present_amount_minor,
    trusted_credential_issuers_json,
    updated_by,
    updated_at
) VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id) DO UPDATE SET
    enabled = EXCLUDED.enabled,
    allowed_protocol_bindings_json = EXCLUDED.allowed_protocol_bindings_json,
    allowed_transaction_modes_json = EXCLUDED.allowed_transaction_modes_json,
    allowed_payment_rails_json = EXCLUDED.allowed_payment_rails_json,
    allowed_currencies_json = EXCLUDED.allowed_currencies_json,
    default_currency = EXCLUDED.default_currency,
    require_intent_mandate = EXCLUDED.require_intent_mandate,
    require_cart_mandate = EXCLUDED.require_cart_mandate,
    require_payment_mandate = EXCLUDED.require_payment_mandate,
    require_merchant_signature = EXCLUDED.require_merchant_signature,
    require_verifiable_credential = EXCLUDED.require_verifiable_credential,
    require_wallet_attestation = EXCLUDED.require_wallet_attestation,
    require_risk_signals = EXCLUDED.require_risk_signals,
    require_tokenized_instrument = EXCLUDED.require_tokenized_instrument,
    allow_x402_extension = EXCLUDED.allow_x402_extension,
    max_human_present_amount_minor = EXCLUDED.max_human_present_amount_minor,
    max_human_not_present_amount_minor = EXCLUDED.max_human_not_present_amount_minor,
    trusted_credential_issuers_json = EXCLUDED.trusted_credential_issuers_json,
    updated_by = EXCLUDED.updated_by,
    updated_at = CURRENT_TIMESTAMP
RETURNING tenant_id,
          enabled,
          allowed_protocol_bindings_json,
          allowed_transaction_modes_json,
          allowed_payment_rails_json,
          allowed_currencies_json,
          default_currency,
          require_intent_mandate,
          require_cart_mandate,
          require_payment_mandate,
          require_merchant_signature,
          require_verifiable_credential,
          require_wallet_attestation,
          require_risk_signals,
          require_tokenized_instrument,
          allow_x402_extension,
          max_human_present_amount_minor,
          max_human_not_present_amount_minor,
          trusted_credential_issuers_json,
          COALESCE(updated_by,''),
          updated_at
`, item.TenantID,
		item.Enabled,
		validJSONOr(mustJSON(item.AllowedProtocolBindings), "[]"),
		validJSONOr(mustJSON(item.AllowedTransactionModes), "[]"),
		validJSONOr(mustJSON(item.AllowedPaymentRails), "[]"),
		validJSONOr(mustJSON(item.AllowedCurrencies), "[]"),
		item.DefaultCurrency,
		item.RequireIntentMandate,
		item.RequireCartMandate,
		item.RequirePaymentMandate,
		item.RequireMerchantSignature,
		item.RequireVerifiableCredential,
		item.RequireWalletAttestation,
		item.RequireRiskSignals,
		item.RequireTokenizedInstrument,
		item.AllowX402Extension,
		item.MaxHumanPresentAmountMinor,
		item.MaxHumanNotPresentAmountMinor,
		validJSONOr(mustJSON(item.TrustedCredentialIssuers), "[]"),
		item.UpdatedBy,
	)

	var (
		out                  PaymentAP2Profile
		protocolBindingsJSON string
		transactionModesJSON string
		paymentRailsJSON     string
		currenciesJSON       string
		trustedIssuersJSON   string
		updatedRaw           interface{}
	)
	if err := row.Scan(
		&out.TenantID,
		&out.Enabled,
		&protocolBindingsJSON,
		&transactionModesJSON,
		&paymentRailsJSON,
		&currenciesJSON,
		&out.DefaultCurrency,
		&out.RequireIntentMandate,
		&out.RequireCartMandate,
		&out.RequirePaymentMandate,
		&out.RequireMerchantSignature,
		&out.RequireVerifiableCredential,
		&out.RequireWalletAttestation,
		&out.RequireRiskSignals,
		&out.RequireTokenizedInstrument,
		&out.AllowX402Extension,
		&out.MaxHumanPresentAmountMinor,
		&out.MaxHumanNotPresentAmountMinor,
		&trustedIssuersJSON,
		&out.UpdatedBy,
		&updatedRaw,
	); err != nil {
		return PaymentAP2Profile{}, err
	}
	out.AllowedProtocolBindings = parseJSONArrayString(protocolBindingsJSON)
	out.AllowedTransactionModes = parseJSONArrayString(transactionModesJSON)
	out.AllowedPaymentRails = parseJSONArrayString(paymentRailsJSON)
	out.AllowedCurrencies = parseJSONArrayString(currenciesJSON)
	out.TrustedCredentialIssuers = parseJSONArrayString(trustedIssuersJSON)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	return out, nil
}
