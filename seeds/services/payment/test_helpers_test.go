package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/metering"
)

type nopPaymentPublisher struct {
	mu       sync.Mutex
	subjects []string
	payloads [][]byte
}

func (p *nopPaymentPublisher) Publish(_ context.Context, subject string, payload []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subjects = append(p.subjects, subject)
	p.payloads = append(p.payloads, payload)
	return nil
}

// Event returns the last event published on subject (nil if none).
func (p *nopPaymentPublisher) Event(subject string) map[string]interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := len(p.subjects) - 1; i >= 0; i-- {
		if p.subjects[i] == subject {
			var ev map[string]interface{}
			_ = json.Unmarshal(p.payloads[i], &ev)
			return ev
		}
	}
	return nil
}

func (p *nopPaymentPublisher) Count(subject string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, s := range p.subjects {
		if s == subject {
			n++
		}
	}
	return n
}

type fakePaymentKeyCore struct {
	mu        sync.Mutex
	counter   int
	materials map[string][]byte
	usages    map[string]string // key ID -> usage of its last export
}

func newFakePaymentKeyCore() *fakePaymentKeyCore {
	return &fakePaymentKeyCore{
		materials: map[string][]byte{},
	}
}

func (f *fakePaymentKeyCore) key(tenantID string, keyID string) string {
	return strings.TrimSpace(tenantID) + ":" + strings.TrimSpace(keyID)
}

func (f *fakePaymentKeyCore) ensureMaterial(tenantID string, keyID string) []byte {
	k := f.key(tenantID, keyID)
	if raw, ok := f.materials[k]; ok {
		out := make([]byte, len(raw))
		copy(out, raw)
		return out
	}
	sum := sha256.Sum256([]byte(k))
	raw := append([]byte{}, sum[:16]...)
	f.materials[k] = append([]byte{}, raw...)
	return raw
}

func (f *fakePaymentKeyCore) GetKey(_ context.Context, tenantID string, keyID string) (map[string]interface{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw := f.ensureMaterial(tenantID, keyID)
	sum := sha256.Sum256(raw)
	return map[string]interface{}{
		"id":  keyID,
		"kcv": strings.ToUpper(hex.EncodeToString(sum[:3])),
	}, nil
}

func (f *fakePaymentKeyCore) ExportKey(_ context.Context, tenantID string, keyID string, usage string) (map[string]interface{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.usages == nil {
		f.usages = map[string]string{}
	}
	f.usages[keyID] = usage
	raw := f.ensureMaterial(tenantID, keyID)
	return map[string]interface{}{
		"material": base64.StdEncoding.EncodeToString(raw),
	}, nil
}

func (f *fakePaymentKeyCore) ImportKey(_ context.Context, tenantID string, _ string, _ string, _ string, _ string, materialB64 string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, _ := base64.StdEncoding.DecodeString(materialB64)
	f.counter++
	id := "imported_" + strconv.Itoa(f.counter)
	f.materials[f.key(tenantID, id)] = append([]byte{}, raw...)
	return id, nil
}

func (f *fakePaymentKeyCore) RotateKey(_ context.Context, _ string, _ string, _ string) (map[string]interface{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counter++
	return map[string]interface{}{
		"version_id": "ver_" + strconv.Itoa(f.counter),
	}, nil
}

func (f *fakePaymentKeyCore) Encrypt(_ context.Context, _ string, _ string, plaintextB64 string, ivB64 string, _ string) (map[string]interface{}, error) {
	raw, _ := base64.StdEncoding.DecodeString(plaintextB64)
	enc := append([]byte("enc:"), raw...)
	if strings.TrimSpace(ivB64) == "" {
		ivB64 = base64.StdEncoding.EncodeToString([]byte("123456789012"))
	}
	return map[string]interface{}{
		"ciphertext": base64.StdEncoding.EncodeToString(enc),
		"iv":         ivB64,
	}, nil
}

func (f *fakePaymentKeyCore) Decrypt(_ context.Context, _ string, _ string, ciphertextB64 string, _ string) (map[string]interface{}, error) {
	raw, _ := base64.StdEncoding.DecodeString(ciphertextB64)
	if strings.HasPrefix(string(raw), "enc:") {
		raw = raw[4:]
	}
	return map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(raw),
	}, nil
}

func (f *fakePaymentKeyCore) Sign(_ context.Context, _ string, keyID string, dataB64 string) (map[string]interface{}, error) {
	data, _ := base64.StdEncoding.DecodeString(dataB64)
	sum := sha256.Sum256(append([]byte(strings.TrimSpace(keyID)), data...))
	return map[string]interface{}{
		"signature": base64.StdEncoding.EncodeToString(sum[:]),
	}, nil
}

func (f *fakePaymentKeyCore) Verify(_ context.Context, _ string, keyID string, dataB64 string, signatureB64 string) (map[string]interface{}, error) {
	data, _ := base64.StdEncoding.DecodeString(dataB64)
	got, _ := base64.StdEncoding.DecodeString(signatureB64)
	sum := sha256.Sum256(append([]byte(strings.TrimSpace(keyID)), data...))
	ok := subtle.ConstantTimeCompare(got, sum[:]) == 1
	return map[string]interface{}{
		"verified": ok,
	}, nil
}

func newPaymentService(t *testing.T) (*Service, *SQLStore, *fakePaymentKeyCore, *nopPaymentPublisher) {
	t.Helper()
	conn, err := pkgdb.Open(context.Background(), pkgdb.Config{
		UseSQLite:  true,
		SQLitePath: ":memory:",
		MaxOpen:    1,
		MaxIdle:    1,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := createPaymentSchemaForTest(conn); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	store := NewSQLStore(conn)
	keycore := newFakePaymentKeyCore()
	pub := &nopPaymentPublisher{}
	svc := NewService(store, keycore, pub, metering.NewMeter(0, time.Hour))
	return svc, store, keycore, pub
}

func newPaymentHandler(t *testing.T) (*Handler, *Service, *fakePaymentKeyCore, *nopPaymentPublisher) {
	t.Helper()
	svc, _, keycore, pub := newPaymentService(t)
	return NewHandler(svc), svc, keycore, pub
}

func createPaymentSchemaForTest(conn *pkgdb.DB) error {
	stmts := []string{
		`CREATE TABLE payment_keys (
			id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			key_id TEXT NOT NULL,
			payment_type TEXT NOT NULL,
			key_environment TEXT NOT NULL DEFAULT 'prod',
			usage_code TEXT NOT NULL,
			mode_of_use TEXT NOT NULL,
			key_version_num TEXT NOT NULL DEFAULT '00',
			exportability TEXT NOT NULL DEFAULT 'E',
			tr31_header TEXT,
			kcv BLOB,
			iso20022_party_id TEXT,
			iso20022_msg_types TEXT NOT NULL DEFAULT '[]',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE tr31_translations (
			id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			source_key_id TEXT NOT NULL DEFAULT '',
			source_format TEXT NOT NULL,
			target_format TEXT NOT NULL,
			kek_key_id TEXT NOT NULL DEFAULT '',
			result_block TEXT,
			status TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE pin_operations_log (
			id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			operation TEXT NOT NULL,
			source_format TEXT,
			target_format TEXT,
			zpk_key_id TEXT,
			result TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE payment_policy (
			tenant_id TEXT PRIMARY KEY,
			allowed_tr31_versions_json TEXT NOT NULL DEFAULT '["B","C","D"]',
			require_kbpk_for_tr31 BOOLEAN NOT NULL DEFAULT FALSE,
			allowed_kbpk_classes_json TEXT NOT NULL DEFAULT '[]',
			allowed_tr31_exportability_json TEXT NOT NULL DEFAULT '["E","N","S"]',
			tr31_exportability_matrix_json TEXT NOT NULL DEFAULT '{}',
			payment_key_purpose_matrix_json TEXT NOT NULL DEFAULT '{}',
			allow_inline_key_material BOOLEAN NOT NULL DEFAULT TRUE,
			max_iso20022_payload_bytes INTEGER NOT NULL DEFAULT 1048576,
			require_iso20022_lau_context BOOLEAN NOT NULL DEFAULT FALSE,
			allowed_iso20022_canonicalization_json TEXT NOT NULL DEFAULT '[]',
			allowed_iso20022_signature_suites_json TEXT NOT NULL DEFAULT '[]',
			strict_pci_dss_4_0 BOOLEAN NOT NULL DEFAULT FALSE,
			require_key_id_for_operations BOOLEAN NOT NULL DEFAULT FALSE,
			allow_tcp_interface BOOLEAN NOT NULL DEFAULT TRUE,
			require_jwt_on_tcp BOOLEAN NOT NULL DEFAULT TRUE,
			max_tcp_payload_bytes INTEGER NOT NULL DEFAULT 262144,
			allowed_tcp_operations_json TEXT NOT NULL DEFAULT '[]',
			allowed_pin_block_formats_json TEXT NOT NULL DEFAULT '["ISO-0","ISO-1","ISO-3"]',
			allowed_pin_translation_pairs_json TEXT NOT NULL DEFAULT '[]',
			disable_iso0_pin_block BOOLEAN NOT NULL DEFAULT FALSE,
			allowed_cvv_service_codes_json TEXT NOT NULL DEFAULT '[]',
			pvki_min INTEGER NOT NULL DEFAULT 0,
			pvki_max INTEGER NOT NULL DEFAULT 9,
			allowed_issuer_profiles_json TEXT NOT NULL DEFAULT '[]',
			allowed_mac_domains_json TEXT NOT NULL DEFAULT '[]',
			allowed_mac_padding_profiles_json TEXT NOT NULL DEFAULT '[]',
			dual_control_required_operations_json TEXT NOT NULL DEFAULT '[]',
			hsm_required_operations_json TEXT NOT NULL DEFAULT '[]',
			rotation_interval_days_by_class_json TEXT NOT NULL DEFAULT '{}',
			runtime_environment TEXT NOT NULL DEFAULT 'prod',
			disallow_test_keys_in_prod BOOLEAN NOT NULL DEFAULT FALSE,
			disallow_prod_keys_in_test BOOLEAN NOT NULL DEFAULT FALSE,
			decimalization_table TEXT NOT NULL DEFAULT '0123456789012345',
			block_wildcard_pan BOOLEAN NOT NULL DEFAULT TRUE,
			updated_by TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE payment_ap2_profile (
			tenant_id TEXT PRIMARY KEY,
			enabled BOOLEAN NOT NULL DEFAULT FALSE,
			allowed_protocol_bindings_json TEXT NOT NULL DEFAULT '["a2a","mcp"]',
			allowed_transaction_modes_json TEXT NOT NULL DEFAULT '["human_present","human_not_present"]',
			allowed_payment_rails_json TEXT NOT NULL DEFAULT '["card","ach","rtp"]',
			allowed_currencies_json TEXT NOT NULL DEFAULT '["USD"]',
			default_currency TEXT NOT NULL DEFAULT 'USD',
			require_intent_mandate BOOLEAN NOT NULL DEFAULT TRUE,
			require_cart_mandate BOOLEAN NOT NULL DEFAULT TRUE,
			require_payment_mandate BOOLEAN NOT NULL DEFAULT TRUE,
			require_merchant_signature BOOLEAN NOT NULL DEFAULT TRUE,
			require_verifiable_credential BOOLEAN NOT NULL DEFAULT TRUE,
			require_wallet_attestation BOOLEAN NOT NULL DEFAULT FALSE,
			require_risk_signals BOOLEAN NOT NULL DEFAULT TRUE,
			require_tokenized_instrument BOOLEAN NOT NULL DEFAULT TRUE,
			allow_x402_extension BOOLEAN NOT NULL DEFAULT FALSE,
			max_human_present_amount_minor INTEGER NOT NULL DEFAULT 1000000,
			max_human_not_present_amount_minor INTEGER NOT NULL DEFAULT 250000,
			trusted_credential_issuers_json TEXT NOT NULL DEFAULT '[]',
			updated_by TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
	}
	for _, stmt := range stmts {
		if _, err := conn.SQL().Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}
