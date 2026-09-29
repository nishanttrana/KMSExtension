ALTER TABLE payment_keys
    ADD COLUMN IF NOT EXISTS key_environment TEXT NOT NULL DEFAULT 'prod';

ALTER TABLE payment_policy
    ADD COLUMN IF NOT EXISTS allowed_kbpk_classes_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE payment_policy
    ADD COLUMN IF NOT EXISTS allowed_tr31_exportability_json TEXT NOT NULL DEFAULT '["E","N","S"]';

ALTER TABLE payment_policy
    ADD COLUMN IF NOT EXISTS tr31_exportability_matrix_json TEXT NOT NULL DEFAULT '{}';

ALTER TABLE payment_policy
    ADD COLUMN IF NOT EXISTS payment_key_purpose_matrix_json TEXT NOT NULL DEFAULT '{}';

ALTER TABLE payment_policy
    ADD COLUMN IF NOT EXISTS allowed_iso20022_canonicalization_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE payment_policy
    ADD COLUMN IF NOT EXISTS allowed_iso20022_signature_suites_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE payment_policy
    ADD COLUMN IF NOT EXISTS allowed_pin_translation_pairs_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE payment_policy
    ADD COLUMN IF NOT EXISTS allowed_cvv_service_codes_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE payment_policy
    ADD COLUMN IF NOT EXISTS pvki_min INTEGER NOT NULL DEFAULT 0;

ALTER TABLE payment_policy
    ADD COLUMN IF NOT EXISTS pvki_max INTEGER NOT NULL DEFAULT 9;

ALTER TABLE payment_policy
    ADD COLUMN IF NOT EXISTS allowed_issuer_profiles_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE payment_policy
    ADD COLUMN IF NOT EXISTS allowed_mac_domains_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE payment_policy
    ADD COLUMN IF NOT EXISTS allowed_mac_padding_profiles_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE payment_policy
    ADD COLUMN IF NOT EXISTS dual_control_required_operations_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE payment_policy
    ADD COLUMN IF NOT EXISTS hsm_required_operations_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE payment_policy
    ADD COLUMN IF NOT EXISTS rotation_interval_days_by_class_json TEXT NOT NULL DEFAULT '{}';

ALTER TABLE payment_policy
    ADD COLUMN IF NOT EXISTS runtime_environment TEXT NOT NULL DEFAULT 'prod';

ALTER TABLE payment_policy
    ADD COLUMN IF NOT EXISTS disallow_test_keys_in_prod BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE payment_policy
    ADD COLUMN IF NOT EXISTS disallow_prod_keys_in_test BOOLEAN NOT NULL DEFAULT FALSE;
