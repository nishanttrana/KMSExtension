ALTER TABLE payment_policy
    ADD COLUMN IF NOT EXISTS strict_pci_dss_4_0 BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE payment_policy
    ADD COLUMN IF NOT EXISTS require_key_id_for_operations BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE payment_policy
    ADD COLUMN IF NOT EXISTS allow_tcp_interface BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE payment_policy
    ADD COLUMN IF NOT EXISTS require_jwt_on_tcp BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE payment_policy
    ADD COLUMN IF NOT EXISTS max_tcp_payload_bytes INTEGER NOT NULL DEFAULT 262144;

ALTER TABLE payment_policy
    ADD COLUMN IF NOT EXISTS allowed_tcp_operations_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE payment_policy
    ADD COLUMN IF NOT EXISTS allowed_pin_block_formats_json TEXT NOT NULL DEFAULT '["ISO-0","ISO-1","ISO-3"]';

ALTER TABLE payment_policy
    ADD COLUMN IF NOT EXISTS block_wildcard_pan BOOLEAN NOT NULL DEFAULT TRUE;
