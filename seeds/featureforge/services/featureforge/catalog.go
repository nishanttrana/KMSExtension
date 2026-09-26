package featureforge

// DefaultCatalog is the allow-list of config-mode actions. Anything an admin
// can "spell" into existence via config mode MUST appear here. This is the
// single most important guardrail in config mode: it bounds the universe of
// possible outcomes to a reviewed, finite set.
//
// To extend the platform's self-service surface, you add an entry here AND a
// corresponding applier — both go through normal code review. The LLM can
// never invent an action outside this list.
func DefaultCatalog() []CatalogAction {
	return []CatalogAction{
		{
			Name:    "policy.restrict_algorithm",
			Summary: "Disallow a named crypto algorithm for a tenant (e.g. RSA-1024).",
			RequiredParams: map[string]string{
				"algorithm": "algorithm identifier to block, e.g. RSA-1024",
			},
			RequiresQuorum: false,
			Sensitive:      false,
		},
		{
			Name:    "policy.require_approval_for",
			Summary: "Require governance approval before a named operation.",
			RequiredParams: map[string]string{
				"operation": "operation name, e.g. key.delete or key.export",
			},
			RequiresQuorum: true,
			Sensitive:      true,
		},
		{
			Name:    "policy.set_min_key_size",
			Summary: "Set a minimum key size for a key type.",
			RequiredParams: map[string]string{
				"key_type": "key type, e.g. RSA or EC",
				"min_bits": "minimum size in bits, e.g. 2048",
			},
			RequiresQuorum: false,
			Sensitive:      false,
		},
		{
			Name:    "pqc.enable_hybrid",
			Summary: "Enable hybrid (classical+PQC) posture on an interface.",
			RequiredParams: map[string]string{
				"interface": "interface name, e.g. rest or kmip",
			},
			RequiresQuorum: true,
			Sensitive:      false,
		},
	}
}

// FindAction returns the catalog entry by name, or nil.
func FindAction(catalog []CatalogAction, name string) *CatalogAction {
	for i := range catalog {
		if catalog[i].Name == name {
			return &catalog[i]
		}
	}
	return nil
}
