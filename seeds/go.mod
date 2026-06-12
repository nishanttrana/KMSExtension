// Placeholder module: keeps the recovered sources under seeds/ out of the
// root build. These files still import "vecta-kms/..." paths from the core
// repo and will be rewritten one by one as they are promoted to services/.
module vecta-kms-extension/seeds

go 1.26
