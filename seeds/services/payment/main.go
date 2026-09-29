package main

import (
	"log"
	"os"
	"strings"
	"time"
	"vecta-kms/pkg/servicetoken"

	"vecta-kms/pkg/metering"
	pkgplatform "vecta-kms/pkg/platform"
)

var logger = log.New(os.Stdout, "[payment] ", log.LstdFlags|log.Lmicroseconds)

// main boots the platform spine and mounts the payment crypto service plus
// its optional ISO 8583-style TCP listener. SkipJWT is set because payment
// endpoints authenticate per-route: operator APIs validate JWTs in handlers
// and terminal injection endpoints use terminal bearer tokens.
func main() {
	// Attach this service's per-service JWT to internal keycore calls (no-op
	// when INTERNAL_SERVICE_BOOTSTRAP_SECRET is unset).
	servicetoken.SetDefault(servicetoken.FromEnv("kms-payment"))
	rt, err := pkgplatform.Boot(pkgplatform.Options{
		ServiceName:   "payment",
		JWTScope:      "PAYMENT",
		HTTPPort:      "8170",
		GRPCPort:      "18170",
		MigrationsDir: "services/payment/migrations",
		SkipJWT:       true,
	})
	if err != nil {
		log.Fatalf("[payment] boot failed: %v", err)
	}
	defer rt.Close()
	logger = rt.Logger

	var publisher EventPublisher
	if rt.Audit != nil {
		publisher = rt.Audit.Publisher()
	}

	keycoreURL := envOr("KEYCORE_URL", "https://keycore:8010")
	svc := NewService(
		NewSQLStore(rt.DB),
		NewHTTPKeyCoreClient(keycoreURL, 5*time.Second),
		publisher,
		metering.NewMeter(0, 0),
	)
	maybeStartPaymentTCPServer(rt.Ctx, svc, logger, rt.Cfg.JWTIssuer, rt.Cfg.JWTAudience)

	if err := rt.Serve(NewHandler(svc)); err != nil {
		rt.Logger.Fatalf("serve failed: %v", err)
	}
}

func envOr(k string, d string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d
	}
	return v
}
