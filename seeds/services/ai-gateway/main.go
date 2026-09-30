package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	pkgsvctls "vecta-kms/pkg/svctls"

	"github.com/nats-io/nats.go"
	"google.golang.org/grpc"

	pkgaudit "vecta-kms/pkg/audit"
	pkgauditmw "vecta-kms/pkg/auditmw"
	pkgauth "vecta-kms/pkg/auth"
	pkgconfig "vecta-kms/pkg/config"
	pkgconsul "vecta-kms/pkg/consul"
	pkgdb "vecta-kms/pkg/db"
	pkgevents "vecta-kms/pkg/events"
	pkggrpc "vecta-kms/pkg/grpc"
	pkgjwtauth "vecta-kms/pkg/jwtauth"
	pkgruntimecfg "vecta-kms/pkg/runtimecfg"
)

// EventPublisher abstracts NATS JetStream publishing so the gateway
// can run without NATS (logs a warning and skips event publishing).
type EventPublisher interface {
	Publish(ctx context.Context, subject string, data []byte) error
}

var logger = log.New(os.Stdout, "[ai-gateway] ", log.LstdFlags|log.Lmicroseconds)

func main() {
	cfg := pkgconfig.Load()

	if err := pkgruntimecfg.ValidateServiceConfig("kms-ai-gateway", cfg); err != nil {
		log.Fatalf("config validation failed: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// Internal mTLS identity from the internal-services Sub CA; nothing is
	// served or called before it (docs/SECURITY/INTERNAL_TLS.md).
	if _, err := pkgsvctls.Init(ctx, "kms-ai-gateway", pkgsvctls.Options{Logger: logger}); err != nil {
		logger.Fatalf("internal mTLS enrolment failed: %v", err)
	}

	// ── Database ───────────────────────────────────────────────────
	dbConn, err := pkgdb.Open(ctx, pkgdb.Config{
		PostgresDSN:     cfg.PostgresDSN,
		PostgresRODSN:   cfg.PostgresRODSN,
		SQLitePath:      cfg.SQLitePath,
		UseSQLite:       cfg.UseSQLite,
		MaxOpen:         cfg.DBMaxOpen,
		MaxIdle:         cfg.DBMaxIdle,
		ConnMaxIdleTime: time.Duration(cfg.DBConnMaxIdleTimeSec) * time.Second,
		ConnMaxLifetime: time.Duration(cfg.DBConnMaxLifetimeSec) * time.Second,
	})
	if err != nil {
		logger.Fatalf("db open failed: %v", err)
	}
	defer dbConn.Close() //nolint:errcheck

	if err := dbConn.RunMigrations(ctx, migrationPath()); err != nil {
		logger.Fatalf("migration failed: %v", err)
	}

	// ── NATS for audit event publishing ────────────────────────────
	var publisher EventPublisher
	if nc, js, err := initNATS(cfg.NATSURL); err == nil {
		defer nc.Close()
		publisher = pkgevents.NewPublisher(js, 3, "audit.ai-gateway.dead_letter")
	} else {
		logger.Printf("nats unavailable, ai-gateway event publishing disabled: %v", err)
	}

	// ── Store & Handler ────────────────────────────────────────────
	store := NewSQLStore(dbConn)
	handler := NewHandler(store, publisher)

	// ── JWT middleware (fail-closed) ───────────────────────────────
	// The AI Gateway proxies LLM traffic and manages per-tenant
	// policies; until 1562c827 it derived the tenant ID from an
	// unsigned X-Tenant-ID header, allowing trivial cross-tenant
	// access. The middleware below requires a valid Bearer token on
	// every request; the tenant helper then verifies that the header
	// tenant matches the JWT claim via pkg/tenantcheck.Enforce.
	jwtParser, err := pkgjwtauth.LoadParser(pkgjwtauth.Config{
		Prefix:   "AI_GATEWAY",
		Issuer:   cfg.JWTIssuer,
		Audience: cfg.JWTAudience,
	})
	if err != nil {
		logger.Fatalf("jwt parser init failed: %v", err)
	}
	if jwtParser == nil {
		logger.Fatalf("AI_GATEWAY_JWT_PUBLIC_KEY_PEM (or _B64) is required to start ai-gateway")
	}
	authedHandler := pkgauth.HTTPMiddleware(handler, jwtParser)

	// ── HTTP server ────────────────────────────────────────────────
	httpPort := envOr("HTTP_PORT", "8320")
	httpSrv := pkgconfig.NewHTTPServer(httpPort, pkgauditmw.Wrap(authedHandler, publisher, "ai-gateway"))
	go func() {
		logger.Printf("https (mTLS) listening on :%s", httpPort)
		if err := httpSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("http server failed: %v", err)
		}
	}()

	// ── gRPC + health server ───────────────────────────────────────
	grpcPort := envOr("GRPC_PORT", "18320")
	tlsCfg, err := devMTLSConfig()
	if err != nil {
		logger.Fatalf("mtls config failed: %v", err)
	}
	grpcSrv := pkggrpc.NewServer(tlsCfg, logger)
	lis, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		logger.Fatalf("grpc listen failed: %v", err)
	}
	go func() {
		logger.Printf("grpc+health listening on :%s", grpcPort)
		if err := grpcSrv.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			logger.Fatalf("grpc server failed: %v", err)
		}
	}()

	// ── Consul registration ────────────────────────────────────────
	if reg, err := pkgconsul.NewRegistrar(cfg.ConsulAddress, "kms-ai-gateway-"+httpPort, "kms-ai-gateway", "127.0.0.1", mustAtoi(grpcPort)); err == nil {
		if err := reg.Register(ctx); err != nil {
			logger.Printf("consul register failed: %v", err)
		} else {
			defer reg.Deregister(context.Background()) //nolint:errcheck
		}
	}

	// ── Graceful shutdown ──────────────────────────────────────────
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	grpcSrv.GracefulStop()
}

func initNATS(url string) (*nats.Conn, nats.JetStreamContext, error) {
	nc, err := pkgevents.Connect(url, "kms-ai-gateway", logger.Printf)
	if err != nil {
		return nil, nil, err
	}
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, nil, err
	}
	_, _ = js.AddStream(pkgaudit.StreamConfig())
	return nc, js, nil
}

func migrationPath() string {
	candidates := []string{
		filepath.Join("services", "ai-gateway", "migrations"),
		filepath.Join(".", "migrations"),
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return filepath.Join("services", "ai-gateway", "migrations")
}

func devMTLSConfig() (*tls.Config, error) {
	return pkgsvctls.Current().ServerConfig(), nil
}

func envOr(k string, d string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d
	}
	return v
}

func mustAtoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}
