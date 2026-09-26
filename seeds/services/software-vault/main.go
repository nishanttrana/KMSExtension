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

	"google.golang.org/grpc"

	pkgconfig "vecta-kms/pkg/config"
	pkgconsul "vecta-kms/pkg/consul"
	pkgcrypto "vecta-kms/pkg/crypto"
	pkggrpc "vecta-kms/pkg/grpc"
	pkgruntimecfg "vecta-kms/pkg/runtimecfg"
)

var logger = log.New(os.Stdout, "[software-vault] ", log.LstdFlags|log.Lmicroseconds)

func main() {
	cfg := pkgconfig.Load()

	if err := pkgruntimecfg.ValidateServiceConfig("kms-software-vault", cfg); err != nil {
		log.Fatalf("config validation failed: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	providerName := strings.ToLower(strings.TrimSpace(envOr("HSM_PROVIDER", "")))
	if providerName == "" {
		if cfg.HSMMode == pkgconfig.HSMModeSoftware {
			providerName = ProviderSoftware
		} else {
			providerName = ProviderSoftware
		}
	}
	passphrase := envOr("SOFTWARE_VAULT_PASSPHRASE", "")
	if strings.TrimSpace(passphrase) == "" {
		passphrase = "vecta-dev-passphrase"
		logger.Printf("software vault passphrase not set; using development default")
	}

	provider, err := NewProvider(ProviderConfig{
		ProviderName:        providerName,
		Passphrase:          passphrase,
		HardwareFingerprint: envOr("SOFTWARE_VAULT_HW_FINGERPRINT", ""),
		MlockRequired:       envBool("SOFTWARE_VAULT_MLOCK_REQUIRED", false),
		ArgonMemoryKB:       envUint32("SOFTWARE_VAULT_ARGON2_MEMORY_KB", 128*1024),
		ArgonIterations:     envUint32("SOFTWARE_VAULT_ARGON2_ITERATIONS", 4),
		ArgonParallel:       envUint8("SOFTWARE_VAULT_ARGON2_PARALLELISM", 4),
		Thales: ThalesConfig{
			Endpoint:  envOr("THALES_ENDPOINT", ""),
			Partition: envOr("THALES_PARTITION", ""),
			SlotLabel: envOr("THALES_SLOT_LABEL", ""),
		},
		Vecta: VectaConfig{
			Endpoint:  envOr("VECTA_ENDPOINT", ""),
			ProjectID: envOr("VECTA_PROJECT_ID", ""),
			KeyDomain: envOr("VECTA_KEY_DOMAIN", ""),
		},
	})
	if err != nil {
		logger.Fatalf("provider init failed: %v", err)
	}
	defer provider.Close() //nolint:errcheck

	if provider.Name() == ProviderSoftware && !envBool("SUPPRESS_SOFTWARE_MODE_WARNING", false) {
		logger.Printf("WARNING: SOFTWARE-ONLY MODE ENABLED - NOT FOR PRODUCTION")
	}
	logger.Printf("provider=%s hsm_mode=%s supported_providers=%s", provider.Name(), cfg.HSMMode, strings.Join(supportedProviders(), ","))

	svc := NewService(provider)
	handler := NewHandler(svc)

	httpPort := envOr("HTTP_PORT", "8440")
	httpSrv := pkgconfig.NewHTTPServer(httpPort, handler)
	go func() {
		logger.Printf("http listening on :%s", httpPort)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("http server failed: %v", err)
		}
	}()

	grpcPort := envOr("GRPC_PORT", "18440")
	tlsCfg, err := devMTLSConfig()
	if err != nil {
		logger.Fatalf("mtls config failed: %v", err)
	}
	grpcSrv := pkggrpc.NewServer(tlsCfg, logger)
	registerVaultGRPCServer(grpcSrv, svc)

	lis, listenerLabel, err := buildGRPCListener(grpcPort, envOr("GRPC_UNIX_SOCKET", ""))
	if err != nil {
		logger.Fatalf("grpc listen failed: %v", err)
	}
	defer lis.Close() //nolint:errcheck
	go func() {
		logger.Printf("grpc+health listening on %s", listenerLabel)
		if err := grpcSrv.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			logger.Fatalf("grpc server failed: %v", err)
		}
	}()

	if lis.Addr().Network() == "tcp" {
		if reg, err := pkgconsul.NewRegistrar(cfg.ConsulAddress, "kms-software-vault-"+httpPort, "kms-software-vault", "127.0.0.1", mustAtoi(grpcPort)); err == nil {
			if err := reg.Register(ctx); err != nil {
				logger.Printf("consul register failed: %v", err)
			} else {
				defer reg.Deregister(context.Background()) //nolint:errcheck
			}
		}
	}

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	grpcSrv.GracefulStop()
	if err := svc.Close(); err != nil {
		logger.Printf("provider close failed: %v", err)
	}
}

func buildGRPCListener(port string, unixSocket string) (net.Listener, string, error) {
	unixSocket = strings.TrimSpace(unixSocket)
	if unixSocket == "" {
		lis, err := net.Listen("tcp", ":"+port)
		if err != nil {
			return nil, "", err
		}
		return lis, ":" + port, nil
	}
	if err := os.MkdirAll(filepath.Dir(unixSocket), 0o700); err != nil {
		return nil, "", err
	}
	_ = os.Remove(unixSocket)
	lis, err := net.Listen("unix", unixSocket)
	if err != nil {
		return nil, "", err
	}
	_ = os.Chmod(unixSocket, 0o600)
	return lis, "unix://" + unixSocket, nil
}

func devMTLSConfig() (*tls.Config, error) {
	return pkgcrypto.SelfSignedMTLSConfig("kms-software-vault-local")
}

func mustAtoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}
