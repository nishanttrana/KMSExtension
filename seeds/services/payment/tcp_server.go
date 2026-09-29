package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/logsanitize"
	pkgsvctls "vecta-kms/pkg/svctls"
)

type paymentTCPRequest struct {
	RequestID     string          `json:"request_id"`
	TenantID      string          `json:"tenant_id"`
	Operation     string          `json:"operation"`
	JWT           string          `json:"jwt"`
	Authorization string          `json:"authorization"`
	Payload       json.RawMessage `json:"payload"`
}

type paymentTCPResponse struct {
	OK        bool        `json:"ok"`
	RequestID string      `json:"request_id,omitempty"`
	Operation string      `json:"operation,omitempty"`
	Result    interface{} `json:"result,omitempty"`
	Error     *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Status  int    `json:"status"`
	} `json:"error,omitempty"`
}

func loadPaymentJWTParser(issuer string, audience string) (func(string) (*pkgauth.Claims, error), error) {
	pubPEM := strings.TrimSpace(os.Getenv("PAYMENT_JWT_PUBLIC_KEY_PEM"))
	if pubPEM == "" {
		if b64 := strings.TrimSpace(os.Getenv("PAYMENT_JWT_PUBLIC_KEY_B64")); b64 != "" {
			raw, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				return nil, err
			}
			pubPEM = string(raw)
		}
	}
	if pubPEM == "" {
		path := strings.TrimSpace(os.Getenv("JWT_PUBLIC_KEY_PATH"))
		if path == "" {
			path = "certs/jwt_public.pem"
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, nil
			}
			return nil, err
		}
		pubPEM = string(raw)
	}
	pubPEM = strings.ReplaceAll(pubPEM, `\n`, "\n")
	pub, err := pkgcrypto.ParseRSAPublicKeyPEM(pubPEM)
	if err != nil {
		return nil, errors.New("unable to parse RSA JWT public key")
	}
	return func(token string) (*pkgauth.Claims, error) {
		return pkgauth.ParseRS256WithOptions(token, pub, pkgauth.ParseOptions{
			Issuer:   issuer,
			Audience: audience,
			Leeway:   30 * time.Second,
		})
	}, nil
}

func startPaymentTCPServer(ctx context.Context, svc *Service, addr string, parseJWT func(string) (*pkgauth.Claims, error), logger *log.Logger) error {
	id := pkgsvctls.Current()
	if id == nil {
		return errors.New("payment tcp: no TLS certificate (svctls not initialised); refusing plaintext")
	}
	raw, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	// External terminals: TLS 1.3, server-authenticated with the service's
	// internal-CA certificate; terminals authenticate in-protocol (JWT).
	// Never plaintext (CLAUDE.md rule 10).
	lis := tls.NewListener(raw, &tls.Config{
		MinVersion:     tls.VersionTLS13,
		ClientAuth:     tls.NoClientCert,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return id.Certificate() },
	})
	logger.Printf("payment tcp (TLS 1.3) listening on %s", addr)
	go func() {
		<-ctx.Done()
		_ = lis.Close()
	}()
	for {
		conn, err := lis.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			logger.Printf("payment tcp accept error: %v", err)
			continue
		}
		go servePaymentTCPConn(ctx, conn, svc, parseJWT, logger)
	}
}

func servePaymentTCPConn(ctx context.Context, conn net.Conn, svc *Service, parseJWT func(string) (*pkgauth.Claims, error), logger *log.Logger) {
	defer conn.Close() //nolint:errcheck
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Minute))
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	defer writer.Flush() //nolint:errcheck

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return
		}
		reqID := newID("paytcp")
		reqLine := strings.TrimSpace(string(line))
		if reqLine == "" {
			continue
		}

		var req paymentTCPRequest
		if err := json.Unmarshal([]byte(reqLine), &req); err != nil {
			writePaymentTCPError(writer, reqID, "bad_request", "invalid json payload", http.StatusBadRequest)
			continue
		}
		if strings.TrimSpace(req.RequestID) != "" {
			reqID = strings.TrimSpace(req.RequestID)
		}
		req.TenantID = strings.TrimSpace(req.TenantID)
		req.Operation = strings.ToLower(strings.TrimSpace(req.Operation))
		if req.TenantID == "" || req.Operation == "" {
			writePaymentTCPError(writer, reqID, "bad_request", "tenant_id and operation are required", http.StatusBadRequest)
			continue
		}
		policy, err := svc.mustPaymentPolicy(ctx, req.TenantID)
		if err != nil {
			writePaymentTCPFromError(writer, reqID, req.Operation, err)
			continue
		}
		if !policy.AllowTCPInterface {
			writePaymentTCPError(writer, reqID, "policy_violation", "payment tcp interface is disabled by payment policy", http.StatusForbidden)
			continue
		}
		if policy.MaxTCPPayloadBytes > 0 && len(reqLine) > policy.MaxTCPPayloadBytes {
			writePaymentTCPError(writer, reqID, "payload_too_large", "tcp payload exceeds payment policy max_tcp_payload_bytes", http.StatusRequestEntityTooLarge)
			continue
		}
		if len(policy.AllowedTCPOperations) > 0 && !containsString(policy.AllowedTCPOperations, req.Operation) {
			writePaymentTCPError(writer, reqID, "policy_violation", "requested operation is blocked on payment tcp interface", http.StatusForbidden)
			continue
		}
		reqJWT := strings.TrimSpace(req.JWT)
		if reqJWT == "" {
			rawAuth := strings.TrimSpace(req.Authorization)
			reqJWT = strings.TrimSpace(strings.TrimPrefix(rawAuth, "Bearer "))
		}
		var claims *pkgauth.Claims
		if policy.RequireJWTOnTCP {
			if parseJWT == nil {
				writePaymentTCPError(writer, reqID, "auth_unavailable", "jwt verification is required but parser is unavailable", http.StatusFailedDependency)
				continue
			}
			if reqJWT == "" {
				writePaymentTCPError(writer, reqID, "unauthorized", "jwt is required on payment tcp interface", http.StatusUnauthorized)
				continue
			}
			parsed, parseErr := parseJWT(reqJWT)
			if parseErr != nil {
				writePaymentTCPError(writer, reqID, "unauthorized", "invalid jwt", http.StatusUnauthorized)
				continue
			}
			if !strings.EqualFold(strings.TrimSpace(parsed.TenantID), req.TenantID) {
				writePaymentTCPError(writer, reqID, "forbidden", "jwt tenant does not match request tenant", http.StatusForbidden)
				continue
			}
			if !hasAnyPermission(parsed.Permissions, []string{"*", "payment.crypto", "payment." + req.Operation}) {
				writePaymentTCPError(writer, reqID, "forbidden", "jwt lacks permission for requested payment operation", http.StatusForbidden)
				continue
			}
			claims = parsed
		}

		dispatchCtx := withPaymentChannel(ctx, paymentChannelTCP)
		dispatchCtx = withPaymentPolicy(dispatchCtx, policy)
		dispatchCtx = withPaymentJWTClaims(dispatchCtx, claims)
		result, err := svc.DispatchPaymentCrypto(dispatchCtx, PaymentCryptoDispatchRequest{
			TenantID:  req.TenantID,
			Operation: req.Operation,
			Payload:   req.Payload,
		})
		if err != nil {
			writePaymentTCPFromError(writer, reqID, req.Operation, err)
			continue
		}
		resp := paymentTCPResponse{
			OK:        true,
			RequestID: reqID,
			Operation: req.Operation,
			Result:    result,
		}
		_ = writePaymentTCPResponse(writer, resp)
		logger.Printf("payment tcp op=%s tenant=%s request_id=%s ok=true", logsanitize.Input(req.Operation), logsanitize.Input(req.TenantID), reqID)
	}
}

func hasAnyPermission(perms []string, required []string) bool {
	if len(required) == 0 {
		return true
	}
	set := map[string]struct{}{}
	for _, p := range perms {
		p = strings.TrimSpace(strings.ToLower(p))
		if p == "" {
			continue
		}
		set[p] = struct{}{}
	}
	for _, need := range required {
		need = strings.TrimSpace(strings.ToLower(need))
		if need == "" {
			continue
		}
		if _, ok := set[need]; ok {
			return true
		}
	}
	return false
}

func writePaymentTCPResponse(w *bufio.Writer, resp paymentTCPResponse) error {
	raw, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	if _, err := w.WriteString(string(raw) + "\n"); err != nil {
		return err
	}
	return w.Flush()
}

func writePaymentTCPError(w *bufio.Writer, requestID string, code string, msg string, status int) {
	resp := paymentTCPResponse{
		OK:        false,
		RequestID: requestID,
		Error: &struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Status  int    `json:"status"`
		}{
			Code:    code,
			Message: msg,
			Status:  status,
		},
	}
	_ = writePaymentTCPResponse(w, resp)
}

func writePaymentTCPFromError(w *bufio.Writer, requestID string, operation string, err error) {
	var svcErr serviceError
	if errors.As(err, &svcErr) {
		resp := paymentTCPResponse{
			OK:        false,
			RequestID: requestID,
			Operation: operation,
			Error: &struct {
				Code    string `json:"code"`
				Message string `json:"message"`
				Status  int    `json:"status"`
			}{
				Code:    svcErr.Code,
				Message: svcErr.Message,
				Status:  svcErr.HTTPStatus,
			},
		}
		_ = writePaymentTCPResponse(w, resp)
		return
	}
	writePaymentTCPError(w, requestID, "internal_error", err.Error(), http.StatusInternalServerError)
}

func parseTCPAddress(bind, port string) (string, error) {
	bind = strings.TrimSpace(bind)
	if bind == "" {
		bind = "0.0.0.0"
	}
	port = strings.TrimSpace(port)
	if port == "" {
		port = "9170"
	}
	return net.JoinHostPort(bind, port), nil
}

func mustBoolEnv(name string, defaultValue bool) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	if raw == "" {
		return defaultValue
	}
	return raw == "1" || raw == "true" || raw == "yes" || raw == "on"
}

func maybeStartPaymentTCPServer(ctx context.Context, svc *Service, logger *log.Logger, issuer string, audience string) {
	if !mustBoolEnv("PAYMENT_TCP_ENABLED", true) {
		logger.Printf("payment tcp interface disabled by env")
		return
	}
	addr, err := parseTCPAddress(envOr("PAYMENT_TCP_BIND", "0.0.0.0"), envOr("PAYMENT_TCP_PORT", "9170"))
	if err != nil {
		logger.Printf("payment tcp disabled: %v", err)
		return
	}
	parser, err := loadPaymentJWTParser(issuer, audience)
	if err != nil {
		logger.Printf("payment tcp jwt parser init warning: %v", err)
	}
	go func() {
		if err := startPaymentTCPServer(ctx, svc, addr, parser, logger); err != nil {
			logger.Printf("payment tcp server stopped: %v", err)
		}
	}()
}
