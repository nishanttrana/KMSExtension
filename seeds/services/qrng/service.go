package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// EventPublisher publishes audit events to NATS JetStream.
type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

// ── In-memory entropy pool ───────────────────────────────────

// entropyPool is a 512-byte ring buffer seeded by QRNG samples.
// Draw output is SHA-256 counter mode over pool state XOR'd with crypto/rand
// for defense-in-depth (even if QRNG is compromised, output is still safe).
type entropyPool struct {
	mu  sync.Mutex
	buf []byte
	pos int
}

func newEntropyPool() *entropyPool {
	buf := make([]byte, 512)
	_, _ = pkgcrypto.Reader.Read(buf) // seed with OS randomness
	return &entropyPool{buf: buf}
}

// absorb XOR-folds new QRNG entropy into the pool state.
func (p *entropyPool) absorb(raw []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, b := range raw {
		p.buf[(p.pos+i)%len(p.buf)] ^= b
	}
	p.pos = (p.pos + len(raw)) % len(p.buf)
}

// draw extracts n bytes using SHA-256 counter mode over pool state,
// mixed with crypto/rand for defense-in-depth.
func (p *entropyPool) draw(n int) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]byte, n)
	osRand := make([]byte, n)
	if _, err := pkgcrypto.Reader.Read(osRand); err != nil {
		return nil, err
	}
	counter := 0
	for i := 0; i < n; {
		h := sha256.New()
		h.Write(p.buf)
		h.Write([]byte{byte(counter), byte(counter >> 8)})
		block := h.Sum(nil)
		for j := 0; j < len(block) && i < n; j++ {
			out[i] = block[j] ^ osRand[i]
			i++
		}
		counter++
	}
	return out, nil
}

// ── Service ──────────────────────────────────────────────────

type Service struct {
	store  Store
	pool   *entropyPool
	events EventPublisher
	now    func() time.Time
}

func NewService(store Store, events EventPublisher) *Service {
	return &Service{
		store:  store,
		pool:   newEntropyPool(),
		events: events,
		now:    func() time.Time { return time.Now().UTC() },
	}
}

// ── Source Management ────────────────────────────────────────

func (s *Service) RegisterSource(ctx context.Context, req RegisterSourceRequest) (QRNGSource, error) {
	if strings.TrimSpace(req.TenantID) == "" {
		return QRNGSource{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	if strings.TrimSpace(req.Name) == "" {
		return QRNGSource{}, newServiceError(http.StatusBadRequest, "bad_request", "name is required")
	}
	now := s.now()
	src := QRNGSource{
		ID:            newID("qrng"),
		TenantID:      strings.TrimSpace(req.TenantID),
		Name:          strings.TrimSpace(req.Name),
		Vendor:        normalizeVendor(req.Vendor),
		Endpoint:      strings.TrimSpace(req.Endpoint),
		Mode:          normalizeSourceMode(req.Mode),
		Status:        SourceStatusActive,
		MinEntropyBPB: req.MinEntropyBPB,
		PullIntervalS: req.PullIntervalS,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if src.MinEntropyBPB <= 0 || src.MinEntropyBPB > 8 {
		src.MinEntropyBPB = MinAcceptableEntropyBPB
	}
	if src.PullIntervalS <= 0 {
		src.PullIntervalS = 60
	}
	if err := s.store.CreateSource(ctx, src); err != nil {
		return QRNGSource{}, newServiceError(http.StatusInternalServerError, "store_error", err.Error())
	}
	_ = s.publishAudit(ctx, "audit.qrng.source_registered", src.TenantID, map[string]interface{}{
		"source_id": src.ID, "vendor": src.Vendor, "mode": src.Mode,
	})
	// Strip auth token from response
	src.AuthToken = ""
	return src, nil
}

func (s *Service) UpdateSource(ctx context.Context, tenantID, id string, req RegisterSourceRequest) (QRNGSource, error) {
	existing, err := s.store.GetSource(ctx, tenantID, id)
	if err != nil {
		return QRNGSource{}, newServiceError(http.StatusNotFound, "not_found", "source not found")
	}
	if strings.TrimSpace(req.Name) != "" {
		existing.Name = strings.TrimSpace(req.Name)
	}
	if strings.TrimSpace(req.Vendor) != "" {
		existing.Vendor = normalizeVendor(req.Vendor)
	}
	if strings.TrimSpace(req.Endpoint) != "" {
		existing.Endpoint = strings.TrimSpace(req.Endpoint)
	}
	if strings.TrimSpace(req.AuthToken) != "" {
		existing.AuthToken = strings.TrimSpace(req.AuthToken)
	}
	if strings.TrimSpace(req.Mode) != "" {
		existing.Mode = normalizeSourceMode(req.Mode)
	}
	if req.MinEntropyBPB > 0 && req.MinEntropyBPB <= 8 {
		existing.MinEntropyBPB = req.MinEntropyBPB
	}
	if req.PullIntervalS > 0 {
		existing.PullIntervalS = req.PullIntervalS
	}
	existing.UpdatedAt = s.now()
	if err := s.store.UpdateSource(ctx, existing); err != nil {
		return QRNGSource{}, newServiceError(http.StatusInternalServerError, "store_error", err.Error())
	}
	_ = s.publishAudit(ctx, "audit.qrng.source_updated", tenantID, map[string]interface{}{
		"source_id": existing.ID, "name": existing.Name, "vendor": existing.Vendor, "mode": existing.Mode,
	})
	existing.AuthToken = ""
	return existing, nil
}

func (s *Service) ListSources(ctx context.Context, tenantID string) ([]QRNGSource, error) {
	items, err := s.store.ListSources(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	// Strip auth tokens
	for i := range items {
		items[i].AuthToken = ""
	}
	return items, nil
}

func (s *Service) GetSource(ctx context.Context, tenantID, id string) (QRNGSource, error) {
	src, err := s.store.GetSource(ctx, tenantID, id)
	if err != nil {
		return QRNGSource{}, newServiceError(http.StatusNotFound, "not_found", "source not found")
	}
	src.AuthToken = ""
	return src, nil
}

func (s *Service) DeleteSource(ctx context.Context, tenantID, id string) error {
	if err := s.store.DeleteSource(ctx, tenantID, id); err != nil {
		return newServiceError(http.StatusInternalServerError, "store_error", err.Error())
	}
	_ = s.publishAudit(ctx, "audit.qrng.source_deleted", tenantID, map[string]interface{}{
		"source_id": id,
	})
	return nil
}

// ── Entropy Ingestion ────────────────────────────────────────

func (s *Service) IngestEntropy(ctx context.Context, req IngestRequest) (IngestResponse, error) {
	tenantID := strings.TrimSpace(req.TenantID)
	sourceID := strings.TrimSpace(req.SourceID)
	if tenantID == "" {
		return IngestResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	if sourceID == "" {
		return IngestResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "source_id is required")
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.EntropyB64))
	if err != nil {
		return IngestResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "entropy must be base64-encoded")
	}
	if len(raw) < MinIngestBytes || len(raw) > MaxIngestBytes {
		return IngestResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "entropy must be 32-4096 bytes")
	}

	// Get source to check min entropy threshold
	src, err := s.store.GetSource(ctx, tenantID, sourceID)
	if err != nil {
		return IngestResponse{}, newServiceError(http.StatusNotFound, "not_found", "source not found")
	}
	minEntropy := src.MinEntropyBPB
	if minEntropy <= 0 {
		minEntropy = MinAcceptableEntropyBPB
	}

	// Run NIST SP 800-90B quality tests
	qr, err := validateQuality(raw, minEntropy)
	if err != nil {
		return IngestResponse{}, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
	}

	now := s.now()
	sampleID := newID("smp")
	sampleHash := hex.EncodeToString(sha256Sum(raw))

	if !qr.AllPassed() {
		reason := "quality check failed:"
		if !qr.EntropyOK {
			reason += " entropy too low"
		}
		if !qr.BiasOK {
			reason += " excessive bias"
		}
		if !qr.AdaptiveOK {
			reason += " adaptive proportion test failed"
		}
		if !qr.RepeatOK {
			reason += " repetition count test failed"
		}

		// Log health failure
		_ = s.store.InsertHealthEvent(ctx, QRNGHealthEvent{
			ID: newID("hlth"), TenantID: tenantID, SourceID: sourceID,
			CheckType: "ingest_quality", Result: "fail", EntropyBPB: qr.Measured,
			Detail:    map[string]interface{}{"quality": qr, "sample_hash": sampleHash},
			CreatedAt: now,
		})
		_ = s.store.UpdateSourceStatus(ctx, tenantID, sourceID, SourceStatusError, reason)

		// Still record the rejected sample for audit
		_ = s.store.InsertSample(ctx, QRNGPoolSample{
			ID: sampleID, TenantID: tenantID, SourceID: sourceID,
			SampleHash: sampleHash, ByteCount: len(raw),
			EntropyBPB: qr.Measured, BiasScore: qr.Bias,
			PassedHealth: false, CreatedAt: now,
		})

		zeroize(raw)
		return IngestResponse{
			SampleID: sampleID, ByteCount: len(raw),
			EntropyBPB: qr.Measured, Accepted: false, RejectReason: reason,
		}, nil
	}

	// Quality passed — absorb into pool
	s.pool.absorb(raw)

	_ = s.store.InsertSample(ctx, QRNGPoolSample{
		ID: sampleID, TenantID: tenantID, SourceID: sourceID,
		SampleHash: sampleHash, ByteCount: len(raw),
		EntropyBPB: qr.Measured, BiasScore: qr.Bias,
		PassedHealth: true, CreatedAt: now,
	})
	_ = s.store.UpdateSourceStatus(ctx, tenantID, sourceID, SourceStatusActive, "")
	_ = s.store.InsertHealthEvent(ctx, QRNGHealthEvent{
		ID: newID("hlth"), TenantID: tenantID, SourceID: sourceID,
		CheckType: "ingest_quality", Result: "pass", EntropyBPB: qr.Measured,
		Detail:    map[string]interface{}{"quality": qr},
		CreatedAt: now,
	})

	_ = s.publishAudit(ctx, "audit.qrng.entropy_ingested", tenantID, map[string]interface{}{
		"source_id": sourceID, "byte_count": len(raw), "entropy_bpb": qr.Measured,
		"sample_hash": sampleHash,
	})

	zeroize(raw)
	return IngestResponse{
		SampleID: sampleID, ByteCount: len(raw),
		EntropyBPB: qr.Measured, Accepted: true,
	}, nil
}

// ── Entropy Draw (called by KeyCore) ─────────────────────────

func (s *Service) DrawEntropy(ctx context.Context, req DrawRequest) (DrawResponse, error) {
	tenantID := strings.TrimSpace(req.TenantID)
	if tenantID == "" {
		return DrawResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	n := req.Bytes
	if n <= 0 {
		n = 32
	}
	if n > MaxIngestBytes {
		return DrawResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "max 4096 bytes per draw")
	}

	raw, err := s.pool.draw(n)
	if err != nil {
		return DrawResponse{}, newServiceError(http.StatusInternalServerError, "pool_error", err.Error())
	}

	b64 := base64.StdEncoding.EncodeToString(raw)
	zeroize(raw)

	_ = s.publishAudit(ctx, "audit.qrng.entropy_drawn", tenantID, map[string]interface{}{
		"byte_count": n,
		"source":     "pool",
	})
	return DrawResponse{
		EntropyB64: b64,
		ByteCount:  n,
		SourceID:   "pool",
		EntropyBPB: 8.0, // post-conditioning, SHA-256 output
	}, nil
}

// ── Pool Status ──────────────────────────────────────────────

func (s *Service) GetPoolStatus(ctx context.Context, tenantID string) (QRNGPoolStatus, error) {
	return s.store.PoolStatus(ctx, tenantID)
}

func (s *Service) GetOverview(ctx context.Context, tenantID string) (QRNGOverview, error) {
	pool, err := s.store.PoolStatus(ctx, tenantID)
	if err != nil {
		return QRNGOverview{}, err
	}
	sources, err := s.store.ListSources(ctx, tenantID)
	if err != nil {
		return QRNGOverview{}, err
	}
	for i := range sources {
		sources[i].AuthToken = ""
	}
	return QRNGOverview{TenantID: tenantID, Pool: pool, Sources: sources}, nil
}

func (s *Service) ListHealthEvents(ctx context.Context, tenantID string, limit int) ([]QRNGHealthEvent, error) {
	return s.store.ListHealthEvents(ctx, tenantID, limit)
}

// ── Helpers ──────────────────────────────────────────────────

func sha256Sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (s *Service) publishAudit(ctx context.Context, subject string, tenantID string, meta map[string]interface{}) error {
	if s.events == nil {
		return nil
	}
	payload := map[string]interface{}{
		"tenant_id":  tenantID,
		"service":    "qrng",
		"subject":    subject,
		"meta":       meta,
		"timestamp":  s.now().Format(time.RFC3339Nano),
		"request_id": newID("evt"),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return s.events.Publish(ctx, subject, data)
}
