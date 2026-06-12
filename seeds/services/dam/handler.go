package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vecta-kms/pkg/tenantcheck"
)

// Handler is the HTTP handler for the DAM service.
type Handler struct {
	store     Store
	publisher EventPublisher
	mux       *http.ServeMux
}

// NewHandler creates a new Handler.
func NewHandler(store Store, publisher EventPublisher) *Handler {
	h := &Handler{store: store, publisher: publisher}
	h.mux = h.routes()
	return h
}

// publishAudit publishes an audit event to NATS. Errors are silently dropped.
func (h *Handler) publishAudit(ctx context.Context, subject string, tenantID string, data map[string]interface{}) {
	if h.publisher == nil {
		return
	}
	raw, err := json.Marshal(map[string]interface{}{
		"tenant_id": tenantID,
		"service":   "dam",
		"action":    subject,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"data":      data,
	})
	if err != nil {
		return
	}
	_ = h.publisher.Publish(ctx, subject, raw)
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.handleHealth)

	mux.HandleFunc("POST /activity/events", h.handleIngestEvent)
	mux.HandleFunc("GET /activity/events", h.handleQueryEvents)
	mux.HandleFunc("GET /activity/stats", h.handleGetStats)
	mux.HandleFunc("GET /activity/actors", h.handleListActors)
	mux.HandleFunc("GET /activity/sources", h.handleListSources)

	return mux
}

func (h *Handler) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok"})
}

func (h *Handler) handleIngestEvent(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req IngestEventRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	if strings.TrimSpace(req.TenantID) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required", reqID, "")
		return
	}
	if strings.TrimSpace(req.EventType) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "event_type is required", reqID, req.TenantID)
		return
	}
	if strings.TrimSpace(req.RiskLevel) == "" {
		req.RiskLevel = "low"
	}
	if req.DataLabels == nil {
		req.DataLabels = []string{}
	}
	if req.Metadata == nil {
		req.Metadata = map[string]interface{}{}
	}
	occurredAt := req.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}

	now := time.Now().UTC()
	event := ActivityEvent{
		ID:         newDAMID("evt"),
		TenantID:   strings.TrimSpace(req.TenantID),
		EventType:  strings.TrimSpace(req.EventType),
		Source:     strings.TrimSpace(req.Source),
		Actor:      strings.TrimSpace(req.Actor),
		ActorIP:    strings.TrimSpace(req.ActorIP),
		Query:      strings.TrimSpace(req.Query),
		RowsAffect: req.RowsAffect,
		DataLabels: req.DataLabels,
		RiskLevel:  strings.TrimSpace(req.RiskLevel),
		Allowed:    req.Allowed,
		Reason:     strings.TrimSpace(req.Reason),
		Metadata:   req.Metadata,
		OccurredAt: occurredAt,
		CreatedAt:  now,
	}

	saved, err := h.store.IngestEvent(r.Context(), event)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "ingest_event_failed", err.Error(), reqID, req.TenantID)
		return
	}
	// Publish audit event for critical or high risk ingested events.
	riskLower := strings.ToLower(saved.RiskLevel)
	if riskLower == "critical" || riskLower == "high" {
		h.publishAudit(r.Context(), "audit.dam.critical_event", saved.TenantID, map[string]interface{}{
			"event_id":    saved.ID,
			"event_type":  saved.EventType,
			"risk_level":  saved.RiskLevel,
			"source":      saved.Source,
			"actor":       saved.Actor,
			"occurred_at": saved.OccurredAt.Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"event": saved, "request_id": reqID})
}

func (h *Handler) handleQueryEvents(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := firstNonEmpty(r.URL.Query().Get("tenant_id"), tenantFromRequest(r))
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-ID header or tenant_id query param required", reqID, "")
		return
	}

	limit := 50
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if n, err := strconv.Atoi(lStr); err == nil && n > 0 {
			limit = n
		}
	}
	offset := 0
	if oStr := r.URL.Query().Get("offset"); oStr != "" {
		if n, err := strconv.Atoi(oStr); err == nil && n >= 0 {
			offset = n
		}
	}

	var since time.Time
	if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
		if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			since = t
		}
	}

	q := ActivityQuery{
		TenantID:  tenantID,
		EventType: r.URL.Query().Get("event_type"),
		Source:    r.URL.Query().Get("source"),
		Actor:     r.URL.Query().Get("actor"),
		RiskLevel: r.URL.Query().Get("risk_level"),
		Limit:     limit,
		Offset:    offset,
		Since:     since,
	}

	items, err := h.store.QueryEvents(r.Context(), q)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query_events_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetStats(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := firstNonEmpty(r.URL.Query().Get("tenant_id"), tenantFromRequest(r))
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-ID header or tenant_id query param required", reqID, "")
		return
	}
	stats, err := h.store.GetStats(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "get_stats_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"stats": stats, "request_id": reqID})
}

func (h *Handler) handleListActors(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := firstNonEmpty(r.URL.Query().Get("tenant_id"), tenantFromRequest(r))
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-ID header or tenant_id query param required", reqID, "")
		return
	}
	actors, err := h.store.ListActors(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_actors_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": actors, "request_id": reqID})
}

func (h *Handler) handleListSources(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := firstNonEmpty(r.URL.Query().Get("tenant_id"), tenantFromRequest(r))
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-ID header or tenant_id query param required", reqID, "")
		return
	}
	sources, err := h.store.ListSources(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_sources_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": sources, "request_id": reqID})
}

// --- shared HTTP helpers ---

func requestID(r *http.Request) string {
	id := r.Header.Get("X-Request-ID")
	if strings.TrimSpace(id) == "" {
		id = newDAMID("req")
	}
	return id
}

func tenantFromRequest(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
}

func mustTenant(r *http.Request, w http.ResponseWriter, reqID string) string {
	tenantID := firstNonEmpty(tenantFromRequest(r), strings.TrimSpace(r.URL.Query().Get("tenant_id")))
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-ID header or tenant_id query param required", reqID, "")
		return ""
	}
	// A01 fix: verify the request tenant matches the authenticated JWT tenant
	if err := tenantcheck.Enforce(r, tenantID); err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", "tenant_id does not match authenticated token", reqID, tenantID)
		return ""
	}
	return tenantID
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, payload map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeErr(w http.ResponseWriter, status int, code, message, requestID, tenantID string) {
	writeJSON(w, status, map[string]interface{}{
		"error":      code,
		"message":    message,
		"request_id": requestID,
		"tenant_id":  tenantID,
	})
}

func decodeJSON(r *http.Request, out interface{}) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		return err
	}
	return json.NewDecoder(bytes.NewReader(body)).Decode(out)
}
