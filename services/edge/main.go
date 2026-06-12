// Edge/IoT device registry — the first KMS Extension service.
//
// Ported out of Vecta KMS keycore (removed there in the product trim). Keeps
// the same REST shape so the original dashboard tab can be revived against
// this service. Key assignments are validated against the core KMS through
// pkg/kmsclient; this service stores no key material.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"vecta-kms-extension/pkg/kmsclient"
)

type EdgeDevice struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id"`
	Name          string     `json:"name"`
	DeviceType    string     `json:"device_type"`
	Platform      string     `json:"platform"`
	HWFingerprint string     `json:"hw_fingerprint"`
	AssignedKeys  []string   `json:"assigned_keys"`
	LastSeenAt    *time.Time `json:"last_seen_at,omitempty"`
	Status        string     `json:"status"`
	CreatedBy     string     `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// memStore is the development store; migrations/001_edge_devices.sql carries
// the PostgreSQL schema for the production store to come.
type memStore struct {
	mu      sync.RWMutex
	devices map[string]EdgeDevice
}

func newMemStore() *memStore { return &memStore{devices: map[string]EdgeDevice{}} }

func (s *memStore) list(tenantID string) []EdgeDevice {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []EdgeDevice{}
	for _, d := range s.devices {
		if d.TenantID == tenantID {
			out = append(out, d)
		}
	}
	return out
}

func (s *memStore) create(d EdgeDevice) EdgeDevice {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices[d.ID] = d
	return d
}

func (s *memStore) updateStatus(tenantID, id, status string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok || d.TenantID != tenantID {
		return false
	}
	now := time.Now().UTC()
	d.Status = status
	d.LastSeenAt = &now
	d.UpdatedAt = now
	s.devices[id] = d
	return true
}

func (s *memStore) delete(tenantID, id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok || d.TenantID != tenantID {
		return false
	}
	delete(s.devices, id)
	return true
}

type server struct {
	store *memStore
	kms   *kmsclient.Client
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func tenantFrom(r *http.Request) string { return strings.TrimSpace(r.Header.Get("X-Tenant-ID")) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}

func (s *server) handleList(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFrom(r)
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-ID header is required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": s.store.list(tenantID)})
}

func (s *server) handleCreate(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFrom(r)
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-ID header is required")
		return
	}
	var req struct {
		Name          string   `json:"name"`
		DeviceType    string   `json:"device_type"`
		Platform      string   `json:"platform"`
		HWFingerprint string   `json:"hw_fingerprint"`
		AssignedKeys  []string `json:"assigned_keys"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "name is required")
		return
	}
	if req.DeviceType == "" {
		req.DeviceType = "iot"
	}
	// Assigned keys must exist in the core KMS for this tenant.
	if s.kms != nil {
		for _, keyID := range req.AssignedKeys {
			ok, err := s.kms.KeyExists(r.Context(), keyID)
			if err != nil {
				writeErr(w, http.StatusBadGateway, "kms_unreachable", err.Error())
				return
			}
			if !ok {
				writeErr(w, http.StatusBadRequest, "unknown_key", "key not found in KMS: "+keyID)
				return
			}
		}
	}
	now := time.Now().UTC()
	d := EdgeDevice{
		ID:            newID("ed"),
		TenantID:      tenantID,
		Name:          strings.TrimSpace(req.Name),
		DeviceType:    req.DeviceType,
		Platform:      req.Platform,
		HWFingerprint: req.HWFingerprint,
		AssignedKeys:  req.AssignedKeys,
		Status:        "registered",
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	writeJSON(w, http.StatusCreated, map[string]any{"device": s.store.create(d)})
}

func (s *server) handleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFrom(r)
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-ID header is required")
		return
	}
	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	switch req.Status {
	case "registered", "active", "revoked":
	default:
		writeErr(w, http.StatusBadRequest, "bad_request", "status must be registered, active or revoked")
		return
	}
	if !s.store.updateStatus(tenantID, r.PathValue("id"), req.Status) {
		writeErr(w, http.StatusNotFound, "not_found", "device not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *server) handleDelete(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFrom(r)
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-ID header is required")
		return
	}
	if !s.store.delete(tenantID, r.PathValue("id")) {
		writeErr(w, http.StatusNotFound, "not_found", "device not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func main() {
	addr := os.Getenv("EDGE_LISTEN_ADDR")
	if addr == "" {
		addr = ":9410"
	}
	var kms *kmsclient.Client
	if base := os.Getenv("KMS_BASE_URL"); base != "" {
		kms = kmsclient.New(base, os.Getenv("KMS_SERVICE_TOKEN"), os.Getenv("KMS_TENANT_ID"))
	} else {
		log.Println("WARN: KMS_BASE_URL not set; key assignment validation disabled")
	}
	s := &server{store: newMemStore(), kms: kms}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /edge/devices", s.handleList)
	mux.HandleFunc("POST /edge/devices", s.handleCreate)
	mux.HandleFunc("PATCH /edge/devices/{id}/status", s.handleUpdateStatus)
	mux.HandleFunc("DELETE /edge/devices/{id}", s.handleDelete)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("kms-extension edge service listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
