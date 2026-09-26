package featureforge

import (
	"encoding/json"
	"net/http"
)

// Handler exposes the forge over HTTP, matching the platform's /svc/<service>
// proxying convention. Routes:
//
//	GET  /svc/featureforge/catalog            -> list allow-listed actions
//	POST /svc/featureforge/intents            -> submit an intent (runs to staging)
//	GET  /svc/featureforge/intents/{id}       -> fetch intent state
//	POST /svc/featureforge/intents/{id}/promote -> attempt prod promotion (gated)
type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

func (h *Handler) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /svc/featureforge/catalog", h.getCatalog)
	mux.HandleFunc("POST /svc/featureforge/intents", h.postIntent)
	mux.HandleFunc("GET /svc/featureforge/intents/{id}", h.getIntent)
	mux.HandleFunc("POST /svc/featureforge/intents/{id}/promote", h.promote)
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *Handler) getCatalog(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, h.svc.Catalog())
}

type submitReq struct {
	TenantID string `json:"tenant_id"`
	Actor    string `json:"actor"`
	Text     string `json:"text"`
}

func (h *Handler) postIntent(w http.ResponseWriter, r *http.Request) {
	var req submitReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	in, err := h.svc.Submit(req.TenantID, req.Actor, req.Text)
	code := http.StatusOK
	if err != nil {
		// Rejections are a normal, expected outcome — return the intent so the
		// caller can read the guardrail trail, with 422.
		code = http.StatusUnprocessableEntity
	}
	writeJSON(w, code, in)
}

func (h *Handler) getIntent(w http.ResponseWriter, r *http.Request) {
	in, ok := h.svc.Get(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, in)
}

func (h *Handler) promote(w http.ResponseWriter, r *http.Request) {
	in, err := h.svc.PromoteToProd(r.PathValue("id"))
	if in == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	code := http.StatusOK
	if err != nil {
		code = http.StatusUnprocessableEntity
	}
	writeJSON(w, code, in)
}
