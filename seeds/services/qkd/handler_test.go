package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerETSIAndSessionEndpoints(t *testing.T) {
	h, _, _, _ := newQKDHandler(t)

	cfgReq := httptest.NewRequest(http.MethodPut, "/qkd/v1/config?tenant_id=t1", bytes.NewReader([]byte(`{
		"tenant_id":"t1",
		"qber_threshold":0.1,
		"pool_low_threshold":1
	}`)))
	cfgRR := httptest.NewRecorder()
	h.ServeHTTP(cfgRR, cfgReq)
	if cfgRR.Code != http.StatusOK {
		t.Fatalf("config status=%d body=%s", cfgRR.Code, cfgRR.Body.String())
	}

	key := base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	encPayload := map[string]interface{}{
		"tenant_id":   "t1",
		"device_id":   "dev-1",
		"device_name": "Alice",
		"role":        "alice",
		"link_status": "up",
		"keys": []map[string]interface{}{
			{"key_id": "k1", "key": key, "qber": 0.02},
		},
	}
	encRaw, _ := json.Marshal(encPayload)
	encReq := httptest.NewRequest(http.MethodPost, "/api/v1/keys/slave-1/enc_keys", bytes.NewReader(encRaw))
	encRR := httptest.NewRecorder()
	h.ServeHTTP(encRR, encReq)
	if encRR.Code != http.StatusOK {
		t.Fatalf("enc_keys status=%d body=%s", encRR.Code, encRR.Body.String())
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/api/v1/keys/slave-1/status?tenant_id=t1", nil)
	statusRR := httptest.NewRecorder()
	h.ServeHTTP(statusRR, statusReq)
	if statusRR.Code != http.StatusOK {
		t.Fatalf("status endpoint code=%d body=%s", statusRR.Code, statusRR.Body.String())
	}
	if !strings.Contains(statusRR.Body.String(), "\"available_key_count\":1") {
		t.Fatalf("unexpected status body=%s", statusRR.Body.String())
	}

	decReq := httptest.NewRequest(http.MethodPost, "/api/v1/keys/slave-1/dec_keys", bytes.NewReader([]byte(`{
		"tenant_id":"t1",
		"count":1
	}`)))
	decRR := httptest.NewRecorder()
	h.ServeHTTP(decRR, decReq)
	if decRR.Code != http.StatusOK {
		t.Fatalf("dec_keys status=%d body=%s", decRR.Code, decRR.Body.String())
	}
	if !strings.Contains(decRR.Body.String(), "\"key_id\":\"k1\"") {
		t.Fatalf("unexpected dec_keys response body=%s", decRR.Body.String())
	}

	openReq := httptest.NewRequest(http.MethodPost, "/qkd/v1/open_connect", bytes.NewReader([]byte(`{
		"tenant_id":"t1",
		"device_id":"consumer",
		"slave_sae_id":"slave-1",
		"app_id":"app1"
	}`)))
	openRR := httptest.NewRecorder()
	h.ServeHTTP(openRR, openReq)
	if openRR.Code != http.StatusOK {
		t.Fatalf("open_connect status=%d body=%s", openRR.Code, openRR.Body.String())
	}
	var openResp struct {
		Session struct {
			SessionID string `json:"session_id"`
		} `json:"session"`
	}
	_ = json.Unmarshal(openRR.Body.Bytes(), &openResp)
	if openResp.Session.SessionID == "" {
		t.Fatalf("missing session id in response=%s", openRR.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodPost, "/qkd/v1/get_key", bytes.NewReader([]byte(`{
		"tenant_id":"t1",
		"session_id":"`+openResp.Session.SessionID+`",
		"count":1
	}`)))
	getRR := httptest.NewRecorder()
	h.ServeHTTP(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("get_key status=%d body=%s", getRR.Code, getRR.Body.String())
	}

	closeReq := httptest.NewRequest(http.MethodPost, "/qkd/v1/close", bytes.NewReader([]byte(`{
		"tenant_id":"t1",
		"session_id":"`+openResp.Session.SessionID+`"
	}`)))
	closeRR := httptest.NewRecorder()
	h.ServeHTTP(closeRR, closeReq)
	if closeRR.Code != http.StatusOK {
		t.Fatalf("close status=%d body=%s", closeRR.Code, closeRR.Body.String())
	}
}

func TestHandlerDeviceAndInjectEndpoints(t *testing.T) {
	h, _, _, _ := newQKDHandler(t)
	key := base64.StdEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxzy123456"))
	encReq := httptest.NewRequest(http.MethodPost, "/api/v1/keys/slave-2/enc_keys", bytes.NewReader([]byte(`{
		"tenant_id":"t2",
		"device_id":"dev-2",
		"device_name":"Bob",
		"role":"bob",
		"link_status":"up",
		"keys":[{"key_id":"k2","key":"`+key+`","qber":0.01}]
	}`)))
	encRR := httptest.NewRecorder()
	h.ServeHTTP(encRR, encReq)
	if encRR.Code != http.StatusOK {
		t.Fatalf("enc_keys status=%d body=%s", encRR.Code, encRR.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/qkd/v1/devices?tenant_id=t2", nil)
	listRR := httptest.NewRecorder()
	h.ServeHTTP(listRR, listReq)
	if listRR.Code != http.StatusOK {
		t.Fatalf("list devices status=%d body=%s", listRR.Code, listRR.Body.String())
	}
	if !strings.Contains(listRR.Body.String(), "\"id\":\"dev-2\"") {
		t.Fatalf("unexpected devices body=%s", listRR.Body.String())
	}

	deviceReq := httptest.NewRequest(http.MethodGet, "/qkd/v1/devices/dev-2/status?tenant_id=t2", nil)
	deviceRR := httptest.NewRecorder()
	h.ServeHTTP(deviceRR, deviceReq)
	if deviceRR.Code != http.StatusOK {
		t.Fatalf("device status=%d body=%s", deviceRR.Code, deviceRR.Body.String())
	}

	injectReq := httptest.NewRequest(http.MethodPost, "/qkd/v1/keys/k2/inject", bytes.NewReader([]byte(`{
		"tenant_id":"t2",
		"name":"qkd-injected",
		"purpose":"encrypt",
		"consume":true
	}`)))
	injectRR := httptest.NewRecorder()
	h.ServeHTTP(injectRR, injectReq)
	if injectRR.Code != http.StatusOK {
		t.Fatalf("inject status=%d body=%s", injectRR.Code, injectRR.Body.String())
	}
	if !strings.Contains(injectRR.Body.String(), "\"status\":\"injected\"") {
		t.Fatalf("unexpected inject response=%s", injectRR.Body.String())
	}
}
