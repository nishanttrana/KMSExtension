package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerDKGAndKeysFlow(t *testing.T) {
	h, _, _ := newMPCHandler(t)
	tenantID := "tenant-h1"

	initReq := httptest.NewRequest(http.MethodPost, "/mpc/dkg/initiate", strings.NewReader(`{
		"tenant_id":"`+tenantID+`",
		"key_name":"wallet",
		"algorithm":"ECDSA_SECP256K1",
		"threshold":2,
		"participants":["node-1","node-2","node-3"]
	}`))
	initReq.Header.Set("Content-Type", "application/json")
	initRR := httptest.NewRecorder()
	h.ServeHTTP(initRR, initReq)
	if initRR.Code != http.StatusAccepted {
		t.Fatalf("init dkg status=%d body=%s", initRR.Code, initRR.Body.String())
	}

	var initPayload map[string]interface{}
	if err := json.Unmarshal(initRR.Body.Bytes(), &initPayload); err != nil {
		t.Fatalf("decode dkg init payload: %v", err)
	}
	ceremony, _ := initPayload["ceremony"].(map[string]interface{})
	dkgID, _ := ceremony["id"].(string)
	keyID, _ := ceremony["key_id"].(string)
	if dkgID == "" || keyID == "" {
		t.Fatalf("missing dkg/key ids")
	}

	for _, party := range []string{"node-1", "node-2"} {
		req := httptest.NewRequest(http.MethodPost, "/mpc/dkg/"+dkgID+"/contribute", strings.NewReader(`{"tenant_id":"`+tenantID+`","party_id":"`+party+`"}`))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("dkg contribute(%s) status=%d body=%s", party, rr.Code, rr.Body.String())
		}
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/mpc/dkg/"+dkgID+"/status?tenant_id="+tenantID, nil)
	statusRR := httptest.NewRecorder()
	h.ServeHTTP(statusRR, statusReq)
	if statusRR.Code != http.StatusOK {
		t.Fatalf("dkg status status=%d body=%s", statusRR.Code, statusRR.Body.String())
	}

	keysReq := httptest.NewRequest(http.MethodGet, "/mpc/keys?tenant_id="+tenantID, nil)
	keysRR := httptest.NewRecorder()
	h.ServeHTTP(keysRR, keysReq)
	if keysRR.Code != http.StatusOK {
		t.Fatalf("keys status=%d body=%s", keysRR.Code, keysRR.Body.String())
	}

	keyReq := httptest.NewRequest(http.MethodGet, "/mpc/keys/"+keyID+"?tenant_id="+tenantID, nil)
	keyRR := httptest.NewRecorder()
	h.ServeHTTP(keyRR, keyReq)
	if keyRR.Code != http.StatusOK {
		t.Fatalf("key status=%d body=%s", keyRR.Code, keyRR.Body.String())
	}
}

func TestHandlerSignDecryptShareFlow(t *testing.T) {
	h, _, _ := newMPCHandler(t)
	tenantID := "tenant-h2"

	dkgInit := httptest.NewRequest(http.MethodPost, "/mpc/dkg/initiate", strings.NewReader(`{
		"tenant_id":"`+tenantID+`",
		"threshold":2,
		"participants":["node-1","node-2","node-3"]
	}`))
	dkgInit.Header.Set("Content-Type", "application/json")
	dkgInitRR := httptest.NewRecorder()
	h.ServeHTTP(dkgInitRR, dkgInit)
	if dkgInitRR.Code != http.StatusAccepted {
		t.Fatalf("dkg init status=%d body=%s", dkgInitRR.Code, dkgInitRR.Body.String())
	}
	var dkgPayload map[string]interface{}
	_ = json.Unmarshal(dkgInitRR.Body.Bytes(), &dkgPayload)
	dkg := dkgPayload["ceremony"].(map[string]interface{})
	dkgID, _ := dkg["id"].(string)
	keyID, _ := dkg["key_id"].(string)

	for _, party := range []string{"node-1", "node-2"} {
		req := httptest.NewRequest(http.MethodPost, "/mpc/dkg/"+dkgID+"/contribute", strings.NewReader(`{"tenant_id":"`+tenantID+`","party_id":"`+party+`"}`))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("dkg contribute status=%d body=%s", rr.Code, rr.Body.String())
		}
	}

	signInitReq := httptest.NewRequest(http.MethodPost, "/mpc/sign/initiate", strings.NewReader(`{
		"tenant_id":"`+tenantID+`",
		"key_id":"`+keyID+`",
		"message_hash":"aabbcc"
	}`))
	signInitReq.Header.Set("Content-Type", "application/json")
	signInitRR := httptest.NewRecorder()
	h.ServeHTTP(signInitRR, signInitReq)
	if signInitRR.Code != http.StatusAccepted {
		t.Fatalf("sign init status=%d body=%s", signInitRR.Code, signInitRR.Body.String())
	}
	var signPayload map[string]interface{}
	_ = json.Unmarshal(signInitRR.Body.Bytes(), &signPayload)
	signID, _ := signPayload["ceremony"].(map[string]interface{})["id"].(string)
	for _, party := range []string{"node-1", "node-2"} {
		req := httptest.NewRequest(http.MethodPost, "/mpc/sign/"+signID+"/contribute", strings.NewReader(`{"tenant_id":"`+tenantID+`","party_id":"`+party+`"}`))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("sign contribute status=%d body=%s", rr.Code, rr.Body.String())
		}
	}

	signResultReq := httptest.NewRequest(http.MethodGet, "/mpc/sign/"+signID+"/result?tenant_id="+tenantID, nil)
	signResultRR := httptest.NewRecorder()
	h.ServeHTTP(signResultRR, signResultReq)
	if signResultRR.Code != http.StatusOK {
		t.Fatalf("sign result status=%d body=%s", signResultRR.Code, signResultRR.Body.String())
	}

	decInitReq := httptest.NewRequest(http.MethodPost, "/mpc/decrypt/initiate", strings.NewReader(`{
		"tenant_id":"`+tenantID+`",
		"key_id":"`+keyID+`",
		"ciphertext":"7b2278223a2279227d",
		"participants":["node-1","node-2"]
	}`))
	decInitReq.Header.Set("Content-Type", "application/json")
	decInitRR := httptest.NewRecorder()
	h.ServeHTTP(decInitRR, decInitReq)
	if decInitRR.Code != http.StatusAccepted {
		t.Fatalf("decrypt init status=%d body=%s", decInitRR.Code, decInitRR.Body.String())
	}
	var decPayload map[string]interface{}
	_ = json.Unmarshal(decInitRR.Body.Bytes(), &decPayload)
	decID, _ := decPayload["ceremony"].(map[string]interface{})["id"].(string)
	for _, party := range []string{"node-1", "node-2"} {
		req := httptest.NewRequest(http.MethodPost, "/mpc/decrypt/"+decID+"/contribute", strings.NewReader(`{"tenant_id":"`+tenantID+`","party_id":"`+party+`"}`))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("decrypt contribute status=%d body=%s", rr.Code, rr.Body.String())
		}
	}
	decResultReq := httptest.NewRequest(http.MethodGet, "/mpc/decrypt/"+decID+"/result?tenant_id="+tenantID, nil)
	decResultRR := httptest.NewRecorder()
	h.ServeHTTP(decResultRR, decResultReq)
	if decResultRR.Code != http.StatusOK {
		t.Fatalf("decrypt result status=%d body=%s", decResultRR.Code, decResultRR.Body.String())
	}

	sharesReq := httptest.NewRequest(http.MethodGet, "/mpc/shares?tenant_id="+tenantID+"&node_id=node-1", nil)
	sharesRR := httptest.NewRecorder()
	h.ServeHTTP(sharesRR, sharesReq)
	if sharesRR.Code != http.StatusOK {
		t.Fatalf("shares status=%d body=%s", sharesRR.Code, sharesRR.Body.String())
	}

	refreshReq := httptest.NewRequest(http.MethodPost, "/mpc/shares/"+keyID+"/refresh?tenant_id="+tenantID, strings.NewReader(`{"actor":"alice"}`))
	refreshReq.Header.Set("Content-Type", "application/json")
	refreshRR := httptest.NewRecorder()
	h.ServeHTTP(refreshRR, refreshReq)
	if refreshRR.Code != http.StatusOK {
		t.Fatalf("refresh status=%d body=%s", refreshRR.Code, refreshRR.Body.String())
	}

	backupReq := httptest.NewRequest(http.MethodPost, "/mpc/shares/backup", strings.NewReader(`{
		"tenant_id":"`+tenantID+`",
		"key_id":"`+keyID+`",
		"node_id":"node-1",
		"destination":"dr-site"
	}`))
	backupReq.Header.Set("Content-Type", "application/json")
	backupRR := httptest.NewRecorder()
	h.ServeHTTP(backupRR, backupReq)
	if backupRR.Code != http.StatusOK {
		t.Fatalf("backup status=%d body=%s", backupRR.Code, backupRR.Body.String())
	}

	rotateReq := httptest.NewRequest(http.MethodPost, "/mpc/keys/"+keyID+"/rotate?tenant_id="+tenantID, strings.NewReader(`{"actor":"alice"}`))
	rotateReq.Header.Set("Content-Type", "application/json")
	rotateRR := httptest.NewRecorder()
	h.ServeHTTP(rotateRR, rotateReq)
	if rotateRR.Code != http.StatusOK {
		t.Fatalf("rotate status=%d body=%s", rotateRR.Code, rotateRR.Body.String())
	}
}
