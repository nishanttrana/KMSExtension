package main

import (
	"context"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"
)

func TestGRPCServerMethods(t *testing.T) {
	provider, err := NewProvider(testProviderConfig(ProviderSoftware))
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	defer provider.Close() //nolint:errcheck

	svc := NewService(provider)
	server := &vaultGRPCServer{svc: svc}

	wrapReq, _ := structpb.NewStruct(map[string]interface{}{"plaintext_dek_b64": b64([]byte("dek-1"))})
	wrapRespAny, err := server.WrapKey(context.Background(), wrapReq)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	wrapResp := wrapRespAny.AsMap()
	wrappedB64 := parseStringField(wrapResp, "wrapped_dek_b64")
	ivB64 := parseStringField(wrapResp, "wrapped_dek_iv_b64")
	if wrappedB64 == "" || ivB64 == "" {
		t.Fatalf("missing wrap response fields: %+v", wrapResp)
	}

	unwrapReq, _ := structpb.NewStruct(map[string]interface{}{"wrapped_dek_b64": wrappedB64, "wrapped_dek_iv_b64": ivB64})
	unwrapRespAny, err := server.UnwrapKey(context.Background(), unwrapReq)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	unwrapResp := unwrapRespAny.AsMap()
	plain, err := b64d(parseStringField(unwrapResp, "plaintext_dek_b64"))
	if err != nil {
		t.Fatalf("decode plaintext: %v", err)
	}
	if string(plain) != "dek-1" {
		t.Fatalf("unwrap mismatch: %q", string(plain))
	}

	signReq, _ := structpb.NewStruct(map[string]interface{}{"data_b64": b64([]byte("payload")), "key_label": "label-a"})
	signRespAny, err := server.Sign(context.Background(), signReq)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if parseStringField(signRespAny.AsMap(), "signature_b64") == "" {
		t.Fatalf("missing signature")
	}

	randomReq, _ := structpb.NewStruct(map[string]interface{}{"length": 32.0})
	randomRespAny, err := server.GenerateRandom(context.Background(), randomReq)
	if err != nil {
		t.Fatalf("generate random: %v", err)
	}
	rnd, err := b64d(parseStringField(randomRespAny.AsMap(), "random_b64"))
	if err != nil {
		t.Fatalf("decode random: %v", err)
	}
	if len(rnd) != 32 {
		t.Fatalf("unexpected random length: %d", len(rnd))
	}

	keyInfoReq, _ := structpb.NewStruct(map[string]interface{}{"key_label": "label-a"})
	keyInfoResp, err := server.GetKeyInfo(context.Background(), keyInfoReq)
	if err != nil {
		t.Fatalf("get key info: %v", err)
	}
	if parseStringField(keyInfoResp.AsMap(), "provider") != ProviderSoftware {
		t.Fatalf("unexpected provider: %+v", keyInfoResp.AsMap())
	}
}
