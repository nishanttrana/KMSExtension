package main

import (
	"context"
	"testing"
)

func TestStoreConfigAndInteractions(t *testing.T) {
	_, store, _, _ := newAIService(t)
	tenantID := "tenant-store"

	cfg := defaultAIConfig(tenantID)
	cfg.Backend = "openai"
	cfg.Endpoint = "https://api.example.test/v1/chat/completions"
	cfg.Model = "gpt-4o-mini"
	cfg.ProviderAuth = ProviderAuthConfig{Required: true, Type: "bearer"}
	cfg.MCP = MCPConfig{Enabled: true, Endpoint: "mcp://kms-ai"}
	if err := store.UpsertConfig(context.Background(), cfg); err != nil {
		t.Fatalf("upsert config: %v", err)
	}
	got, err := store.GetConfig(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("get config: %v", err)
	}
	if got.Backend != "openai" {
		t.Fatalf("unexpected backend: %+v", got)
	}
	if !got.ProviderAuth.Required || got.ProviderAuth.Type != "bearer" {
		t.Fatalf("unexpected provider auth: %+v", got.ProviderAuth)
	}
	if !got.MCP.Enabled || got.MCP.Endpoint != "mcp://kms-ai" {
		t.Fatalf("unexpected mcp config: %+v", got.MCP)
	}

	interaction := AIInteraction{
		ID:       "aii_1",
		TenantID: tenantID,
		Action:   "query",
		Request: map[string]interface{}{
			"input": "show keys",
		},
		ContextSummary: map[string]interface{}{"keys_count": 1},
		Response:       map[string]interface{}{"answer": "ok"},
		Backend:        "openai",
		Model:          "gpt-4o-mini",
	}
	if err := store.CreateInteraction(context.Background(), interaction); err != nil {
		t.Fatalf("create interaction: %v", err)
	}

	items, err := store.ListRecentInteractions(context.Background(), tenantID, 10)
	if err != nil {
		t.Fatalf("list interactions: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected one interaction got %d", len(items))
	}
	if items[0].Action != "query" {
		t.Fatalf("unexpected interaction: %+v", items[0])
	}
}
