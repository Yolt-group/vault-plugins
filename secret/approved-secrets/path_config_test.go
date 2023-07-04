package main

import (
	"context"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
)

/*
func TestConfig_Read(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
		"approval_ttl":      300,
		"identity_template": "{{identity.entity.aliases.auth_plugin_05c79452.name}}",
		"vault_addr":        "https://vault.yolt.io",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
		Data:      nil,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if !reflect.DeepEqual(resp.Data, data) {
		t.Fatalf("Expected did not equal actual: expected %#v\n got %#v\n", data, resp.Data)
	}
}

func TestConfig_MissingVaultToken(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
		"approval_ttl": "15m",
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      data,
	}

	resp, _ := b.HandleRequest(context.Background(), req)
	if resp != errMissingVaultToken {
		t.Fatalf("expected error response: %v\n got: %v", errMissingVaultToken, resp)
	}
}
*/

func getBackend(t *testing.T) (*backend, logical.Storage) {
	defaultLeaseTTLVal := time.Hour * 12
	maxLeaseTTLVal := time.Hour * 24
	b := newBackend()

	config := &logical.BackendConfig{
		Logger: logging.NewVaultLogger(log.Trace),

		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLVal,
			MaxLeaseTTLVal:     maxLeaseTTLVal,
		},
		StorageView: &logical.InmemStorage{},
	}
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	return b, config.StorageView
}
